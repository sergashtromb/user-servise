package test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
	"user_service/config"
	"user_service/domain"
	"user_service/infrastructure/reporedis/custerr"
	"user_service/initial/middleware"
	"uuid"

	"github.com/stretchr/testify/mock"
)

// SPEC UpdateRefreshToken
// Что это и что делает? - это handler который принимает запросы на обновление refresh токена используя sessionStore
// если все корректно то попытается взять из существующего окна методом  если получит ошибку окна не существует попытается
// создает окно и сгенерировать токены через метод sessionStore.CreateGracePeriodic которое живет 30 секунд
// если произойдет ошибка при создании вернет ошибку клиенту, если произойдет строго определенные ошибки то вернет ошибку клиенту
// 	и удалит сессии по id семейству
// если все норм будет создано окно и вернут ответ в виде access и refresh токенов
//	Tests:
//			correct_create_window - корректный тест попытаяется получить с окна после сгененрирует токены и создаст окно после вернет их
//			correct_get_from_window - корректный запрос который вернет пару токенов из окна
//			req_param_dont_equal_param_tokens - параметры запроса не совпадают с параметрами токена которые прилетели вернет ошибку
//			window_closed - попытается получить данные из закрытого окна ситуация когда окно было только что закрыто а время с последнего
//				обновления сейссии меньше чем время жизни access токена, значет токен был украден(повторная попытка сделать refresh)
// 				или баг клиента логируем плюс откатываем сессию
//			old_version - когда пришел запрос в котором слишком старая версия, либо баг клиента либо токен был украден но очень долго не отправлен
//				странное поведение возвращаем ошибку откатываем сессию
//			param_req_dont_equal_param_session - ситуация когда отправили корректный токен совпадающий с данными запроса, но не совпали по family id,
//				странное поведение device id невозможно подделать если он создается как слепок устройства, возвращаем ошибку откатываем сессию
//			refresh_expired - ситуация когда прислали просроченный refresh токен, просто возвращаем ошибку

type ResponseResult struct {
	Code    int         `json:"code"`
	Headers http.Header `json:"headers"`
	Body    []byte      `json:"body"` // Изменили тип на []byte
}

func TestUpdateRefreshToken(t *testing.T) {

	sessionStore := new(domain.SessionStoreMock)
	cm := config.NewConfigManager()
	cm.Init(context.TODO(), "")

	userId1 := uuid.NewV7()
	familyId1 := uuid.NewV7()
	familyId2 := uuid.NewV7()

	agent1 := "chrome win 10"
	agent2 := "chrome android"
	deviceId1 := "12345"
	deviceId2 := "58945"

	access1, refresh1, _ := middleware.GeneratePairToken(userId1, familyId1, deviceId1, agent1, cm)
	accessNew1, refreshNew1, _ := middleware.GeneratePairToken(userId1, familyId1, deviceId1, agent1, cm)
	_, _, _ = middleware.GeneratePairToken(userId1, familyId2, deviceId2, agent2, cm)

	session1 := domain.Session{
		UserId:     userId1,
		DeviceId:   deviceId1,
		Agent:      agent1,
		Ip:         "1.1.1.1",
		CreatedAt:  time.Now().Add(-48 * time.Hour),
		Version:    "jwt-10",
		LastUpdate: time.Now().Add(-16 * time.Minute),
	}

	sessionLU1 := domain.Session{
		UserId:     userId1,
		DeviceId:   deviceId1,
		Agent:      agent1,
		Ip:         "1.1.1.1",
		CreatedAt:  time.Now().Add(-48 * time.Hour),
		Version:    "jwt-10",
		LastUpdate: time.Now().Add(-3 * time.Minute),
	}

	// TODO: заполнить таблицу тестов
	_ = deviceId1
	_ = deviceId2
	_ = agent1
	_ = agent2
	_ = userId1
	_ = familyId1
	_ = familyId2

	type TableTest struct {
		// пояснение для теста
		Comm string
		// является ли тест ошибкой
		IsError bool
		// параметры запроса
		IpReq        string
		DeviceIdReq  string
		AgentReq     string
		RefreshToken string
		// поля тела ответа
		FieldBodyForCheck []string
		// методы которые должны быть вызваны в sessionStoreMock
		MethodMustCall []string
		// методы которые НЕ должны вызваться в sessionStoreMock
		MethodNoCall []string
		// метод установки моков и данных сначала очистка resetMock потом установка
		fnSetUpMock func()
		// метод подготавливает ResponseResult то каким должен быть ответ
		fnReadyAnswer func() *ResponseResult
		// метод проверяет какие методы были вызваны какие нет из двух верхних массивов
		fnCheckMethods func(methodMustCall, methodNoCall []string)
	}

	checkMethods := func(methodMustCall, methodNoCall []string) {

		for _, must := range methodMustCall {
			found := false
			for _, exp := range sessionStore.ExpectedCalls {
				if exp.Method == must {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("method %s should have been mocked", must)
			}
		}

		// Verify excluded methods were NOT set up
		for _, noCall := range methodNoCall {
			found := false
			for _, exp := range sessionStore.ExpectedCalls {
				if exp.Method == noCall {
					found = true
					break
				}
			}
			if found {
				t.Errorf("method %s should NOT have been mocked", noCall)
			}
		}
	}

	// TODO: заполнить таблицу тестов
	table := map[string]TableTest{
		"correct_create_window": TableTest{
			Comm:              "корректный тест попытаяется получить с окна после сгененрирует токены и создаст окно после вернет их",
			IsError:           false,
			IpReq:             "1.1.1.1:5423",
			DeviceIdReq:       deviceId1,
			AgentReq:          agent1,
			RefreshToken:      refresh1,
			FieldBodyForCheck: []string{"expires_in", "token_type"},
			MethodMustCall:    []string{"GetSessionByFamilyId", "GetFromGracePeriodic", "CreateGracePeriodic"},
			MethodNoCall:      []string{"Registration", "GetAllSession", "DeleteAll", "DeleteByRefresh", "UpdateIpAdress"},
			fnSetUpMock: func() {
				resetMock(&sessionStore.Mock, t)
				sessionStore.On("GetSessionByFamilyId", context.Background(), userId1, familyId1).
					Return(&session1, nil).
					Once()
				sessionStore.On("GetFromGracePeriodic", context.Background(), userId1, familyId1, "jwt-11").
					Return("", "", custerr.ErrGracePeriodicNoExists).
					Once()
				sessionStore.On("CreateGracePeriodic", context.Background(), userId1, familyId1, mock.Anything).
					Return(nil).
					Once()
			},
			fnReadyAnswer: func() *ResponseResult {

				bodyJson := `
				{
					"access_token": "access_token",
					"token_type": "Bearer",
					"expires_in": 900,
					"refresh_token": "refresh_token"
				}
				`
				resp := httptest.NewRecorder()
				resp.Header().Set("Content-Type", "application/json;charset=UTF-8")
				resp.Header().Set("Cache-Control", "no-store")
				resp.Header().Set("Pragma", "no-cache")
				resp.WriteHeader(http.StatusOK)
				resp.Write([]byte(bodyJson))

				return &ResponseResult{
					Code:    resp.Code,
					Headers: resp.Header(),
					Body:    resp.Body.Bytes(),
				}
			},
			fnCheckMethods: checkMethods,
		},
		"correct_get_from_window": TableTest{
			Comm:              "корректный запрос который вернет пару токенов из окна",
			IsError:           false,
			IpReq:             "1.1.1.1:5423",
			DeviceIdReq:       deviceId1,
			AgentReq:          agent1,
			RefreshToken:      refresh1,
			FieldBodyForCheck: []string{"access_token", "expires_in", "token_type", "refresh_token"},
			MethodMustCall:    []string{"GetSessionByFamilyId", "GetFromGracePeriodic"},
			MethodNoCall:      []string{"Registration", "GetAllSession", "DeleteAll", "DeleteByRefresh", "UpdateIpAdress", "CreateGracePeriodic"},
			fnSetUpMock: func() {
				resetMock(&sessionStore.Mock, t)
				sessionStore.On("GetSessionByFamilyId", context.Background(), userId1, familyId1).
					Return(&session1, nil).
					Once()
				sessionStore.On("GetFromGracePeriodic", context.Background(), userId1, familyId1, "jwt-11").
					Return(accessNew1, refreshNew1, nil).
					Once()
			},
			fnReadyAnswer: func() *ResponseResult {

				bodyJson := fmt.Sprintf(`
				{
					"access_token": "%s",
					"token_type": "Bearer",
					"expires_in": 900,
					"refresh_token": "%s"
				}
				`, accessNew1, refreshNew1)
				resp := httptest.NewRecorder()
				resp.Header().Set("Content-Type", "application/json;charset=UTF-8")
				resp.Header().Set("Cache-Control", "no-store")
				resp.Header().Set("Pragma", "no-cache")
				resp.WriteHeader(http.StatusOK)
				resp.Write([]byte(bodyJson))

				return &ResponseResult{
					Code:    resp.Code,
					Headers: resp.Header(),
					Body:    resp.Body.Bytes(),
				}
			},
			fnCheckMethods: checkMethods,
		},
		"req_param_dont_equal_param_tokens": TableTest{
			Comm:              "параметры запроса не совпадают с параметрами токена которые прилетели вернет ошибку",
			IsError:           true,
			IpReq:             "4.4.4.4:6532",
			DeviceIdReq:       "66666",
			AgentReq:          "mozila ios 10",
			RefreshToken:      refresh1,
			FieldBodyForCheck: []string{"error", "error_description"},
			MethodMustCall:    []string{"DeleteByRefresh"},
			MethodNoCall:      []string{"GetSessionByFamilyId", "GetFromGracePeriodic", "Registration", "GetAllSession", "DeleteAll", "DeleteByRefresh", "UpdateIpAdress", "CreateGracePeriodic"},
			fnSetUpMock: func() {
				resetMock(&sessionStore.Mock, t)
				sessionStore.On("DeleteByRefresh", context.Background(), userId1, familyId1).
					Return(nil).
					Once()
			},
			fnReadyAnswer: func() *ResponseResult {
				bodyJson := `
				{
					"error": "invalid_grant",
					"error_description": "Session context mismatch. Please log in again."
				}
				`
				resp := httptest.NewRecorder()
				resp.Header().Set("Content-Type", "application/json;charset=UTF-8")
				resp.WriteHeader(http.StatusBadRequest)
				resp.Write([]byte(bodyJson))

				return &ResponseResult{
					Code:    resp.Code,
					Headers: resp.Header(),
					Body:    resp.Body.Bytes(),
				}
			},
			fnCheckMethods: checkMethods,
		},
		"window_closed": TableTest{
			Comm: `попытается получить данные из закрытого окна ситуация когда окно было только что закрыто а время с последнего
						обновления сейссии меньше чем время жизни access токена, значет токен был украден(повторная попытка сделать refresh)
 						или баг клиента логируем плюс откатываем сессию`,
			IsError:           true,
			IpReq:             "1.1.1.1:5432",
			DeviceIdReq:       deviceId1,
			AgentReq:          agent1,
			RefreshToken:      refresh1,
			FieldBodyForCheck: []string{"error", "error_description"},
			MethodMustCall:    []string{"GetSessionByFamilyId", "DeleteByRefresh"},
			MethodNoCall:      []string{"GetFromGracePeriodic", "Registration", "GetAllSession", "DeleteAll", "DeleteByRefresh", "UpdateIpAdress", "CreateGracePeriodic"},
			fnSetUpMock: func() {
				resetMock(&sessionStore.Mock, t)
				sessionStore.On("GetSessionByFamilyId", context.Background(), userId1, familyId1).
					Return(&sessionLU1, nil).
					Once()
				sessionStore.On("DeleteByRefresh", context.Background(), userId1, familyId1).
					Return(nil).
					Once()

			},
			fnReadyAnswer: func() *ResponseResult {
				bodyJson := `
				{
					"error": "invalid_grant",
					"error_description": "Token reuse detected. Session has been revoked."
				}
				`
				resp := httptest.NewRecorder()
				resp.Header().Set("Content-Type", "application/json;charset=UTF-8")
				resp.WriteHeader(http.StatusBadRequest)
				resp.Write([]byte(bodyJson))

				return &ResponseResult{
					Code:    resp.Code,
					Headers: resp.Header(),
					Body:    resp.Body.Bytes(),
				}
			},
		},
	}
	_ = table

}

func resetMock(m *mock.Mock, t *testing.T) {
	m.ExpectedCalls = nil
	m.Calls = nil
	m.Test(t) // перепривязать к TestingT текущего подтеста
}
