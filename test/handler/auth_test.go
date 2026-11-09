package test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"user_service/config"
	"user_service/domain"
	"user_service/infrastructure/postgres"
	"user_service/infrastructure/reporedis/custerr"
	"user_service/infrastructure/tokens"
	"user_service/initial/handler"
	"user_service/initial/middleware"
	"user_service/util"
	"uuid"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/mock"
	"golang.org/x/crypto/bcrypt"
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
//			param_req_dont_equal_param_session - ситуация когда отправили корректный токен совпадающий с данными запроса, но не совпали по family id,
//				странное поведение device id невозможно подделать если он создается как слепок устройства, возвращаем ошибку откатываем сессию
//			window_closed - попытается получить данные из закрытого окна ситуация когда окно было только что закрыто а время с последнего
//				обновления сейссии меньше чем время жизни access токена, значет токен был украден(повторная попытка сделать refresh)
// 				или баг клиента логируем плюс откатываем сессию
//			old_version - когда пришел запрос в котором слишком старая версия, либо баг клиента либо токен был украден но очень долго не отправлен
//				странное поведение возвращаем ошибку откатываем сессию
//			refresh_expired - ситуация когда прислали просроченный refresh токен, просто возвращаем ошибку
//			get_periodic_bad_data - ситуация когда при получении токенов из окна вернется ошибка битых данных
//			get_periodic_ver_miss_data - ситуация когда при получении токенов из окна вернется ошибка промаха версии токенов
//			empty_refresh_token - ситуация когда прислали токен на апдейт а он пустой
//			invalid_grant_type - ситуация когда в теле при запросе grant_type не равен refresh_token

type ResponseResult struct {
	Code    int         `json:"code"`
	Headers http.Header `json:"headers"`
	Body    []byte      `json:"body"` // Изменили тип на []byte
}

func TestUpdateRefreshToken(t *testing.T) {

	sessionStore := domain.NewSessionStoreMock(t)
	cm := config.NewConfigManager()
	cm.Init(context.TODO(), "")

	userId1 := uuid.NewV7()
	familyId1 := uuid.NewV7()
	familyId2 := uuid.NewV7()

	agent1 := "chrome win 10"
	agent2 := "chrome android"
	deviceId1 := "12345"
	deviceId2 := "58945"

	tu := tokens.NewTokenUtil(cm)

	_, refresh1, _ := tu.GeneratePairToken(userId1, familyId1, deviceId1, agent1)
	accessNew1, refreshNew1, _ := tu.GeneratePairToken(userId1, familyId1, deviceId1, agent1)
	_, _, _ = tu.GeneratePairToken(userId1, familyId2, deviceId2, agent2)

	// expired refresh token
	expiredRefreshClaims := &tokens.RefreshToken{
		UserId:    userId1,
		FamilyId:  familyId1,
		TokenType: tokens.RefreshTokenType,
		Version:   "jwt-1",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-1 * time.Hour)),
			Issuer:    tokens.Issuer,
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
			Subject:   userId1.String(),
			ID:        uuid.New().String(),
		},
	}
	expiredRefresh := jwt.NewWithClaims(jwt.SigningMethodHS256, expiredRefreshClaims)
	expiredRefreshToken, _ := expiredRefresh.SignedString(cm.Get().TokenConf.RefreshBt)
	userStoreBD := domain.NewUserStoreMock(t)
	authHandler := handler.NewAuthHandler(cm, domain.GetMockAuditService(), sessionStore, tu, userStoreBD)

	session1 := domain.Session{
		UserId:     userId1,
		DeviceId:   deviceId1,
		Agent:      agent1,
		Ip:         "1.1.1.1",
		CreatedAt:  time.Now().Add(-48 * time.Hour),
		Version:    "jwt-1",
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
		// grant_type для отправки в запросе (по умолчанию refresh_token)
		GrantType string
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
		// Собираем множество РЕАЛЬНО вызванных методов
		called := make(map[string]struct{}, len(sessionStore.Calls))
		for _, call := range sessionStore.Calls {
			called[call.Method] = struct{}{}
		}

		// Должны быть вызваны
		for _, method := range methodMustCall {
			if _, ok := called[method]; !ok {
				t.Errorf("method %s was NOT called, but should have been", method)
			}
		}

		// НЕ должны быть вызваны
		for _, method := range methodNoCall {
			if _, ok := called[method]; ok {
				t.Errorf("method %s WAS called, but should NOT have been", method)
			}
		}
	}

	// TODO: заполнить таблицу тестов
	table := map[string]TableTest{
		"correct_create_window": {
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
				sessionStore.On("GetFromGracePeriodic", context.Background(), userId1, familyId1, "jwt-2").
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
		"correct_get_from_window": {
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
				sessionStore.On("GetFromGracePeriodic", context.Background(), userId1, familyId1, "jwt-2").
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
		"param_req_dont_equal_param_session": {
			Comm:              "параметры запроса не совпадают с параметрами токена которые прилетели вернет ошибку",
			IsError:           true,
			IpReq:             "4.4.4.4:6532",
			DeviceIdReq:       "66666",
			AgentReq:          "mozila ios 10",
			RefreshToken:      refresh1,
			FieldBodyForCheck: []string{"error", "error_description"},
			MethodMustCall:    []string{"GetSessionByFamilyId", "DeleteByRefresh"},
			MethodNoCall:      []string{"GetFromGracePeriodic", "Registration", "GetAllSession", "DeleteAll", "UpdateIpAdress", "CreateGracePeriodic"},
			fnSetUpMock: func() {
				resetMock(&sessionStore.Mock, t)
				sessionStore.On("GetSessionByFamilyId", context.Background(), userId1, familyId1).
					Return(&session1, nil).
					Once()
				sessionStore.On("DeleteByRefresh", context.Background(), userId1, familyId1).
					Return(nil).
					Once()
			},
			fnReadyAnswer: func() *ResponseResult {
				errBody := middleware.ErrBody{
					Err:     "invalid_grant",
					Code:    "SESSION_CONTEXT_MISMATCH",
					Message: "Session context mismatch. Please log in again.",
				}
				bodyJson, _ := json.Marshal(errBody)
				resp := httptest.NewRecorder()
				resp.Header().Set("Content-Type", "application/json;charset=UTF-8")
				resp.WriteHeader(http.StatusBadRequest)
				resp.Write(bodyJson)

				return &ResponseResult{
					Code:    resp.Code,
					Headers: resp.Header(),
					Body:    resp.Body.Bytes(),
				}
			},
			fnCheckMethods: checkMethods,
		},
		"window_closed": {
			Comm: `попытается получить данные из закрытого окна ситуация когда окно было только что закрыто а время с последнего
						обновления сейссии меньше чем время жизни access токена, значет токен был украден(повторная попытка сделать refresh)
  						или баг клиента логируем плюс откатываем сессию`,
			IsError:           true,
			IpReq:             "1.1.1.1:5432",
			DeviceIdReq:       deviceId1,
			AgentReq:          agent1,
			RefreshToken:      refresh1,
			FieldBodyForCheck: []string{"error", "error_description"},
			MethodMustCall:    []string{"GetSessionByFamilyId", "GetFromGracePeriodic", "CreateGracePeriodic", "DeleteByRefresh"},
			MethodNoCall:      []string{"Registration", "GetAllSession", "DeleteAll", "UpdateIpAdress"},
			fnCheckMethods:    checkMethods,
			fnSetUpMock: func() {
				resetMock(&sessionStore.Mock, t)
				sessionStore.On("GetSessionByFamilyId", context.Background(), userId1, familyId1).
					Return(&session1, nil).
					Once()
				sessionStore.On("GetFromGracePeriodic", context.Background(), userId1, familyId1, "jwt-2").
					Return("", "", custerr.ErrGracePeriodicNoExists).
					Once()
				sessionStore.On("CreateGracePeriodic", context.Background(), userId1, familyId1, mock.Anything).
					Return(custerr.ErrSuspiciousRefreshRate).
					Once()
				sessionStore.On("DeleteByRefresh", context.Background(), userId1, familyId1).
					Return(nil).
					Once()
			},
			fnReadyAnswer: func() *ResponseResult {
				errBody := middleware.ErrBody{
					Err:     "invalid_grant",
					Code:    "TOKEN_REUSE_DETECTED",
					Message: "Token reuse detected. Session has been revoked.",
				}
				bodyJson, _ := json.Marshal(errBody)
				resp := httptest.NewRecorder()
				resp.Header().Set("Content-Type", "application/json;charset=UTF-8")
				resp.WriteHeader(http.StatusBadRequest)
				resp.Write(bodyJson)

				return &ResponseResult{
					Code:    resp.Code,
					Headers: resp.Header(),
					Body:    resp.Body.Bytes(),
				}
			},
		},
		"old_version": {
			Comm:              "когда пришел запрос в котором слишком старая версия",
			IsError:           true,
			IpReq:             "1.1.1.1:5432",
			AgentReq:          agent1,
			DeviceIdReq:       deviceId1,
			RefreshToken:      refresh1,
			FieldBodyForCheck: []string{"error", "error_description"},
			MethodMustCall:    []string{"GetSessionByFamilyId", "DeleteByRefresh"},
			MethodNoCall:      []string{"GetFromGracePeriodic", "Registration", "GetAllSession", "DeleteAll", "UpdateIpAdress", "CreateGracePeriodic"},
			fnCheckMethods:    checkMethods,
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
				errBody := middleware.ErrBody{
					Err:     "invalid_grant",
					Code:    "TOKEN_REUSE_DETECTED",
					Message: "Token reuse detected. Session has been revoked.",
				}
				bodyJson, _ := json.Marshal(errBody)
				resp := httptest.NewRecorder()
				resp.Header().Set("Content-Type", "application/json;charset=UTF-8")
				resp.WriteHeader(http.StatusBadRequest)
				resp.Write(bodyJson)

				return &ResponseResult{
					Code:    resp.Code,
					Headers: resp.Header(),
					Body:    resp.Body.Bytes(),
				}
			},
		},
		"refresh_expired": {
			Comm:              "ситуация когда прислали просроченный refresh токен, просто возвращаем ошибку",
			IsError:           true,
			IpReq:             "1.1.1.1:5432",
			DeviceIdReq:       deviceId1,
			AgentReq:          agent1,
			RefreshToken:      expiredRefreshToken,
			FieldBodyForCheck: []string{"error", "error_description"},
			MethodMustCall:    []string{},
			MethodNoCall:      []string{"GetSessionByFamilyId", "GetFromGracePeriodic", "Registration", "GetAllSession", "DeleteAll", "UpdateIpAdress", "CreateGracePeriodic", "DeleteByRefresh"},
			fnSetUpMock: func() {
				resetMock(&sessionStore.Mock, t)
			},
			fnReadyAnswer: func() *ResponseResult {
				errBody := middleware.ErrBody{
					Err:     "invalid_grant",
					Code:    "INVALID_GRANT",
					Message: "The refresh token has expired. Please re-authenticate.",
				}
				bodyJson, _ := json.Marshal(errBody)
				resp := httptest.NewRecorder()
				resp.Header().Set("Content-Type", "application/json;charset=UTF-8")
				resp.WriteHeader(http.StatusBadRequest)
				resp.Write(bodyJson)

				return &ResponseResult{
					Code:    resp.Code,
					Headers: resp.Header(),
					Body:    resp.Body.Bytes(),
				}
			},
			fnCheckMethods: checkMethods,
		},
		"get_periodic_bad_data": {
			Comm:              "GetFromGracePeriodic возвращает ошибку, возвращается 500",
			IsError:           true,
			IpReq:             "1.1.1.1:5432",
			DeviceIdReq:       deviceId1,
			AgentReq:          agent1,
			RefreshToken:      refresh1,
			FieldBodyForCheck: []string{"error", "error_description"},
			MethodMustCall:    []string{"GetSessionByFamilyId", "GetFromGracePeriodic"},
			MethodNoCall:      []string{"CreateGracePeriodic", "DeleteByRefresh", "Registration", "GetAllSession", "DeleteAll", "UpdateIpAdress"},
			fnSetUpMock: func() {
				resetMock(&sessionStore.Mock, t)
				sessionStore.On("GetSessionByFamilyId", context.Background(), userId1, familyId1).
					Return(&session1, nil).
					Once()
				sessionStore.On("GetFromGracePeriodic", context.Background(), userId1, familyId1, "jwt-2").
					Return("", "", custerr.ErrBadData).
					Once()
			},
			fnReadyAnswer: func() *ResponseResult {
				errBody := middleware.ErrBody{
					Err:     "Internal Server Error",
					Code:    "AUTH_SERVICE_ERROR",
					Message: "Authentication service is temporarily unavailable. Please try again later.",
				}
				bodyJson, _ := json.Marshal(errBody)
				resp := httptest.NewRecorder()
				resp.Header().Set("Content-Type", "application/json;charset=UTF-8")
				resp.WriteHeader(http.StatusInternalServerError)
				resp.Write(bodyJson)

				return &ResponseResult{
					Code:    resp.Code,
					Headers: resp.Header(),
					Body:    resp.Body.Bytes(),
				}
			},
			fnCheckMethods: checkMethods,
		},
		"get_periodic_ver_miss_data": {
			Comm:              "GetFromGracePeriodic возвращает ошибку, возвращается 500",
			IsError:           true,
			IpReq:             "1.1.1.1:5432",
			DeviceIdReq:       deviceId1,
			AgentReq:          agent1,
			RefreshToken:      refresh1,
			FieldBodyForCheck: []string{"error", "error_description"},
			MethodMustCall:    []string{"GetSessionByFamilyId", "GetFromGracePeriodic"},
			MethodNoCall:      []string{"CreateGracePeriodic", "DeleteByRefresh", "Registration", "GetAllSession", "DeleteAll", "UpdateIpAdress"},
			fnSetUpMock: func() {
				resetMock(&sessionStore.Mock, t)
				sessionStore.On("GetSessionByFamilyId", context.Background(), userId1, familyId1).
					Return(&session1, nil).
					Once()
				sessionStore.On("GetFromGracePeriodic", context.Background(), userId1, familyId1, "jwt-2").
					Return("", "", custerr.ErrGracePeriodicVersionMiss).
					Once()
			},
			fnReadyAnswer: func() *ResponseResult {
				errBody := middleware.ErrBody{
					Err:     "Internal Server Error",
					Code:    "AUTH_SERVICE_ERROR",
					Message: "Authentication service is temporarily unavailable. Please try again later.",
				}
				bodyJson, _ := json.Marshal(errBody)
				resp := httptest.NewRecorder()
				resp.Header().Set("Content-Type", "application/json;charset=UTF-8")
				resp.WriteHeader(http.StatusInternalServerError)
				resp.Write(bodyJson)

				return &ResponseResult{
					Code:    resp.Code,
					Headers: resp.Header(),
					Body:    resp.Body.Bytes(),
				}
			},
			fnCheckMethods: checkMethods,
		},
		"empty_refresh_token": {
			Comm:              "refresh_token пустой, возвращается ошибка 400",
			IsError:           true,
			IpReq:             "1.1.1.1:5432",
			DeviceIdReq:       deviceId1,
			AgentReq:          agent1,
			RefreshToken:      "",
			FieldBodyForCheck: []string{"error", "error_description"},
			MethodMustCall:    []string{},
			MethodNoCall:      []string{"GetSessionByFamilyId", "GetFromGracePeriodic", "CreateGracePeriodic", "DeleteByRefresh", "Registration", "GetAllSession", "DeleteAll", "UpdateIpAdress"},
			fnSetUpMock: func() {
				resetMock(&sessionStore.Mock, t)
			},
			fnReadyAnswer: func() *ResponseResult {
				errBody := middleware.ErrBody{
					Err:     "invalid_request",
					Code:    "INVALID_REQUEST",
					Message: "refresh_token is required",
				}
				bodyJson, _ := json.Marshal(errBody)
				resp := httptest.NewRecorder()
				resp.Header().Set("Content-Type", "application/json;charset=UTF-8")
				resp.WriteHeader(http.StatusBadRequest)
				resp.Write(bodyJson)

				return &ResponseResult{
					Code:    resp.Code,
					Headers: resp.Header(),
					Body:    resp.Body.Bytes(),
				}
			},
			fnCheckMethods: checkMethods,
		},
		"invalid_grant_type": {
			Comm:              "grant_type не равен refresh_token, возвращается ошибка 400",
			IsError:           true,
			IpReq:             "1.1.1.1:5432",
			DeviceIdReq:       deviceId1,
			AgentReq:          agent1,
			RefreshToken:      refresh1,
			GrantType:         "invalid",
			FieldBodyForCheck: []string{"error", "error_description"},
			MethodMustCall:    []string{},
			MethodNoCall:      []string{"GetSessionByFamilyId", "GetFromGracePeriodic", "CreateGracePeriodic", "DeleteByRefresh", "Registration", "GetAllSession", "DeleteAll", "UpdateIpAdress"},
			fnSetUpMock: func() {
				resetMock(&sessionStore.Mock, t)
			},
			fnReadyAnswer: func() *ResponseResult {
				errBody := middleware.ErrBody{
					Err:     "bad request",
					Code:    "BAD_REQUEST",
					Message: "grant_type must be refresh_token.",
				}
				bodyJson, _ := json.Marshal(errBody)
				resp := httptest.NewRecorder()
				resp.Header().Set("Content-Type", "application/json;charset=UTF-8")
				resp.WriteHeader(http.StatusBadRequest)
				resp.Write(bodyJson)

				return &ResponseResult{
					Code:    resp.Code,
					Headers: resp.Header(),
					Body:    resp.Body.Bytes(),
				}
			},
			fnCheckMethods: checkMethods,
		},
	}

	for name, val := range table {

		t.Run(name, func(t *testing.T) {

			val.fnSetUpMock()

			grantType := val.GrantType
			if grantType == "" {
				grantType = "refresh_token"
			}
			bodyStr := fmt.Sprintf("grant_type=%s&refresh_token=%v", grantType, val.RefreshToken)

			testReq := httptest.NewRequest("POST", "/refresh", bytes.NewBufferString(bodyStr))
			testReq.RemoteAddr = val.IpReq
			testReq.Header.Set("User-Agent", val.AgentReq)
			testReq.Header.Set("Device-Id", val.DeviceIdReq)
			testReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			rec := httptest.NewRecorder()

			authHandler.UpdateRefreshToken(rec, testReq)

			mustResp := val.fnReadyAnswer()

			if mustResp.Code != rec.Code {
				t.Errorf("fail http status code dont equal want %v have %v", mustResp.Code, rec.Code)
			}

			if len(mustResp.Body) > 0 {

				if val.IsError {

					var mustErrBody middleware.ErrBody
					err := json.Unmarshal(mustResp.Body, &mustErrBody)
					if err != nil {
						t.Fatalf("unmarshal json must %v", err)
					}

					var outErrBody middleware.ErrBody
					err = json.Unmarshal(rec.Body.Bytes(), &outErrBody)
					if err != nil {
						t.Fatalf("unmarshal json out %v", err)
					}

					if mustErrBody.Err != outErrBody.Err || mustErrBody.Code != outErrBody.Code ||
						mustErrBody.Message != outErrBody.Message {
						t.Errorf("fail http body dont equal want %+v have %+v", mustErrBody, outErrBody)
					}
				} else {
					var data map[string]any
					err := json.Unmarshal(mustResp.Body, &data)
					if err != nil {
						t.Fatalf("unmarshal json must %v", err)
					}

					var outdata map[string]any
					err = json.Unmarshal(rec.Body.Bytes(), &outdata)
					if err != nil {
						t.Fatalf("unmarshal json out %v", err)
					}

					if data["token_type"] != outdata["token_type"] || data["expires_in"] != outdata["expires_in"] {
						t.Errorf("fail http body dont equal")
					}
				}
			}

			errHeaderAuth := mustResp.Headers.Get("WWW-Authenticate")
			if errHeaderAuth != "" {
				respHead := rec.Header().Get("WWW-Authenticate")
				if errHeaderAuth != respHead {
					t.Errorf("fail http auth header dont equal want %v have %v", errHeaderAuth, respHead)
				}
			}

			val.fnCheckMethods(val.MethodMustCall, val.MethodNoCall)

		})

	}

}

// SPEC RegistrationUser
// Что это и что делает? - handler регистрации нового пользователя.
// Валидирует Content-Type/IP/заголовки/JSON, требует непустые username+password,
// хеширует пароль bcrypt, создаёт пользователя в userStoreBD через Create,
// регистрирует сессию в sessionStore.Registration, генерирует пару токенов и
// возвращает access+refresh со статусом 201.
//
//	Tests:
//		correct_request                 - успешная регистрация только по username+password
//		correct_with_email              - успешная регистрация с email
//		correct_with_phone              - успешная регистрация с phone
//		correct_with_email_and_phone    - успешная регистрация со всеми полями
//		dublicate_username              - UNIQUE violation по username → 409
//		dublicate_email                 - UNIQUE violation по email → 409
//		dublicate_phone                 - UNIQUE violation по phone → 409
//		empty_username                  - пустой username → 400 VALIDATION_ERROR
//		empty_password                  - пустой password → 400 VALIDATION_ERROR
//		whitespace_username             - username из одних пробелов → 400 VALIDATION_ERROR
//		whitespace_password             - password из одних пробелов → 400 VALIDATION_ERROR
//		db_error                        - userStoreBD.Create вернул generic error → 500
//		session_registration_fail       - sessionStore.Registration упал → 500
//		missing_device_id               - нет Device-Id заголовка → 400 BAD_REQUEST
//		missing_user_agent              - нет User-Agent заголовка → 400 BAD_REQUEST
//		wrong_content_type              - Content-Type не application/json → 415
//		invalid_json                    - битый JSON в теле → 400
//		bad_remote_addr                 - невалидный RemoteAddr → 400
//		body_too_large                  - тело > 64KiB → 400
func TestRegistrationUser(t *testing.T) {
	util.LoadEnvFile()
	cm := config.NewConfigManager()
	cm.Init(context.TODO(), "")

	userStoreBD := domain.NewUserStoreMock(t)
	sessionStore := domain.NewSessionStoreMock(t)
	tu := tokens.NewTokenUtil(cm)

	ip1 := "1.1.1.1:5432"
	agent1 := "chrome widows 10"
	deviceId1 := "12345"

	username1 := "username"
	pass1 := "54321"
	email1 := "user@example.com"
	phone1 := "+79991234567"

	authHandler := handler.NewAuthHandler(cm, domain.GetMockAuditService(), sessionStore, tu, userStoreBD)

	// checkMethods сканирует вызовы обоих моков.
	checkMethods := func(methodMustCall, methodNoCall []string) {
		called := make(map[string]struct{})
		for _, call := range userStoreBD.Calls {
			called[call.Method] = struct{}{}
		}
		for _, call := range sessionStore.Calls {
			called[call.Method] = struct{}{}
		}

		for _, m := range methodMustCall {
			if _, ok := called[m]; !ok {
				t.Errorf("method %s was NOT called, but should have been", m)
			}
		}
		for _, m := range methodNoCall {
			if _, ok := called[m]; ok {
				t.Errorf("method %s WAS called, but should NOT have been", m)
			}
		}
	}

	// buildNoCall — собирает полный список методов обоих сторов,
	// исключая перечисленные в called.
	buildNoCall := func(called ...string) []string {
		calledSet := make(map[string]struct{}, len(called))
		for _, c := range called {
			calledSet[c] = struct{}{}
		}
		all := []string{
			"GetByID", "Update", "Create", "Delete", "HardDelete",
			"GetByEmail", "GetByPhone", "GetByOpt",
			"Registration", "GetAllSession", "GetSessionByFamilyId",
			"DeleteAll", "DeleteByRefresh", "CreateGracePeriodic",
			"GetFromGracePeriodic", "UpdateIpAdress",
		}
		out := make([]string, 0, len(all))
		for _, m := range all {
			if _, ok := calledSet[m]; !ok {
				out = append(out, m)
			}
		}
		return out
	}

	// Готовые ответы-«эталоны».
	successAnswer := func() *ResponseResult {
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
		resp.WriteHeader(http.StatusCreated)
		resp.Write([]byte(bodyJson))
		return &ResponseResult{
			Code:    resp.Code,
			Headers: resp.Header(),
			Body:    resp.Body.Bytes(),
		}
	}

	errAnswer := func(status int, body middleware.ErrBody) *ResponseResult {
		bodyJson, _ := json.Marshal(body)
		resp := httptest.NewRecorder()
		resp.Header().Set("Content-Type", "application/json;charset=UTF-8")
		resp.WriteHeader(status)
		resp.Write(bodyJson)
		return &ResponseResult{
			Code:    resp.Code,
			Headers: resp.Header(),
			Body:    resp.Body.Bytes(),
		}
	}

	// Хелпер для UNIQUE-violation — клонирует sentinel и выставляет поле.
	dupErr := func(field string) error {
		e := postgres.ErrUserAlreadyExists.Clone()
		e.Fields = append(e.Fields, field)
		return e
	}

	type TableTest struct {
		// пояснение для теста
		Comm string
		// является ли тест ошибкой
		IsError bool
		// параметры запроса
		IpReq       string
		AgentReq    string
		DeviceIdReq string
		ContentType string
		// поля тела запроса
		UserName string
		Email    string
		Phone    string
		Password string
		// сырое тело (приоритетнее полей выше) — для invalid_json / body_too_large
		RawBody string
		// поля тела ответа, которые нужно проверить
		FieldBodyForCheck []string
		// методы, которые должны быть вызваны
		MethodMustCall []string
		// методы, которые НЕ должны быть вызваны
		MethodNoCall []string
		// настройка моков
		fnSetUpMock func()
		// эталонный ответ
		fnReadyAnswer func() *ResponseResult
		// проверка вызовов
		fnCheckMethods func(methodMustCall, methodNoCall []string)
	}

	table := map[string]TableTest{
		"correct_request": {
			Comm:              "успешная регистрация по username+password",
			IsError:           false,
			IpReq:             ip1,
			AgentReq:          agent1,
			DeviceIdReq:       deviceId1,
			ContentType:       "application/json",
			UserName:          username1,
			Password:          pass1,
			FieldBodyForCheck: []string{"access_token", "expires_in", "token_type", "refresh_token"},
			MethodMustCall:    []string{"Create", "Registration"},
			MethodNoCall:      buildNoCall("Create", "Registration"),
			fnSetUpMock: func() {
				resetMock(&userStoreBD.Mock, t)
				resetMock(&sessionStore.Mock, t)

				userStoreBD.On("Create", context.Background(), mock.Anything).
					Return(uuid.NewV7(), nil).
					Once()
				sessionStore.On("Registration", context.Background(), mock.Anything, mock.Anything).
					Return(nil).
					Once()
			},
			fnReadyAnswer:  successAnswer,
			fnCheckMethods: checkMethods,
		},
		"correct_with_email": {
			Comm:              "успешная регистрация с email (username обязателен)",
			IsError:           false,
			IpReq:             ip1,
			AgentReq:          agent1,
			DeviceIdReq:       deviceId1,
			ContentType:       "application/json",
			UserName:          username1,
			Email:             email1,
			Password:          pass1,
			FieldBodyForCheck: []string{"access_token", "expires_in", "token_type", "refresh_token"},
			MethodMustCall:    []string{"Create", "Registration"},
			MethodNoCall:      buildNoCall("Create", "Registration"),
			fnSetUpMock: func() {
				resetMock(&userStoreBD.Mock, t)
				resetMock(&sessionStore.Mock, t)

				userStoreBD.On("Create", context.Background(), mock.Anything).
					Return(uuid.NewV7(), nil).
					Once()
				sessionStore.On("Registration", context.Background(), mock.Anything, mock.Anything).
					Return(nil).
					Once()
			},
			fnReadyAnswer:  successAnswer,
			fnCheckMethods: checkMethods,
		},
		"correct_with_phone": {
			Comm:              "успешная регистрация с phone (username обязателен)",
			IsError:           false,
			IpReq:             ip1,
			AgentReq:          agent1,
			DeviceIdReq:       deviceId1,
			ContentType:       "application/json",
			UserName:          username1,
			Phone:             phone1,
			Password:          pass1,
			FieldBodyForCheck: []string{"access_token", "expires_in", "token_type", "refresh_token"},
			MethodMustCall:    []string{"Create", "Registration"},
			MethodNoCall:      buildNoCall("Create", "Registration"),
			fnSetUpMock: func() {
				resetMock(&userStoreBD.Mock, t)
				resetMock(&sessionStore.Mock, t)

				userStoreBD.On("Create", context.Background(), mock.Anything).
					Return(uuid.NewV7(), nil).
					Once()
				sessionStore.On("Registration", context.Background(), mock.Anything, mock.Anything).
					Return(nil).
					Once()
			},
			fnReadyAnswer:  successAnswer,
			fnCheckMethods: checkMethods,
		},
		"correct_with_email_and_phone": {
			Comm:              "успешная регистрация со всеми полями",
			IsError:           false,
			IpReq:             ip1,
			AgentReq:          agent1,
			DeviceIdReq:       deviceId1,
			ContentType:       "application/json",
			UserName:          username1,
			Email:             email1,
			Phone:             phone1,
			Password:          pass1,
			FieldBodyForCheck: []string{"access_token", "expires_in", "token_type", "refresh_token"},
			MethodMustCall:    []string{"Create", "Registration"},
			MethodNoCall:      buildNoCall("Create", "Registration"),
			fnSetUpMock: func() {
				resetMock(&userStoreBD.Mock, t)
				resetMock(&sessionStore.Mock, t)

				userStoreBD.On("Create", context.Background(), mock.Anything).
					Return(uuid.NewV7(), nil).
					Once()
				sessionStore.On("Registration", context.Background(), mock.Anything, mock.Anything).
					Return(nil).
					Once()
			},
			fnReadyAnswer:  successAnswer,
			fnCheckMethods: checkMethods,
		},
		"dublicate_username": {
			Comm:              "username уже занят — UNIQUE violation",
			IsError:           true,
			IpReq:             ip1,
			AgentReq:          agent1,
			DeviceIdReq:       deviceId1,
			ContentType:       "application/json",
			UserName:          username1,
			Password:          pass1,
			FieldBodyForCheck: []string{"error", "code", "message"},
			MethodMustCall:    []string{"Create"},
			MethodNoCall:      buildNoCall("Create"),
			fnSetUpMock: func() {
				resetMock(&userStoreBD.Mock, t)
				resetMock(&sessionStore.Mock, t)

				userStoreBD.On("Create", context.Background(), mock.Anything).
					Return(uuid.Nil(), dupErr("username")).
					Once()
			},
			fnReadyAnswer: func() *ResponseResult {
				return errAnswer(http.StatusConflict, middleware.ErrBody{
					Err:     "conflict",
					Code:    "REGISTRATION_FAILED",
					Message: "Registration failed. Please check your details or try logging in.",
				})
			},
			fnCheckMethods: checkMethods,
		},
		"dublicate_email": {
			Comm:              "email уже занят — UNIQUE violation",
			IsError:           true,
			IpReq:             ip1,
			AgentReq:          agent1,
			DeviceIdReq:       deviceId1,
			ContentType:       "application/json",
			UserName:          username1,
			Email:             email1,
			Password:          pass1,
			FieldBodyForCheck: []string{"error", "code", "message"},
			MethodMustCall:    []string{"Create"},
			MethodNoCall:      buildNoCall("Create"),
			fnSetUpMock: func() {
				resetMock(&userStoreBD.Mock, t)
				resetMock(&sessionStore.Mock, t)

				userStoreBD.On("Create", context.Background(), mock.Anything).
					Return(uuid.Nil(), dupErr("email")).
					Once()
			},
			fnReadyAnswer: func() *ResponseResult {
				return errAnswer(http.StatusConflict, middleware.ErrBody{
					Err:     "conflict",
					Code:    "REGISTRATION_FAILED",
					Message: "Registration failed. Please check your details or try logging in.",
				})
			},
			fnCheckMethods: checkMethods,
		},
		"dublicate_phone": {
			Comm:              "phone уже занят — UNIQUE violation",
			IsError:           true,
			IpReq:             ip1,
			AgentReq:          agent1,
			DeviceIdReq:       deviceId1,
			ContentType:       "application/json",
			UserName:          username1,
			Phone:             phone1,
			Password:          pass1,
			FieldBodyForCheck: []string{"error", "code", "message"},
			MethodMustCall:    []string{"Create"},
			MethodNoCall:      buildNoCall("Create"),
			fnSetUpMock: func() {
				resetMock(&userStoreBD.Mock, t)
				resetMock(&sessionStore.Mock, t)

				userStoreBD.On("Create", context.Background(), mock.Anything).
					Return(uuid.Nil(), dupErr("phone")).
					Once()
			},
			fnReadyAnswer: func() *ResponseResult {
				return errAnswer(http.StatusConflict, middleware.ErrBody{
					Err:     "conflict",
					Code:    "REGISTRATION_FAILED",
					Message: "Registration failed. Please check your details or try logging in.",
				})
			},
			fnCheckMethods: checkMethods,
		},
		"empty_username": {
			Comm:              "пустой username",
			IsError:           true,
			IpReq:             ip1,
			AgentReq:          agent1,
			DeviceIdReq:       deviceId1,
			ContentType:       "application/json",
			UserName:          "",
			Password:          pass1,
			FieldBodyForCheck: []string{"error", "code", "message"},
			MethodMustCall:    []string{},
			MethodNoCall:      buildNoCall(),
			fnSetUpMock: func() {
				resetMock(&userStoreBD.Mock, t)
				resetMock(&sessionStore.Mock, t)
			},
			fnReadyAnswer: func() *ResponseResult {
				return errAnswer(http.StatusBadRequest, middleware.ErrBody{
					Err:     "invalid_request",
					Code:    "VALIDATION_ERROR",
					Message: "Username and password are required.",
				})
			},
			fnCheckMethods: checkMethods,
		},
		"empty_password": {
			Comm:              "пустой password",
			IsError:           true,
			IpReq:             ip1,
			AgentReq:          agent1,
			DeviceIdReq:       deviceId1,
			ContentType:       "application/json",
			UserName:          username1,
			Password:          "",
			FieldBodyForCheck: []string{"error", "code", "message"},
			MethodMustCall:    []string{},
			MethodNoCall:      buildNoCall(),
			fnSetUpMock: func() {
				resetMock(&userStoreBD.Mock, t)
				resetMock(&sessionStore.Mock, t)
			},
			fnReadyAnswer: func() *ResponseResult {
				return errAnswer(http.StatusBadRequest, middleware.ErrBody{
					Err:     "invalid_request",
					Code:    "VALIDATION_ERROR",
					Message: "Username and password are required.",
				})
			},
			fnCheckMethods: checkMethods,
		},
		"whitespace_username": {
			Comm:              "username из одних пробелов — TrimSpace даёт пустую строку",
			IsError:           true,
			IpReq:             ip1,
			AgentReq:          agent1,
			DeviceIdReq:       deviceId1,
			ContentType:       "application/json",
			UserName:          "    ",
			Password:          pass1,
			FieldBodyForCheck: []string{"error", "code", "message"},
			MethodMustCall:    []string{},
			MethodNoCall:      buildNoCall(),
			fnSetUpMock: func() {
				resetMock(&userStoreBD.Mock, t)
				resetMock(&sessionStore.Mock, t)
			},
			fnReadyAnswer: func() *ResponseResult {
				return errAnswer(http.StatusBadRequest, middleware.ErrBody{
					Err:     "invalid_request",
					Code:    "VALIDATION_ERROR",
					Message: "Username and password are required.",
				})
			},
			fnCheckMethods: checkMethods,
		},
		"whitespace_password": {
			Comm:              "password из одних пробелов",
			IsError:           true,
			IpReq:             ip1,
			AgentReq:          agent1,
			DeviceIdReq:       deviceId1,
			ContentType:       "application/json",
			UserName:          username1,
			Password:          "    ",
			FieldBodyForCheck: []string{"error", "code", "message"},
			MethodMustCall:    []string{},
			MethodNoCall:      buildNoCall(),
			fnSetUpMock: func() {
				resetMock(&userStoreBD.Mock, t)
				resetMock(&sessionStore.Mock, t)
			},
			fnReadyAnswer: func() *ResponseResult {
				return errAnswer(http.StatusBadRequest, middleware.ErrBody{
					Err:     "invalid_request",
					Code:    "VALIDATION_ERROR",
					Message: "Username and password are required.",
				})
			},
			fnCheckMethods: checkMethods,
		},
		"db_error": {
			Comm:              "userStoreBD.Create вернул generic error",
			IsError:           true,
			IpReq:             ip1,
			AgentReq:          agent1,
			DeviceIdReq:       deviceId1,
			ContentType:       "application/json",
			UserName:          username1,
			Password:          pass1,
			FieldBodyForCheck: []string{"error", "code", "message"},
			MethodMustCall:    []string{"Create"},
			MethodNoCall:      buildNoCall("Create"),
			fnSetUpMock: func() {
				resetMock(&userStoreBD.Mock, t)
				resetMock(&sessionStore.Mock, t)

				userStoreBD.On("Create", context.Background(), mock.Anything).
					Return(uuid.Nil(), errors.New("connection reset by peer")).
					Once()
			},
			fnReadyAnswer: func() *ResponseResult {
				return errAnswer(http.StatusInternalServerError, middleware.ErrBody{
					Err:     "Internal Server Error",
					Code:    "AUTH_SERVICE_ERROR",
					Message: "Authentication service is temporarily unavailable. Please try again later.",
				})
			},
			fnCheckMethods: checkMethods,
		},
		"session_registration_fail": {
			Comm:              "пользователь создан, но sessionStore.Registration упал",
			IsError:           true,
			IpReq:             ip1,
			AgentReq:          agent1,
			DeviceIdReq:       deviceId1,
			ContentType:       "application/json",
			UserName:          username1,
			Password:          pass1,
			FieldBodyForCheck: []string{"error", "code", "message"},
			MethodMustCall:    []string{"Create", "Registration"},
			MethodNoCall:      buildNoCall("Create", "Registration"),
			fnSetUpMock: func() {
				resetMock(&userStoreBD.Mock, t)
				resetMock(&sessionStore.Mock, t)

				userStoreBD.On("Create", context.Background(), mock.Anything).
					Return(uuid.NewV7(), nil).
					Once()
				sessionStore.On("Registration", context.Background(), mock.Anything, mock.Anything).
					Return(errors.New("redis unavailable")).
					Once()
			},
			fnReadyAnswer: func() *ResponseResult {
				return errAnswer(http.StatusInternalServerError, middleware.ErrBody{
					Err:     "Internal Server Error",
					Code:    "AUTH_SERVICE_ERROR",
					Message: "Authentication service is temporarily unavailable. Please try again later.",
				})
			},
			fnCheckMethods: checkMethods,
		},
		"missing_device_id": {
			Comm:              "нет заголовка Device-Id",
			IsError:           true,
			IpReq:             ip1,
			AgentReq:          agent1,
			DeviceIdReq:       "", // не задаём
			ContentType:       "application/json",
			UserName:          username1,
			Password:          pass1,
			FieldBodyForCheck: []string{"error", "code", "message"},
			MethodMustCall:    []string{},
			MethodNoCall:      buildNoCall(),
			fnSetUpMock: func() {
				resetMock(&userStoreBD.Mock, t)
				resetMock(&sessionStore.Mock, t)
			},
			fnReadyAnswer: func() *ResponseResult {
				return errAnswer(http.StatusBadRequest, middleware.ErrBody{
					Err:     "bad request",
					Code:    "BAD_REQUEST",
					Message: "The request is missing important fields.",
				})
			},
			fnCheckMethods: checkMethods,
		},
		"missing_user_agent": {
			Comm:              "нет заголовка User-Agent",
			IsError:           true,
			IpReq:             ip1,
			AgentReq:          "", // не задаём
			DeviceIdReq:       deviceId1,
			ContentType:       "application/json",
			UserName:          username1,
			Password:          pass1,
			FieldBodyForCheck: []string{"error", "code", "message"},
			MethodMustCall:    []string{},
			MethodNoCall:      buildNoCall(),
			fnSetUpMock: func() {
				resetMock(&userStoreBD.Mock, t)
				resetMock(&sessionStore.Mock, t)
			},
			fnReadyAnswer: func() *ResponseResult {
				return errAnswer(http.StatusBadRequest, middleware.ErrBody{
					Err:     "bad request",
					Code:    "BAD_REQUEST",
					Message: "The request is missing important fields.",
				})
			},
			fnCheckMethods: checkMethods,
		},
		"wrong_content_type": {
			Comm:              "Content-Type не application/json",
			IsError:           true,
			IpReq:             ip1,
			AgentReq:          agent1,
			DeviceIdReq:       deviceId1,
			ContentType:       "text/plain",
			UserName:          username1,
			Password:          pass1,
			FieldBodyForCheck: []string{"error", "code", "message"},
			MethodMustCall:    []string{},
			MethodNoCall:      buildNoCall(),
			fnSetUpMock: func() {
				resetMock(&userStoreBD.Mock, t)
				resetMock(&sessionStore.Mock, t)
			},
			fnReadyAnswer: func() *ResponseResult {
				return errAnswer(http.StatusUnsupportedMediaType, middleware.ErrBody{
					Err:     "invalid_body",
					Code:    "INVALID_BODY",
					Message: "Unsupported Media Type",
				})
			},
			fnCheckMethods: checkMethods,
		},
		"invalid_json": {
			Comm:              "битый JSON в теле",
			IsError:           true,
			IpReq:             ip1,
			AgentReq:          agent1,
			DeviceIdReq:       deviceId1,
			ContentType:       "application/json",
			RawBody:           `{not valid json}`,
			FieldBodyForCheck: []string{"error", "code", "message"},
			MethodMustCall:    []string{},
			MethodNoCall:      buildNoCall(),
			fnSetUpMock: func() {
				resetMock(&userStoreBD.Mock, t)
				resetMock(&sessionStore.Mock, t)
			},
			fnReadyAnswer: func() *ResponseResult {
				return errAnswer(http.StatusBadRequest, middleware.ErrBody{
					Err:     "bad request",
					Code:    "BAD_REQUEST",
					Message: "The request body contains invalid or missing fields.",
				})
			},
			fnCheckMethods: checkMethods,
		},
		"bad_remote_addr": {
			Comm:              "невалидный RemoteAddr (SplitHostPort падает)",
			IsError:           true,
			IpReq:             "invalid", // нет порта
			AgentReq:          agent1,
			DeviceIdReq:       deviceId1,
			ContentType:       "application/json",
			UserName:          username1,
			Password:          pass1,
			FieldBodyForCheck: []string{"error", "code", "message"},
			MethodMustCall:    []string{},
			MethodNoCall:      buildNoCall(),
			fnSetUpMock: func() {
				resetMock(&userStoreBD.Mock, t)
				resetMock(&sessionStore.Mock, t)
			},
			fnReadyAnswer: func() *ResponseResult {
				return errAnswer(http.StatusBadRequest, middleware.ErrBody{
					Err:     "bad request",
					Code:    "BAD_REQUEST",
					Message: "The request is missing important fields.",
				})
			},
			fnCheckMethods: checkMethods,
		},
		"body_too_large": {
			Comm:              "тело запроса > 64KiB",
			IsError:           true,
			IpReq:             ip1,
			AgentReq:          agent1,
			DeviceIdReq:       deviceId1,
			ContentType:       "application/json",
			RawBody:           strings.Repeat("a", 100*1024),
			FieldBodyForCheck: []string{"error", "code", "message"},
			MethodMustCall:    []string{},
			MethodNoCall:      buildNoCall(),
			fnSetUpMock: func() {
				resetMock(&userStoreBD.Mock, t)
				resetMock(&sessionStore.Mock, t)
			},
			fnReadyAnswer: func() *ResponseResult {
				return errAnswer(http.StatusBadRequest, middleware.ErrBody{
					Err:     "bad request",
					Code:    "BAD_REQUEST",
					Message: "The request body contains invalid or missing fields.",
				})
			},
			fnCheckMethods: checkMethods,
		},
	}

	for name, val := range table {
		t.Run(name, func(t *testing.T) {
			val.fnSetUpMock()

			// Собираем тело: RawBody приоритетнее, иначе JSON из полей.
			body := val.RawBody
			if body == "" {
				body = fmt.Sprintf(
					`{"username": "%s", "email": "%s", "phone": "%s", "password": "%s"}`,
					val.UserName, val.Email, val.Phone, val.Password,
				)
			}

			req := httptest.NewRequest(http.MethodPost, "/reg", bytes.NewBufferString(body))

			contentType := val.ContentType
			if contentType == "" {
				contentType = "application/json"
			}
			req.Header.Add("Content-Type", contentType)
			req.Header.Add("Accept", "application/json")

			if val.DeviceIdReq != "" {
				req.Header.Add("Device-Id", val.DeviceIdReq)
			}
			if val.AgentReq != "" {
				req.Header.Add("User-Agent", val.AgentReq)
			}

			if val.IpReq != "" {
				req.RemoteAddr = val.IpReq
			}

			rec := httptest.NewRecorder()

			authHandler.RegistrationUser(rec, req)

			mustResp := val.fnReadyAnswer()

			if mustResp.Code != rec.Code {
				t.Errorf("fail http status code dont equal want %v have %v", mustResp.Code, rec.Code)
			}

			if len(mustResp.Body) > 0 {
				if val.IsError {
					var mustErrBody middleware.ErrBody
					if err := json.Unmarshal(mustResp.Body, &mustErrBody); err != nil {
						t.Fatalf("unmarshal json must %v", err)
					}

					var outErrBody middleware.ErrBody
					if err := json.Unmarshal(rec.Body.Bytes(), &outErrBody); err != nil {
						t.Fatalf("unmarshal json out %v", err)
					}

					if mustErrBody.Err != outErrBody.Err ||
						mustErrBody.Code != outErrBody.Code ||
						mustErrBody.Message != outErrBody.Message {
						t.Errorf("fail http body dont equal want %+v have %+v", mustErrBody, outErrBody)
					}
				} else {
					var data map[string]any
					if err := json.Unmarshal(mustResp.Body, &data); err != nil {
						t.Fatalf("unmarshal json must %v", err)
					}

					var outdata map[string]any
					if err := json.Unmarshal(rec.Body.Bytes(), &outdata); err != nil {
						t.Fatalf("unmarshal json out %v", err)
					}

					if data["token_type"] != outdata["token_type"] ||
						data["expires_in"] != outdata["expires_in"] {
						t.Errorf("fail http body dont equal")
					}

					if _, ok := outdata["access_token"]; !ok {
						t.Errorf("fail answer dont have access_token")
					}
					if _, ok := outdata["refresh_token"]; !ok {
						t.Errorf("fail answer dont have refresh_token")
					}
				}
			}

			// Проверяем WWW-Authenticate, если эталон его задаёт.
			errHeaderAuth := mustResp.Headers.Get("WWW-Authenticate")
			if errHeaderAuth != "" {
				respHead := rec.Header().Get("WWW-Authenticate")
				if errHeaderAuth != respHead {
					t.Errorf("fail http auth header dont equal want %v have %v", errHeaderAuth, respHead)
				}
			}

			if val.fnCheckMethods != nil {
				val.fnCheckMethods(val.MethodMustCall, val.MethodNoCall)
			}
		})
	}
}

// SPEC SignIn
// Что это и что делает? - handler аутентификации пользователя.
// Принимает username/email/phone + password, валидирует тело, ищет пользователя в
// userStore через GetByOpt, сравнивает bcrypt-хеш, при успехе создаёт сессию
// в sessionStore и возвращает пару access/refresh токенов.
//
//	Tests:
//		correct_by_username      - успешный вход по username+password
//		correct_by_email         - успешный вход по email+password
//		correct_by_phone         - успешный вход по phone+password
//		wrong_password           - пользователь есть, но пароль не совпадает → 401
//		user_not_found           - пользователя нет в БД → 401 (fake bcrypt для тайминга)
//		empty_identifier         - не передан ни username, ни email, ни phone → 400
//		empty_password           - пустой пароль → 400
//		db_error                 - GetByOpt вернул произвольную ошибку → 500
//		session_registration_fail - sessionStore.Registration упал → 500
//		missing_headers          - нет User-Agent/Device-Id → 400
//		wrong_content_type       - Content-Type не application/json → 415
func TestSignIn(t *testing.T) {
	util.LoadEnvFile()
	cm := config.NewConfigManager()
	cm.Init(context.TODO(), "")

	userStoreBD := domain.NewUserStoreMock(t)
	sessionStore := domain.NewSessionStoreMock(t)
	tu := tokens.NewTokenUtil(cm)

	ip1 := "1.1.1.1:5432"
	agent1 := "chrome windows 10"
	deviceId1 := "12345"

	username1 := "username"
	email1 := "user@example.com"
	phone1 := "+79991234567"
	pass1 := "54321"

	// Готовим bcrypt-хеш «настоящего» пароля — его мы положим в БД-мок.
	hashedPass, err := bcrypt.GenerateFromPassword([]byte(pass1), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("failed hash password: %v", err)
	}

	userId1 := uuid.NewV7()

	testUser := &domain.User{
		Id:        userId1,
		UserName:  username1,
		Password:  string(hashedPass),
		Email:     email1,
		Phone:     phone1,
		CreatedAt: time.Now(),
	}

	authHandler := handler.NewAuthHandler(cm, domain.GetMockAuditService(), sessionStore, tu, userStoreBD)

	type TableTest struct {
		// пояснение для теста
		Comm string
		// является ли тест ошибкой
		IsError bool
		// параметры запроса
		IpReq       string
		AgentReq    string
		DeviceIdReq string
		ContentType string
		// поля тела запроса
		UserName string
		Email    string
		Phone    string
		Password string
		// поля тела ответа, которые нужно проверить
		FieldBodyForCheck []string
		// методы, которые должны быть вызваны в моках
		MethodMustCall []string
		// методы, которые НЕ должны быть вызваны
		MethodNoCall []string
		// подготовка моков
		fnSetUpMock func()
		// эталонный ответ
		fnReadyAnswer func() *ResponseResult
		// проверка вызовов
		fnCheckMethods func(methodMustCall, methodNoCall []string)
	}

	checkMethods := func(methodMustCall, methodNoCall []string) {
		called := make(map[string]struct{})
		for _, call := range userStoreBD.Calls {
			called[call.Method] = struct{}{}
		}
		for _, call := range sessionStore.Calls {
			called[call.Method] = struct{}{}
		}

		for _, m := range methodMustCall {
			if _, ok := called[m]; !ok {
				t.Errorf("method %s was NOT called, but should have been", m)
			}
		}
		for _, m := range methodNoCall {
			if _, ok := called[m]; ok {
				t.Errorf("method %s WAS called, but should NOT have been", m)
			}
		}
	}

	// шаблон успешного ответа
	successAnswer := func() *ResponseResult {
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
	}

	// хелпер для ErrorBody-ответа
	errAnswer := func(status int, body middleware.ErrBody) *ResponseResult {
		bodyJson, _ := json.Marshal(body)
		resp := httptest.NewRecorder()
		resp.Header().Set("Content-Type", "application/json;charset=UTF-8")
		resp.WriteHeader(status)
		resp.Write(bodyJson)
		return &ResponseResult{
			Code:    resp.Code,
			Headers: resp.Header(),
			Body:    resp.Body.Bytes(),
		}
	}

	table := map[string]TableTest{
		"correct_by_username": {
			Comm:              "успешный вход по username+password",
			IsError:           false,
			IpReq:             ip1,
			AgentReq:          agent1,
			DeviceIdReq:       deviceId1,
			ContentType:       "application/json",
			UserName:          username1,
			Password:          pass1,
			FieldBodyForCheck: []string{"access_token", "expires_in", "token_type", "refresh_token"},
			MethodMustCall:    []string{"GetByOpt", "Registration"},
			MethodNoCall: []string{
				"GetAllSession", "DeleteAll", "DeleteByRefresh", "UpdateIpAdress",
				"GetSessionByFamilyId", "GetFromGracePeriodic", "CreateGracePeriodic",
			},
			fnSetUpMock: func() {
				resetMock(&userStoreBD.Mock, t)
				resetMock(&sessionStore.Mock, t)

				userStoreBD.On("GetByOpt", context.Background(), mock.Anything).
					Return(testUser, nil).
					Once()
				sessionStore.On("Registration", context.Background(), mock.Anything, mock.Anything).
					Return(nil).
					Once()
			},
			fnReadyAnswer:  successAnswer,
			fnCheckMethods: checkMethods,
		},
		"correct_by_email": {
			Comm:              "успешный вход по email+password",
			IsError:           false,
			IpReq:             ip1,
			AgentReq:          agent1,
			DeviceIdReq:       deviceId1,
			ContentType:       "application/json",
			Email:             email1,
			Password:          pass1,
			FieldBodyForCheck: []string{"access_token", "expires_in", "token_type", "refresh_token"},
			MethodMustCall:    []string{"GetByOpt", "Registration"},
			MethodNoCall: []string{
				"GetAllSession", "DeleteAll", "DeleteByRefresh", "UpdateIpAdress",
				"GetSessionByFamilyId", "GetFromGracePeriodic", "CreateGracePeriodic",
			},
			fnSetUpMock: func() {
				resetMock(&userStoreBD.Mock, t)
				resetMock(&sessionStore.Mock, t)

				userStoreBD.On("GetByOpt", context.Background(), mock.Anything).
					Return(testUser, nil).
					Once()
				sessionStore.On("Registration", context.Background(), mock.Anything, mock.Anything).
					Return(nil).
					Once()
			},
			fnReadyAnswer:  successAnswer,
			fnCheckMethods: checkMethods,
		},
		"correct_by_phone": {
			Comm:              "успешный вход по phone+password",
			IsError:           false,
			IpReq:             ip1,
			AgentReq:          agent1,
			DeviceIdReq:       deviceId1,
			ContentType:       "application/json",
			Phone:             phone1,
			Password:          pass1,
			FieldBodyForCheck: []string{"access_token", "expires_in", "token_type", "refresh_token"},
			MethodMustCall:    []string{"GetByOpt", "Registration"},
			MethodNoCall: []string{
				"GetAllSession", "DeleteAll", "DeleteByRefresh", "UpdateIpAdress",
				"GetSessionByFamilyId", "GetFromGracePeriodic", "CreateGracePeriodic",
			},
			fnSetUpMock: func() {
				resetMock(&userStoreBD.Mock, t)
				resetMock(&sessionStore.Mock, t)

				userStoreBD.On("GetByOpt", context.Background(), mock.Anything).
					Return(testUser, nil).
					Once()
				sessionStore.On("Registration", context.Background(), mock.Anything, mock.Anything).
					Return(nil).
					Once()
			},
			fnReadyAnswer:  successAnswer,
			fnCheckMethods: checkMethods,
		},
		"wrong_password": {
			Comm:              "пользователь есть, но пароль не совпал",
			IsError:           true,
			IpReq:             ip1,
			AgentReq:          agent1,
			DeviceIdReq:       deviceId1,
			ContentType:       "application/json",
			UserName:          username1,
			Password:          "definitely-wrong-password",
			FieldBodyForCheck: []string{"error", "code", "message"},
			MethodMustCall:    []string{"GetByOpt"},
			MethodNoCall: []string{
				"Registration", "GetAllSession", "DeleteAll", "DeleteByRefresh",
				"UpdateIpAdress", "GetSessionByFamilyId", "GetFromGracePeriodic", "CreateGracePeriodic",
			},
			fnSetUpMock: func() {
				resetMock(&userStoreBD.Mock, t)
				resetMock(&sessionStore.Mock, t)

				userStoreBD.On("GetByOpt", context.Background(), mock.Anything).
					Return(testUser, nil).
					Once()
			},
			fnReadyAnswer: func() *ResponseResult {
				return errAnswer(http.StatusUnauthorized, middleware.ErrBody{
					Err:     "invalid_grant",
					Code:    "INVALID_CREDENTIALS",
					Message: "Invalid username or password.",
				})
			},
			fnCheckMethods: checkMethods,
		},
		"user_not_found": {
			Comm:              "пользователь не найден в БД",
			IsError:           true,
			IpReq:             ip1,
			AgentReq:          agent1,
			DeviceIdReq:       deviceId1,
			ContentType:       "application/json",
			UserName:          "ghost-user",
			Password:          pass1,
			FieldBodyForCheck: []string{"error", "code", "message"},
			MethodMustCall:    []string{"GetByOpt"},
			MethodNoCall: []string{
				"Registration", "GetAllSession", "DeleteAll", "DeleteByRefresh",
				"UpdateIpAdress", "GetSessionByFamilyId", "GetFromGracePeriodic", "CreateGracePeriodic",
			},
			fnSetUpMock: func() {
				resetMock(&userStoreBD.Mock, t)
				resetMock(&sessionStore.Mock, t)

				userStoreBD.On("GetByOpt", context.Background(), mock.Anything).
					Return(nil, postgres.ErrUserDontExist).
					Once()
			},
			fnReadyAnswer: func() *ResponseResult {
				return errAnswer(http.StatusUnauthorized, middleware.ErrBody{
					Err:     "invalid_grant",
					Code:    "INVALID_CREDENTIALS",
					Message: "Invalid username or password.",
				})
			},
			fnCheckMethods: checkMethods,
		},
		"empty_identifier": {
			Comm:              "не передан ни username, ни email, ни phone",
			IsError:           true,
			IpReq:             ip1,
			AgentReq:          agent1,
			DeviceIdReq:       deviceId1,
			ContentType:       "application/json",
			Password:          pass1,
			FieldBodyForCheck: []string{"error", "code", "message"},
			MethodMustCall:    []string{},
			MethodNoCall: []string{
				"GetByOpt", "Registration", "GetAllSession", "DeleteAll", "DeleteByRefresh",
				"UpdateIpAdress", "GetSessionByFamilyId", "GetFromGracePeriodic", "CreateGracePeriodic",
			},
			fnSetUpMock: func() {
				resetMock(&userStoreBD.Mock, t)
				resetMock(&sessionStore.Mock, t)
			},
			fnReadyAnswer: func() *ResponseResult {
				return errAnswer(http.StatusBadRequest, middleware.ErrBody{
					Err:     "invalid_request",
					Code:    "VALIDATION_ERROR",
					Message: "Username and password are required.",
				})
			},
			fnCheckMethods: checkMethods,
		},
		"empty_password": {
			Comm:              "пустой пароль",
			IsError:           true,
			IpReq:             ip1,
			AgentReq:          agent1,
			DeviceIdReq:       deviceId1,
			ContentType:       "application/json",
			UserName:          username1,
			Password:          "",
			FieldBodyForCheck: []string{"error", "code", "message"},
			MethodMustCall:    []string{},
			MethodNoCall: []string{
				"GetByOpt", "Registration", "GetAllSession", "DeleteAll", "DeleteByRefresh",
				"UpdateIpAdress", "GetSessionByFamilyId", "GetFromGracePeriodic", "CreateGracePeriodic",
			},
			fnSetUpMock: func() {
				resetMock(&userStoreBD.Mock, t)
				resetMock(&sessionStore.Mock, t)
			},
			fnReadyAnswer: func() *ResponseResult {
				return errAnswer(http.StatusBadRequest, middleware.ErrBody{
					Err:     "invalid_request",
					Code:    "VALIDATION_ERROR",
					Message: "Username and password are required.",
				})
			},
			fnCheckMethods: checkMethods,
		},
		"db_error": {
			Comm:              "GetByOpt вернул произвольную ошибку",
			IsError:           true,
			IpReq:             ip1,
			AgentReq:          agent1,
			DeviceIdReq:       deviceId1,
			ContentType:       "application/json",
			UserName:          username1,
			Password:          pass1,
			FieldBodyForCheck: []string{"error", "code", "message"},
			MethodMustCall:    []string{"GetByOpt"},
			MethodNoCall: []string{
				"Registration", "GetAllSession", "DeleteAll", "DeleteByRefresh",
				"UpdateIpAdress", "GetSessionByFamilyId", "GetFromGracePeriodic", "CreateGracePeriodic",
			},
			fnSetUpMock: func() {
				resetMock(&userStoreBD.Mock, t)
				resetMock(&sessionStore.Mock, t)

				userStoreBD.On("GetByOpt", context.Background(), mock.Anything).
					Return(nil, errors.New("db connection reset")).
					Once()
			},
			fnReadyAnswer: func() *ResponseResult {
				return errAnswer(http.StatusInternalServerError, middleware.ErrBody{
					Err:     "Internal Server Error",
					Code:    "AUTH_SERVICE_ERROR",
					Message: "Authentication service is temporarily unavailable. Please try again later.",
				})
			},
			fnCheckMethods: checkMethods,
		},
		"session_registration_fail": {
			Comm:              "userStore вернул пользователя, пароль верный, но sessionStore.Registration упал",
			IsError:           true,
			IpReq:             ip1,
			AgentReq:          agent1,
			DeviceIdReq:       deviceId1,
			ContentType:       "application/json",
			UserName:          username1,
			Password:          pass1,
			FieldBodyForCheck: []string{"error", "code", "message"},
			MethodMustCall:    []string{"GetByOpt", "Registration"},
			MethodNoCall: []string{
				"GetAllSession", "DeleteAll", "DeleteByRefresh", "UpdateIpAdress",
				"GetSessionByFamilyId", "GetFromGracePeriodic", "CreateGracePeriodic",
			},
			fnSetUpMock: func() {
				resetMock(&userStoreBD.Mock, t)
				resetMock(&sessionStore.Mock, t)

				userStoreBD.On("GetByOpt", context.Background(), mock.Anything).
					Return(testUser, nil).
					Once()
				sessionStore.On("Registration", context.Background(), mock.Anything, mock.Anything).
					Return(errors.New("redis unavailable")).
					Once()
			},
			fnReadyAnswer: func() *ResponseResult {
				return errAnswer(http.StatusInternalServerError, middleware.ErrBody{
					Err:     "Internal Server Error",
					Code:    "AUTH_SERVICE_ERROR",
					Message: "Authentication service is temporarily unavailable. Please try again later.",
				})
			},
			fnCheckMethods: checkMethods,
		},
		"missing_headers": {
			Comm:              "отсутствует Device-Id",
			IsError:           true,
			IpReq:             ip1,
			AgentReq:          agent1,
			DeviceIdReq:       "", // пусто — validateCheck должен отсечь
			ContentType:       "application/json",
			UserName:          username1,
			Password:          pass1,
			FieldBodyForCheck: []string{"error", "code", "message"},
			MethodMustCall:    []string{},
			MethodNoCall: []string{
				"GetByOpt", "Registration", "GetAllSession", "DeleteAll", "DeleteByRefresh",
				"UpdateIpAdress", "GetSessionByFamilyId", "GetFromGracePeriodic", "CreateGracePeriodic",
			},
			fnSetUpMock: func() {
				resetMock(&userStoreBD.Mock, t)
				resetMock(&sessionStore.Mock, t)
			},
			fnReadyAnswer: func() *ResponseResult {
				return errAnswer(http.StatusBadRequest, middleware.ErrBody{
					Err:     "bad request",
					Code:    "BAD_REQUEST",
					Message: "The request is missing important fields.",
				})
			},
			fnCheckMethods: checkMethods,
		},
		"wrong_content_type": {
			Comm:              "Content-Type не application/json",
			IsError:           true,
			IpReq:             ip1,
			AgentReq:          agent1,
			DeviceIdReq:       deviceId1,
			ContentType:       "text/plain",
			UserName:          username1,
			Password:          pass1,
			FieldBodyForCheck: []string{"error", "code", "message"},
			MethodMustCall:    []string{},
			MethodNoCall: []string{
				"GetByOpt", "Registration", "GetAllSession", "DeleteAll", "DeleteByRefresh",
				"UpdateIpAdress", "GetSessionByFamilyId", "GetFromGracePeriodic", "CreateGracePeriodic",
			},
			fnSetUpMock: func() {
				resetMock(&userStoreBD.Mock, t)
				resetMock(&sessionStore.Mock, t)
			},
			fnReadyAnswer: func() *ResponseResult {
				return errAnswer(http.StatusUnsupportedMediaType, middleware.ErrBody{
					Err:     "invalid_body",
					Code:    "INVALID_BODY",
					Message: "Unsupported Media Type",
				})
			},
			fnCheckMethods: checkMethods,
		},
	}

	for name, val := range table {
		t.Run(name, func(t *testing.T) {
			val.fnSetUpMock()

			body := fmt.Sprintf(`{"username": "%s", "email": "%s", "phone": "%s", "password": "%s"}`,
				val.UserName, val.Email, val.Phone, val.Password)

			req := httptest.NewRequest(http.MethodPost, "/signin", bytes.NewBufferString(body))

			contentType := val.ContentType
			if contentType == "" {
				contentType = "application/json"
			}
			req.Header.Add("Content-Type", contentType)
			req.Header.Add("Accept", "application/json")

			if val.DeviceIdReq != "" {
				req.Header.Add("Device-Id", val.DeviceIdReq)
			}
			if val.AgentReq != "" {
				req.Header.Add("User-Agent", val.AgentReq)
			}

			req.RemoteAddr = val.IpReq

			rec := httptest.NewRecorder()
			authHandler.SingIn(rec, req)

			mustResp := val.fnReadyAnswer()

			if mustResp.Code != rec.Code {
				t.Errorf("fail http status code dont equal want %v have %v", mustResp.Code, rec.Code)
			}

			if len(mustResp.Body) > 0 {
				if val.IsError {
					var mustErrBody middleware.ErrBody
					if err := json.Unmarshal(mustResp.Body, &mustErrBody); err != nil {
						t.Fatalf("unmarshal json must %v", err)
					}

					var outErrBody middleware.ErrBody
					if err := json.Unmarshal(rec.Body.Bytes(), &outErrBody); err != nil {
						t.Fatalf("unmarshal json out %v", err)
					}

					if mustErrBody.Err != outErrBody.Err ||
						mustErrBody.Code != outErrBody.Code ||
						mustErrBody.Message != outErrBody.Message {
						t.Errorf("fail http body dont equal want %+v have %+v", mustErrBody, outErrBody)
					}
				} else {
					var data map[string]any
					if err := json.Unmarshal(mustResp.Body, &data); err != nil {
						t.Fatalf("unmarshal json must %v", err)
					}

					var outdata map[string]any
					if err := json.Unmarshal(rec.Body.Bytes(), &outdata); err != nil {
						t.Fatalf("unmarshal json out %v", err)
					}

					if data["token_type"] != outdata["token_type"] ||
						data["expires_in"] != outdata["expires_in"] {
						t.Errorf("fail http body dont equal")
					}

					_, ok := outdata["access_token"]
					if !ok {
						t.Errorf("fail answer dont have access_token")
					}
					_, ok = outdata["refresh_token"]
					if !ok {
						t.Errorf("fail answer dont have refresh_token")
					}
				}
			}

			// Если эталон задаёт WWW-Authenticate — сверяем
			errHeaderAuth := mustResp.Headers.Get("WWW-Authenticate")
			if errHeaderAuth != "" {
				respHead := rec.Header().Get("WWW-Authenticate")
				if errHeaderAuth != respHead {
					t.Errorf("fail http auth header dont equal want %v have %v", errHeaderAuth, respHead)
				}
			}

			val.fnCheckMethods(val.MethodMustCall, val.MethodNoCall)
		})
	}
}

// SPEC Authentication
// Что это и что делает? - handler проверки access JWT (RFC 6750, protected resource).
// Клиент присылает access токен в заголовке Authorization: Bearer <token>
// плюс заголовки User-Agent и Device-Id. Handler:
//  1. извлекает Bearer-токен (схема регистронезависима: RFC 6750 §2.1);
//  2. валидирует подпись, iss, exp, iat через tu.ValidAccessToken;
//  3. по UserId+FamilyId из claims достаёт сессию из sessionStore;
//  4. сверяет session.DeviceId == Device-Id header и session.Agent == User-Agent header;
//  5. если IP запроса отличается от session.Ip — вызывает UpdateIpAdress;
//  6. на успех → 200 OK.
//
// Статусы ошибок (RFC 6750 §3.1):
//
//   - отсутствующий/невалидный/просроченный/отозванный токен → 401 + WWW-Authenticate: Bearer ...
//
//   - 400 допустим только на token endpoint (в /refresh), здесь НЕ используется.
//
//   - внутренние ошибки стора → 500.
//
//     Tests:
//     correct_request              - валидный токен, сессия найдена, контекст и IP совпадают → 200
//     lowercase_bearer_scheme      - схема "bearer" в нижнем регистре — регистронезависима → 200
//     ip_changed                   - всё совпадает, но IP отличается → 200, UpdateIpAdress
//     missing_authorization        - нет заголовка Authorization → 401 INVALID_TOKEN
//     non_bearer_scheme            - схема не Bearer → 401 INVALID_TOKEN
//     malformed_authorization      - "Bearer" без токена → 401 INVALID_TOKEN
//     empty_token_after_bearer     - "Bearer " с пустым токеном → 401 INVALID_TOKEN
//     expired_token                - exp в прошлом → 401 INVALID_GRANT + WWW-Authenticate
//     invalid_signature            - подпись не тем ключом → 401 INVALID_TOKEN
//     invalid_format               - мусор вместо JWT → 401 INVALID_TOKEN
//     future_date_token            - iat в будущем → 401 INVALID_TOKEN + DeleteByRefresh
//     session_not_found            - валидный токен, сессия отсутствует → 401 INVALID_TOKEN
//     session_context_mismatch     - session.DeviceId/Agent != заголовков → 401 SESSION_CONTEXT_MISMATCH + DeleteByRefresh
//     db_error_on_get_session      - sessionStore вернул generic error → 500
func TestAuthentication(t *testing.T) {

	util.LoadEnvFile()

	cm := config.NewConfigManager()
	cm.Init(context.TODO(), "")

	userStoreBD := domain.NewUserStoreMock(t)
	sessionStore := domain.NewSessionStoreMock(t)
	tu := tokens.NewTokenUtil(cm)

	ip1 := "1.1.1.1:5432"
	ip2 := "2.2.2.2:5432"
	agent1 := "chrome win 10"
	deviceId1 := "12345"

	userId1 := uuid.NewV7()
	familyId1 := uuid.NewV7()

	authHandler := handler.NewAuthHandler(cm, domain.GetMockAuditService(), sessionStore, tu, userStoreBD)

	// Валидный access токен
	access1, _, err := tu.GeneratePairToken(userId1, familyId1, deviceId1, agent1)
	if err != nil {
		t.Fatalf("failed generate pair token: %v", err)
	}

	// Просроченный access токен
	expiredClaims := &tokens.AccessToken{
		UserId:    userId1,
		FamilyId:  familyId1,
		DeviceId:  deviceId1,
		Agent:     agent1,
		TokenType: tokens.AccessTokenType,
		Version:   "jwt-1",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-1 * time.Hour)),
			Issuer:    tokens.Issuer,
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
			Subject:   userId1.String(),
			ID:        uuid.New().String(),
		},
	}
	expiredToken, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, expiredClaims).
		SignedString(cm.Get().TokenConf.AccessBt)

	// Токен с iat в будущем
	futureClaims := &tokens.AccessToken{
		UserId:    userId1,
		FamilyId:  familyId1,
		DeviceId:  deviceId1,
		Agent:     agent1,
		TokenType: tokens.AccessTokenType,
		Version:   "jwt-1",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(2 * time.Hour)),
			Issuer:    tokens.Issuer,
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
			Subject:   userId1.String(),
			ID:        uuid.New().String(),
		},
	}
	futureToken, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, futureClaims).
		SignedString(cm.Get().TokenConf.AccessBt)

	// Токен с неверной подписью (подписан refresh-ключом вместо access-ключа)
	badSignClaims := tokens.NewAccessToken(userId1, familyId1, deviceId1, agent1, "jwt-1", 15)
	badSignedToken, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, badSignClaims).
		SignedString(cm.Get().TokenConf.RefreshBt)

	session1 := domain.Session{
		UserId:     userId1,
		DeviceId:   deviceId1,
		Agent:      agent1,
		Ip:         "1.1.1.1",
		Version:    "jwt-1",
		CreatedAt:  time.Now(),
		LastUpdate: time.Now(),
	}

	// Вспомогательная проверка вызванных методов через оба мока
	checkMethods := func(methodMustCall, methodNoCall []string) {
		called := make(map[string]struct{})
		for _, call := range sessionStore.Calls {
			called[call.Method] = struct{}{}
		}
		for _, call := range userStoreBD.Calls {
			called[call.Method] = struct{}{}
		}

		for _, m := range methodMustCall {
			if _, ok := called[m]; !ok {
				t.Errorf("method %s was NOT called, but should have been", m)
			}
		}
		for _, m := range methodNoCall {
			if _, ok := called[m]; ok {
				t.Errorf("method %s WAS called, but should NOT have been", m)
			}
		}
	}

	// Методы, которые Authentication не должен трогать ни при каких условиях.
	noSessionMethods := []string{
		"Registration", "GetAllSession", "DeleteAll",
		"CreateGracePeriodic", "GetFromGracePeriodic",
	}

	// Эталон успешного ответа: 200, без обязательного тела.
	successAnswer := func() *ResponseResult {
		resp := httptest.NewRecorder()
		resp.Header().Set("Content-Type", "application/json;charset=UTF-8")
		resp.Header().Set("Cache-Control", "no-store")
		resp.Header().Set("Pragma", "no-cache")
		resp.WriteHeader(http.StatusOK)
		return &ResponseResult{
			Code:    resp.Code,
			Headers: resp.Header(),
			Body:    resp.Body.Bytes(),
		}
	}

	errAnswer := func(status int, body middleware.ErrBody) *ResponseResult {
		bodyJson, _ := json.Marshal(body)
		resp := httptest.NewRecorder()
		resp.Header().Set("Content-Type", "application/json;charset=UTF-8")
		resp.WriteHeader(status)
		resp.Write(bodyJson)
		return &ResponseResult{
			Code:    resp.Code,
			Headers: resp.Header(),
			Body:    resp.Body.Bytes(),
		}
	}

	// RFC 6750: invalid_token → 401 + WWW-Authenticate: Bearer ...
	invalidTokenAnswer := func() *ResponseResult {
		r := errAnswer(http.StatusUnauthorized, middleware.ErrBody{
			Err:     "invalid_token",
			Code:    "INVALID_TOKEN",
			Message: "The token is invalid or malformed.",
		})
		r.Headers.Set("WWW-Authenticate",
			`Bearer error="invalid_token", error_description="The token is invalid or malformed."`)
		return r
	}

	type TableTest struct {
		Comm           string
		IsError        bool
		IpReq          string
		DeviceIdReq    string
		AgentReq       string
		AuthHeader     string
		MethodMustCall []string
		MethodNoCall   []string
		fnSetUpMock    func()
		fnReadyAnswer  func() *ResponseResult
		fnCheckMethods func(methodMustCall, methodNoCall []string)
	}

	table := map[string]TableTest{
		"correct_request": {
			Comm:           "валидный access токен, сессия найдена, контекст и IP совпадают",
			IsError:        false,
			IpReq:          ip1,
			DeviceIdReq:    deviceId1,
			AgentReq:       agent1,
			AuthHeader:     "Bearer " + access1,
			MethodMustCall: []string{"GetSessionByFamilyId"},
			MethodNoCall: append(
				[]string{"DeleteByRefresh", "UpdateIpAdress"},
				noSessionMethods...,
			),
			fnSetUpMock: func() {
				resetMock(&userStoreBD.Mock, t)
				resetMock(&sessionStore.Mock, t)

				sessionStore.On("GetSessionByFamilyId", context.Background(), userId1, familyId1).
					Return(&session1, nil).
					Once()
			},
			fnReadyAnswer:  successAnswer,
			fnCheckMethods: checkMethods,
		},
		"lowercase_bearer_scheme": {
			Comm: `RFC 6750 §2.1: схема нечувствительна к регистру.
				Заголовок "bearer <token>" (нижний регистр) с валидным токеном — успех`,
			IsError:        false,
			IpReq:          ip1,
			DeviceIdReq:    deviceId1,
			AgentReq:       agent1,
			AuthHeader:     "bearer " + access1,
			MethodMustCall: []string{"GetSessionByFamilyId"},
			MethodNoCall: append(
				[]string{"DeleteByRefresh", "UpdateIpAdress"},
				noSessionMethods...,
			),
			fnSetUpMock: func() {
				resetMock(&userStoreBD.Mock, t)
				resetMock(&sessionStore.Mock, t)

				sessionStore.On("GetSessionByFamilyId", context.Background(), userId1, familyId1).
					Return(&session1, nil).
					Once()
			},
			fnReadyAnswer:  successAnswer,
			fnCheckMethods: checkMethods,
		},
		"ip_changed": {
			Comm: `все поля (Authorization, Device-Id, User-Agent) корректны и совпадают с сессией,
				но IP запроса отличается от session.Ip — ожидается 200 и UpdateIpAdress с новым IP`,
			IsError:        false,
			IpReq:          ip2,
			DeviceIdReq:    deviceId1,
			AgentReq:       agent1,
			AuthHeader:     "Bearer " + access1,
			MethodMustCall: []string{"GetSessionByFamilyId", "UpdateIpAdress"},
			MethodNoCall: append(
				[]string{"DeleteByRefresh"},
				noSessionMethods...,
			),
			fnSetUpMock: func() {
				resetMock(&userStoreBD.Mock, t)
				resetMock(&sessionStore.Mock, t)

				sessionStore.On("GetSessionByFamilyId", context.Background(), userId1, familyId1).
					Return(&session1, nil).
					Once()
				sessionStore.On("UpdateIpAdress", context.Background(), userId1, familyId1, "2.2.2.2").
					Return(nil).
					Once()
			},
			fnReadyAnswer:  successAnswer,
			fnCheckMethods: checkMethods,
		},
		"missing_authorization": {
			Comm:           "нет заголовка Authorization",
			IsError:        true,
			IpReq:          ip1,
			DeviceIdReq:    deviceId1,
			AgentReq:       agent1,
			AuthHeader:     "",
			MethodMustCall: []string{},
			MethodNoCall: append(
				[]string{"GetSessionByFamilyId", "DeleteByRefresh", "UpdateIpAdress"},
				noSessionMethods...,
			),
			fnSetUpMock: func() {
				resetMock(&userStoreBD.Mock, t)
				resetMock(&sessionStore.Mock, t)
			},
			fnReadyAnswer:  invalidTokenAnswer,
			fnCheckMethods: checkMethods,
		},
		"non_bearer_scheme": {
			Comm:           "схема не Bearer",
			IsError:        true,
			IpReq:          ip1,
			DeviceIdReq:    deviceId1,
			AgentReq:       agent1,
			AuthHeader:     "Basic dXNlcjpwYXNz",
			MethodMustCall: []string{},
			MethodNoCall: append(
				[]string{"GetSessionByFamilyId", "DeleteByRefresh", "UpdateIpAdress"},
				noSessionMethods...,
			),
			fnSetUpMock: func() {
				resetMock(&userStoreBD.Mock, t)
				resetMock(&sessionStore.Mock, t)
			},
			fnReadyAnswer:  invalidTokenAnswer,
			fnCheckMethods: checkMethods,
		},
		"malformed_authorization": {
			Comm:           "только Bearer без токена",
			IsError:        true,
			IpReq:          ip1,
			DeviceIdReq:    deviceId1,
			AgentReq:       agent1,
			AuthHeader:     "Bearer",
			MethodMustCall: []string{},
			MethodNoCall: append(
				[]string{"GetSessionByFamilyId", "DeleteByRefresh", "UpdateIpAdress"},
				noSessionMethods...,
			),
			fnSetUpMock: func() {
				resetMock(&userStoreBD.Mock, t)
				resetMock(&sessionStore.Mock, t)
			},
			fnReadyAnswer:  invalidTokenAnswer,
			fnCheckMethods: checkMethods,
		},
		"empty_token_after_bearer": {
			Comm:           "Bearer с пустым токеном",
			IsError:        true,
			IpReq:          ip1,
			DeviceIdReq:    deviceId1,
			AgentReq:       agent1,
			AuthHeader:     "Bearer ",
			MethodMustCall: []string{},
			MethodNoCall: append(
				[]string{"GetSessionByFamilyId", "DeleteByRefresh", "UpdateIpAdress"},
				noSessionMethods...,
			),
			fnSetUpMock: func() {
				resetMock(&userStoreBD.Mock, t)
				resetMock(&sessionStore.Mock, t)
			},
			fnReadyAnswer:  invalidTokenAnswer,
			fnCheckMethods: checkMethods,
		},
		"expired_token": {
			Comm:           "просроченный access токен → 401 (RFC 6750)",
			IsError:        true,
			IpReq:          ip1,
			DeviceIdReq:    deviceId1,
			AgentReq:       agent1,
			AuthHeader:     "Bearer " + expiredToken,
			MethodMustCall: []string{},
			MethodNoCall: append(
				[]string{"GetSessionByFamilyId", "DeleteByRefresh", "UpdateIpAdress"},
				noSessionMethods...,
			),
			fnSetUpMock: func() {
				resetMock(&userStoreBD.Mock, t)
				resetMock(&sessionStore.Mock, t)
			},
			fnReadyAnswer: func() *ResponseResult {
				r := errAnswer(http.StatusUnauthorized, middleware.ErrBody{
					Err:     "invalid_grant",
					Code:    "INVALID_GRANT",
					Message: "The access token has expired. Please re-authenticate.",
				})
				r.Headers.Set("WWW-Authenticate",
					`Bearer error="invalid_token", error_description="The access token expired"`)
				return r
			},
			fnCheckMethods: checkMethods,
		},
		"invalid_signature": {
			Comm:           "подпись сделана не тем ключом → 401",
			IsError:        true,
			IpReq:          ip1,
			DeviceIdReq:    deviceId1,
			AgentReq:       agent1,
			AuthHeader:     "Bearer " + badSignedToken,
			MethodMustCall: []string{},
			MethodNoCall: append(
				[]string{"GetSessionByFamilyId", "DeleteByRefresh", "UpdateIpAdress"},
				noSessionMethods...,
			),
			fnSetUpMock: func() {
				resetMock(&userStoreBD.Mock, t)
				resetMock(&sessionStore.Mock, t)
			},
			fnReadyAnswer:  invalidTokenAnswer,
			fnCheckMethods: checkMethods,
		},
		"invalid_format": {
			Comm:           "мусор вместо JWT (не парсится) → 401",
			IsError:        true,
			IpReq:          ip1,
			DeviceIdReq:    deviceId1,
			AgentReq:       agent1,
			AuthHeader:     "Bearer not-a-jwt-token",
			MethodMustCall: []string{},
			MethodNoCall: append(
				[]string{"GetSessionByFamilyId", "DeleteByRefresh", "UpdateIpAdress"},
				noSessionMethods...,
			),
			fnSetUpMock: func() {
				resetMock(&userStoreBD.Mock, t)
				resetMock(&sessionStore.Mock, t)
			},
			fnReadyAnswer:  invalidTokenAnswer,
			fnCheckMethods: checkMethods,
		},
		"future_date_token": {
			Comm:           "iat в будущем — сессия отзывается → 401",
			IsError:        true,
			IpReq:          ip1,
			DeviceIdReq:    deviceId1,
			AgentReq:       agent1,
			AuthHeader:     "Bearer " + futureToken,
			MethodMustCall: []string{"DeleteByRefresh"},
			MethodNoCall: append(
				[]string{"GetSessionByFamilyId", "UpdateIpAdress"},
				noSessionMethods...,
			),
			fnSetUpMock: func() {
				resetMock(&userStoreBD.Mock, t)
				resetMock(&sessionStore.Mock, t)

				sessionStore.On("DeleteByRefresh", context.Background(), userId1, familyId1).
					Return(nil).
					Once()
			},
			fnReadyAnswer: func() *ResponseResult {
				r := errAnswer(http.StatusUnauthorized, middleware.ErrBody{
					Err:     "invalid_token",
					Code:    "INVALID_TOKEN",
					Message: "Token reuse detected. Session has been revoked.",
				})
				r.Headers.Set("WWW-Authenticate",
					`Bearer error="invalid_token", error_description="Token reuse detected. Session has been revoked."`)
				return r
			},
			fnCheckMethods: checkMethods,
		},
		"session_not_found": {
			Comm:           "валидный токен, но сессия отсутствует → 401 (токен отозван)",
			IsError:        true,
			IpReq:          ip1,
			DeviceIdReq:    deviceId1,
			AgentReq:       agent1,
			AuthHeader:     "Bearer " + access1,
			MethodMustCall: []string{"GetSessionByFamilyId"},
			MethodNoCall: append(
				[]string{"DeleteByRefresh", "UpdateIpAdress"},
				noSessionMethods...,
			),
			fnSetUpMock: func() {
				resetMock(&userStoreBD.Mock, t)
				resetMock(&sessionStore.Mock, t)

				sessionStore.On("GetSessionByFamilyId", context.Background(), userId1, familyId1).
					Return(nil, custerr.ErrNotFound).
					Once()
			},
			fnReadyAnswer: func() *ResponseResult {
				r := errAnswer(http.StatusUnauthorized, middleware.ErrBody{
					Err:     "invalid_token",
					Code:    "INVALID_TOKEN",
					Message: "The session is invalid or has been revoked.",
				})
				r.Headers.Set("WWW-Authenticate",
					`Bearer error="invalid_token", error_description="The session is invalid or has been revoked."`)
				return r
			},
			fnCheckMethods: checkMethods,
		},
		"session_context_mismatch": {
			Comm:           "сессия найдена, но Device-Id/User-Agent не совпадают — отзыв → 401",
			IsError:        true,
			IpReq:          ip1,
			DeviceIdReq:    "different-device",
			AgentReq:       "different-agent",
			AuthHeader:     "Bearer " + access1,
			MethodMustCall: []string{"GetSessionByFamilyId", "DeleteByRefresh"},
			MethodNoCall: append(
				[]string{"UpdateIpAdress"},
				noSessionMethods...,
			),
			fnSetUpMock: func() {
				resetMock(&userStoreBD.Mock, t)
				resetMock(&sessionStore.Mock, t)

				sessionStore.On("GetSessionByFamilyId", context.Background(), userId1, familyId1).
					Return(&session1, nil).
					Once()
				sessionStore.On("DeleteByRefresh", context.Background(), userId1, familyId1).
					Return(nil).
					Once()
			},
			fnReadyAnswer: func() *ResponseResult {
				r := errAnswer(http.StatusUnauthorized, middleware.ErrBody{
					Err:     "invalid_grant",
					Code:    "SESSION_CONTEXT_MISMATCH",
					Message: "Session context mismatch. Please log in again.",
				})
				r.Headers.Set("WWW-Authenticate",
					`Bearer error="invalid_grant", error_description="Session context mismatch. Please log in again."`)
				return r
			},
			fnCheckMethods: checkMethods,
		},
		"db_error_on_get_session": {
			Comm:           "sessionStore.GetSessionByFamilyId вернул generic error → 500",
			IsError:        true,
			IpReq:          ip1,
			DeviceIdReq:    deviceId1,
			AgentReq:       agent1,
			AuthHeader:     "Bearer " + access1,
			MethodMustCall: []string{"GetSessionByFamilyId"},
			MethodNoCall: append(
				[]string{"DeleteByRefresh", "UpdateIpAdress"},
				noSessionMethods...,
			),
			fnSetUpMock: func() {
				resetMock(&userStoreBD.Mock, t)
				resetMock(&sessionStore.Mock, t)

				sessionStore.On("GetSessionByFamilyId", context.Background(), userId1, familyId1).
					Return(nil, errors.New("redis unavailable")).
					Once()
			},
			fnReadyAnswer: func() *ResponseResult {
				return errAnswer(http.StatusInternalServerError, middleware.ErrBody{
					Err:     "Internal Server Error",
					Code:    "AUTH_SERVICE_ERROR",
					Message: "Authentication service is temporarily unavailable. Please try again later.",
				})
			},
			fnCheckMethods: checkMethods,
		},
	}

	for name, val := range table {
		t.Run(name, func(t *testing.T) {
			val.fnSetUpMock()

			req := httptest.NewRequest(http.MethodGet, "/auth", nil)
			if val.AuthHeader != "" {
				req.Header.Set("Authorization", val.AuthHeader)
			}
			if val.DeviceIdReq != "" {
				req.Header.Set("Device-Id", val.DeviceIdReq)
			}
			if val.AgentReq != "" {
				req.Header.Set("User-Agent", val.AgentReq)
			}
			req.RemoteAddr = val.IpReq

			rec := httptest.NewRecorder()

			authHandler.Authentication(rec, req)

			mustResp := val.fnReadyAnswer()

			if mustResp.Code != rec.Code {
				t.Errorf("fail http status code dont equal want %v have %v", mustResp.Code, rec.Code)
			}

			if len(mustResp.Body) > 0 {
				if val.IsError {
					var mustErrBody middleware.ErrBody
					if err := json.Unmarshal(mustResp.Body, &mustErrBody); err != nil {
						t.Fatalf("unmarshal json must %v", err)
					}

					var outErrBody middleware.ErrBody
					if err := json.Unmarshal(rec.Body.Bytes(), &outErrBody); err != nil {
						t.Fatalf("unmarshal json out %v", err)
					}

					if mustErrBody.Err != outErrBody.Err ||
						mustErrBody.Code != outErrBody.Code ||
						mustErrBody.Message != outErrBody.Message {
						t.Errorf("fail http body dont equal want %+v have %+v", mustErrBody, outErrBody)
					}
				}
			}

			// Сверяем WWW-Authenticate, если эталон его задаёт (RFC 6750 §3).
			errHeaderAuth := mustResp.Headers.Get("WWW-Authenticate")
			if errHeaderAuth != "" {
				respHead := rec.Header().Get("WWW-Authenticate")
				if errHeaderAuth != respHead {
					t.Errorf("fail http auth header dont equal want %v have %v", errHeaderAuth, respHead)
				}
			}

			val.fnCheckMethods(val.MethodMustCall, val.MethodNoCall)
		})
	}
}

func resetMock(m *mock.Mock, t *testing.T) {
	m.ExpectedCalls = nil
	m.Calls = nil
	m.Test(t) // перепривязать к TestingT текущего подтеста
}
