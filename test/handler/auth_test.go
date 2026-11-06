package test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
	"user_service/config"
	"user_service/domain"
	"user_service/infrastructure/postgres"
	"user_service/infrastructure/reporedis/custerr"
	"user_service/infrastructure/tokens"
	"user_service/initial/handler"
	"user_service/initial/middleware"
	"uuid"

	"github.com/golang-jwt/jwt/v5"
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
// Что это и что делает? - это handler который принимает запросы на регистрацию нового пользователя в системе
// если все корректно то попытается зарегать пользователя либо вернет ошибку уникальности что пользователь уже существует
//
//	Tests:
//			correct_request - корректный тест зарегестрирует пользователя в базе данных, создат сейссию в кеш
//				так же положит пользователя в кеш userStore
//			dublicate - ошибочный тест когда username уже существует, вернуть ошибку
//			empty_field - ошибочный тест с пустыми полями, вернуть ошибку
func TestRegistrationUser(t *testing.T) {

	cm := config.NewConfigManager()
	cm.Init(context.TODO(), "")

	userStoreCache := domain.NewUserStoreMock(t)
	userStoreBD := domain.NewUserStoreMock(t)
	sessionStore := domain.NewSessionStoreMock(t)
	tu := tokens.NewTokenUtil(cm)

	ip1 := "1.1.1.1:5432"
	agent1 := "chrome widows 10"
	deviceId := "12345"

	username1 := "username"
	pass1 := "54321"

	authHandler := handler.NewAuthHandler(cm, domain.GetMockAuditService(), sessionStore, tu, userStoreBD)

	table := map[string]struct {
		Comm          string
		IsError       bool
		IpReq         string
		AgentReq      string
		DeviceIdReq   string
		UserName      string
		Email         string
		Phone         string
		Password      string
		fnSetUpMock   func()
		fnReadyAnswer func() *ResponseResult
	}{
		"correct_request": {
			Comm: `корректный тест зарегестрирует пользователя в базе данных, создат сейссию в кеш
					так же положит пользователя в кеш userStore`,
			IsError:     false,
			IpReq:       ip1,
			AgentReq:    agent1,
			DeviceIdReq: deviceId,
			UserName:    username1,
			Password:    pass1,
			Email:       "",
			Phone:       "",
			fnSetUpMock: func() {
				resetMock(&userStoreCache.Mock, t)
				resetMock(&userStoreBD.Mock, t)
				resetMock(&sessionStore.Mock, t)

				userStoreBD.On("Create", context.Background(), mock.Anything).
					Return(uuid.NewV7(), nil).
					Once()

				sessionStore.On("Registration", context.Background(), mock.Anything, mock.Anything).
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
				resp.WriteHeader(http.StatusCreated)
				resp.Write([]byte(bodyJson))

				return &ResponseResult{
					Code:    resp.Code,
					Headers: resp.Header(),
					Body:    resp.Body.Bytes(),
				}
			},
		},
		"dublicate": {
			Comm:        `ошибочный тест когда username уже существует, вернуть ошибку`,
			IsError:     true,
			IpReq:       ip1,
			AgentReq:    agent1,
			DeviceIdReq: deviceId,
			UserName:    username1,
			Password:    pass1,
			Email:       "",
			Phone:       "",
			fnSetUpMock: func() {
				resetMock(&userStoreCache.Mock, t)
				resetMock(&userStoreBD.Mock, t)
				resetMock(&sessionStore.Mock, t)

				userStoreBD.On("Create", context.Background(), mock.Anything).
					Return(uuid.Nil(), postgres.ErrUserAlreadyExists).
					Once()

			},
			fnReadyAnswer: func() *ResponseResult {

				bodyJson := `
				{
					"error": "conflict",
					"code": "REGISTRATION_FAILED",
					"message": "Registration failed. Please check your details or try logging in."
				}
				`
				resp := httptest.NewRecorder()
				resp.Header().Set("Content-Type", "application/json;charset=UTF-8")
				resp.WriteHeader(http.StatusConflict)
				resp.Write([]byte(bodyJson))

				return &ResponseResult{
					Code:    resp.Code,
					Headers: resp.Header(),
					Body:    resp.Body.Bytes(),
				}
			},
		},
		"empty_field": {
			Comm:        `ошибочный тест когда прислали пустые username и password`,
			IsError:     true,
			IpReq:       ip1,
			AgentReq:    agent1,
			DeviceIdReq: deviceId,
			UserName:    "",
			Password:    "",
			Email:       "",
			Phone:       "",
			fnSetUpMock: func() {
				resetMock(&userStoreCache.Mock, t)
				resetMock(&userStoreBD.Mock, t)
				resetMock(&sessionStore.Mock, t)
			},
			fnReadyAnswer: func() *ResponseResult {

				bodyJson := `
				{
					"error": "invalid_request",
					"code": "VALIDATION_ERROR",
					"message": "Username and password are required."
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

	for name, val := range table {

		t.Run(name, func(t *testing.T) {

			val.fnSetUpMock()

			body := fmt.Sprintf(`
			{
				"username": "%s",
				"password": "%s"
			}`, val.UserName, val.Password)

			req := httptest.NewRequest(http.MethodPost, "/reg", bytes.NewBufferString(body))
			req.Header.Add("Content-Type", "application/json")
			req.Header.Add("Accept", "application/json")
			req.Header.Add("Device-Id", val.DeviceIdReq)
			req.Header.Add("User-Agent", val.AgentReq)
			req.RemoteAddr = val.IpReq

			rec := httptest.NewRecorder()

			authHandler.RegistrationUser(rec, req)

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
		})

	}

}

func resetMock(m *mock.Mock, t *testing.T) {
	m.ExpectedCalls = nil
	m.Calls = nil
	m.Test(t) // перепривязать к TestingT текущего подтеста
}
