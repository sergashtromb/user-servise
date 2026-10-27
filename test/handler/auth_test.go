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

type ResponseResult struct {
	Code    int         `json:"code"`
	Headers http.Header `json:"headers"`
	Body    []byte      `json:"body"` // Изменили тип на []byte
}

func TestUpdateRefreshToken(t *testing.T) {

	sessionStore := new(domain.SessionStoreMock)
	cm := config.NewConfigManager()
	cm.Init(context.TODO(), "")

	id1 := uuid.NewV7()

	resresh1, _, err := middleware.GeneratePairToken(id1, "12345", "chrome win 10", cm)
	if err != nil {
		t.Fatalf("fail generate first pair tokens err:%v", err)
	}
	resresh2, _, err := middleware.GeneratePairToken(id1, "58945", "chrome android", cm)
	if err != nil {
		t.Fatalf("fail generate first pair tokens err:%v", err)
	}

	refreshs := []string{resresh1, resresh2}

	agent1 := "chrome win 10"
	agent2 := "chrome android"
	deviceId1 := "12345"
	deviceId2 := "58945"

	trueSessions := []domain.Session{
		{
			UserId:    id1,
			DeviceId:  deviceId1,
			Ip:        "1.1.1.1",
			Agent:     agent1,
			CreatedAt: time.Now().Add(-48 * time.Hour),
		},
		{
			UserId:    id1,
			DeviceId:  deviceId2,
			Ip:        "3.3.3.3",
			Agent:     agent2,
			CreatedAt: time.Now().Add(-24 * time.Hour),
		},
	}

	table := []struct {
		Name               string
		Comm               string
		IsError            bool
		IpReq              string
		DeviceReq          string
		AgentReq           string
		RefreshForSessions []string
		Sessions           []domain.Session
		RefreshAgent       string
		RefreshDeviceId    string
		RefreshIssAt       time.Time
		RefreshExp         time.Time
		UserId             uuid.UUID
		MethodMustCall     []string
		MethodNoCall       []string
		fnSetUpMock        func()
		fnGetResultAnswer  func() *ResponseResult
	}{
		{
			Name:               "correct_req",
			Comm:               "should return new access and refresh token, and make rotation token un session store",
			IsError:            false,
			IpReq:              "1.1.1.1:1234",
			DeviceReq:          deviceId1,
			AgentReq:           agent1,
			RefreshForSessions: refreshs,
			Sessions:           trueSessions,
			RefreshAgent:       agent1,
			RefreshDeviceId:    deviceId1,
			RefreshIssAt:       time.Now(),
			RefreshExp: time.Now().Add(
				time.Duration(time.Duration(cm.Get().TokenConf.RefreshLifeTime) * time.Minute)),
			UserId:         id1,
			MethodMustCall: []string{"GetSessionByFamilyId", "GetFromGracePeriodic", "CreateGracePeriodic"},
			MethodNoCall:   []string{"Registration", "GetAllSession", "DeleteAll", "DeleteByRefresh"},
			fnSetUpMock: func() {
				resetMock(&sessionStore.Mock, t)
				sessionStore.On("GetSessionByFamilyId", context.Background(), id1, resresh1).
					Return(&trueSessions[0], nil).
					Once()
				sessionStore.On("CreateGracePeriodic", context.Background(), id1, id1, domain.GracePeriodic{
					Version: trueSessions[0].Version,
				}).
					Return(nil).
					Once()
			},
			fnGetResultAnswer: func() *ResponseResult {

				// access and refresh check separate from body
				sec := cm.Get().TokenConf.AccessLifeTime * 60
				bodyJson := fmt.Sprintf(`
				{
					"access_token": "access", 
					"token_type": "Bearer",
					"expires_in": "%v",
					"refresh_token": "refresh"
				}
				`, sec)

				resp := httptest.NewRecorder()
				resp.Header().Set("Content-Type", "application/json;charset=UTF-8")
				resp.Header().Set("Cache-Control", "no-store")
				resp.Header().Set("Pragma", "no-cache")
				resp.WriteHeader(http.StatusOK)
				resp.Write([]byte(bodyJson))

				return &ResponseResult{
					Code:    resp.Code,
					Headers: resp.Header(),
					Body:    resp.Body.Bytes(), // Используем .Bytes() вместо .String()
				}
			},
		},
		{
			Name:               "empty_token",
			Comm:               "should return error 400 bad request",
			IsError:            true,
			IpReq:              "1.1.1.1:1234",
			DeviceReq:          deviceId1,
			AgentReq:           agent1,
			RefreshForSessions: refreshs,
			Sessions:           trueSessions,
			RefreshAgent:       agent1,
			RefreshDeviceId:    deviceId1,
			RefreshIssAt:       time.Now(),
			RefreshExp:         time.Now(),
			UserId:             uuid.Nil(),
			MethodMustCall:     []string{},
			MethodNoCall: []string{"Registration", "GetAllSession", "DeleteAll", "DeleteByRefresh", "GetSessionByRefresh",
				"CreateGracePeriodic", "GetFromGracePeriodic", "UpdateIpAdress"},
			fnSetUpMock: func() {
				resetMock(&sessionStore.Mock, t)
			},
			fnGetResultAnswer: func() *ResponseResult {

				bodyJson := `
				{
					"error": "invalid_request",
					"message": "The required 'refresh_token' parameter is missing or empty.",
					"code": "INVALID_REQUEST"
				}`

				resp := httptest.NewRecorder()
				resp.Header().Set("Content-Type", "application/json;charset=UTF-8")
				resp.WriteHeader(http.StatusBadRequest)
				resp.Write([]byte(bodyJson))

				return &ResponseResult{
					Code:    resp.Code,
					Headers: resp.Header(),
					Body:    resp.Body.Bytes(), // Используем .Bytes() вместо .String()
				}
			},
		},
		{
			Name:               "param_req_dont_equal_param_session",
			Comm:               "should return error 400",
			IsError:            true,
			IpReq:              "5.5.5.5:1234",
			DeviceReq:          deviceId1,
			AgentReq:           agent1,
			RefreshForSessions: refreshs,
			Sessions:           trueSessions,
			RefreshAgent:       agent1,
			RefreshDeviceId:    deviceId1,
			RefreshIssAt:       time.Now(),
			RefreshExp:         time.Now(),
			UserId:             uuid.Nil(),
			MethodMustCall:     []string{"GetSessionByFamilyId", "DeleteByRefresh"},
			MethodNoCall: []string{"Registration", "GetAllSession", "DeleteAll", "CreateGracePeriodic",
				"GetFromGracePeriodic", "UpdateIpAdress"},
			fnSetUpMock: func() {
				resetMock(&sessionStore.Mock, t)
				sessionStore.On("GetSessionByRefresh", context.Background(), id1, resresh1).
					Return(&trueSessions[0], nil).
					Once()
				sessionStore.On("GetSessionByFamilyId", context.Background(), id1, id1).
					Return(&trueSessions[0], nil).
					Once()
				sessionStore.On("DeleteByRefresh", context.Background(), id1, resresh1).
					Return(nil).
					Once()
			},
			fnGetResultAnswer: func() *ResponseResult {

				bodyJson := `
				{
					"error": "invalid_grant",
					"message": "The refresh token is bound to a different device context.",
					"code": "INVALID_GRANT"
				}`

				resp := httptest.NewRecorder()
				resp.Header().Set("Content-Type", "application/json;charset=UTF-8")
				resp.WriteHeader(http.StatusBadRequest)
				resp.Write([]byte(bodyJson))

				return &ResponseResult{
					Code:    resp.Code,
					Headers: resp.Header(),
					Body:    resp.Body.Bytes(), // Используем .Bytes() вместо .String()
				}
			},
		},
		{
			Name:               "get_access_and_refresh_from_grace_periodic",
			Comm:               "should return correct answer from grace periodic",
			IsError:            false,
			IpReq:              "1.1.1.1:1234",
			DeviceReq:          deviceId1,
			AgentReq:           agent1,
			RefreshForSessions: refreshs,
			Sessions:           trueSessions,
			UserId:             id1,
			MethodMustCall:     []string{"GetSessionByFamilyId", "CreateGracePeriodic", "GetFromGracePeriodic"},
			MethodNoCall: []string{"Registration", "GetAllSession", "DeleteAll", "DeleteByRefresh",
				"UpdateRefreshToken", "UpdateIpAdress"},
			fnSetUpMock: func() {
				resetMock(&sessionStore.Mock, t)
				sessionStore.On("GetSessionByFamilyId", context.Background(), id1, resresh1).
					Return(&trueSessions[0], nil).
					Once()
				sessionStore.On("GetFromGracePeriodic", context.Background(), id1, id1, trueSessions[0].Version).
					Return(resresh1, resresh1, nil).
					Once()
			},
			fnGetResultAnswer: func() *ResponseResult {
				sec := cm.Get().TokenConf.AccessLifeTime * 60
				bodyJson := fmt.Sprintf(`
				{
					"access_token": "%s",
					"token_type": "Bearer",
					"expires_in": "%v",
					"refresh_token": "%s"
				}
				`, resresh1, sec, resresh1)

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
		},
		{
			Name:               "get_access_and_refresh_from_no_exists_grace_periodic",
			Comm:               "should return 400 bad request, and delete session by refresh",
			IsError:            true,
			IpReq:              "1.1.1.1:1234",
			DeviceReq:          deviceId1,
			AgentReq:           agent1,
			RefreshForSessions: refreshs,
			Sessions:           trueSessions,
			UserId:             id1,
			MethodMustCall:     []string{"GetSessionByRefresh", "GetFromGracePeriodic", "DeleteByRefresh"},
			MethodNoCall: []string{"Registration", "GetAllSession", "DeleteAll",
				"UpdateRefreshToken", "CreateGracePeriodic", "UpdateIpAdress"},
			fnSetUpMock: func() {
				resetMock(&sessionStore.Mock, t)
				sessionStore.On("GetSessionByRefresh", context.Background(), id1, resresh1).
					Return(&trueSessions[0], nil).
					Once()
				sessionStore.On("GetFromGracePeriodic", context.Background(), id1, id1, trueSessions[0].Version).
					Return("", "", custerr.ErrGracePeriodicNoExists).
					Once()
				sessionStore.On("DeleteByRefresh", context.Background(), id1, resresh1).
					Return(nil).
					Once()
			},
			fnGetResultAnswer: func() *ResponseResult {
				bodyJson := `{
					"error": "invalid_grant",
					"message": "The refresh token is invalid or session not found.",
					"code": "INVALID_GRANT"
				}`

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
		{
			Name:               "get_access_and_refresh_with_old_version",
			Comm:               "should return 400 bad request, and delete session by refresh",
			IsError:            true,
			IpReq:              "1.1.1.1:1234",
			DeviceReq:          deviceId1,
			AgentReq:           agent1,
			RefreshForSessions: refreshs,
			Sessions:           trueSessions,
			UserId:             id1,
			MethodMustCall:     []string{"GetSessionByRefresh", "GetFromGracePeriodic", "DeleteByRefresh"},
			MethodNoCall: []string{"Registration", "GetAllSession", "DeleteAll",
				"UpdateRefreshToken", "CreateGracePeriodic", "UpdateIpAdress"},
			fnSetUpMock: func() {
				resetMock(&sessionStore.Mock, t)
				sessionStore.On("GetSessionByRefresh", context.Background(), id1, resresh1).
					Return(&trueSessions[0], nil).
					Once()
				sessionStore.On("GetFromGracePeriodic", context.Background(), id1, id1, "wrong_version").
					Return("", "", custerr.ErrGracePeriodicVersionMiss).
					Once()
				sessionStore.On("DeleteByRefresh", context.Background(), id1, resresh1).
					Return(nil).
					Once()
			},
			fnGetResultAnswer: func() *ResponseResult {
				bodyJson := `{
					"error": "invalid_grant",
					"message": "The refresh token is invalid or session not found.",
					"code": "INVALID_GRANT"
				}`

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

	// Run test cases
	for _, tt := range table {
		t.Run(tt.Name, func(t *testing.T) {
			tt.fnSetUpMock()

			// Verify expected methods were set up
			for _, must := range tt.MethodMustCall {
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
			for _, noCall := range tt.MethodNoCall {
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
		})
	}

}

func resetMock(m *mock.Mock, t *testing.T) {
	m.ExpectedCalls = nil
	m.Calls = nil
	m.Test(t) // перепривязать к TestingT текущего подтеста
}
