package test

import (
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"testing"
	"time"
	"user_service/config"
	"user_service/domain"
	"user_service/initial/limiter"
	"user_service/initial/middleware"
	"user_service/pkg/repoerrors"
	"user_service/util"
	"uuid"

	"github.com/golang-jwt/jwt/v5"
)

func TestPanicRecoveryMiddleware(t *testing.T) {
	mockLimiter := limiter.GetMockShardLimiter()
	mockAudit := domain.GetMockAuditService()

	handlerF := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("Fatal error")
	})

	MyMiddleware := middleware.NewMiddleware(mockAudit, mockLimiter)

	handler := MyMiddleware.PanicRecovery(handlerF)

	t.Run("panic recovery test", func(t *testing.T) {

		reqTest := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, reqTest)

		if rec.Code != http.StatusInternalServerError {
			t.Errorf("fail test return code:%v\n", rec.Code)
		}

	})
}

func TestMakeTraceIdInMiddleware(t *testing.T) {

	mockLimiter := limiter.GetMockShardLimiter()
	mockAudit := domain.GetMockAuditService()

	handlerOurTraceId := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		ctx := r.Context()
		traceFromContext, ok := ctx.Value(domain.TraceKey).(string)
		if !ok {
			t.Errorf("fail trace key don't string")
		}

		if traceFromContext == "" {
			t.Errorf("fail trace from ctx equal empty string")
		}

	})

	UMiddleware := middleware.NewMiddleware(mockAudit, mockLimiter)

	handler := UMiddleware.TraceControl(handlerOurTraceId)

	t.Run("add our trace id in request", func(t *testing.T) {

		reqTest := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, reqTest)

	})

	traceInHeader := "54321"

	handlerTraceFromHeader := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		ctx := r.Context()
		traceFromContext, ok := ctx.Value(domain.TraceKey).(string)
		if !ok {
			t.Errorf("fail trace key don't string")
		}

		if traceFromContext != traceInHeader {
			t.Errorf("fail trace from ctx don't equal main traceId")
		}

	})

	handler = UMiddleware.TraceControl(handlerTraceFromHeader)

	t.Run("add trace id from header X-Request-Id", func(t *testing.T) {

		reqTest := httptest.NewRequest(http.MethodGet, "/", nil)
		reqTest.Header.Set("X-Request-Id", traceInHeader)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, reqTest)

	})
}

func TestLoggerMiddlewareTest(t *testing.T) {

	mockLimiter := limiter.GetMockShardLimiter()
	fieldsForCheckInt := []string{
		"Method",
		"Pattern",
		"ContentLenght",
		"Ip",
		"Referer",
		"Host",
		"UserAgent",
	}

	fieldsForCheckOut := []string{
		"ContentLenght",
		"StatusCode",
	}

	mock := domain.MockAuditService{
		TableResult: make(map[string][]domain.AuditEvent),
	}
	var au domain.AuditService
	au = &mock

	testTable := []struct {
		name      string
		method    string
		pattern   string
		handleF   http.HandlerFunc
		traceId   string
		countLog  int
		resultIn  map[string]string
		resultOut map[string]string
	}{
		{
			name:    "test success result",
			method:  http.MethodGet,
			pattern: "/user_id",
			handleF: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("test"))
			},
			traceId:  "12345",
			countLog: 2,
			resultIn: map[string]string{
				"Method":        http.MethodGet,
				"Pattern":       "/user_id",
				"ContentLenght": "0",
				"Ip":            "1.2.3.4:8080",
				"Referer":       "",
				"Host":          "5.5.5.5",
				"UserAgent":     "Chrome 1.0",
			},
			resultOut: map[string]string{
				"ContentLenght": strconv.Itoa(len([]byte("test"))),
				"StatusCode":    strconv.Itoa(http.StatusOK),
			},
		},
		{
			name:    "test bad result",
			method:  http.MethodPost,
			pattern: "/user_role",
			handleF: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusBadRequest)
			},
			traceId:  "54321",
			countLog: 2,
			resultIn: map[string]string{
				"Method":        http.MethodPost,
				"Pattern":       "/user_role",
				"ContentLenght": "0",
				"Ip":            "3.3.3.4:6060",
				"Referer":       "",
				"Host":          "5.5.5.5",
				"UserAgent":     "Safari 1.0",
			},
			resultOut: map[string]string{
				"ContentLenght": "0",
				"StatusCode":    strconv.Itoa(http.StatusBadRequest),
			},
		},
		{
			name:    "test panic result",
			method:  http.MethodDelete,
			pattern: "/",
			handleF: func(w http.ResponseWriter, r *http.Request) {
				panic("fatal error")
			},
			traceId:  "98765",
			countLog: 1,
			resultIn: map[string]string{
				"Method":        http.MethodDelete,
				"Pattern":       "/",
				"ContentLenght": "0",
				"Ip":            "6.6.6.6:6060",
				"Referer":       "",
				"Host":          "5.5.5.5",
				"UserAgent":     "Mozila 1.0",
			},
		},
	}

	UMiddleware := middleware.NewMiddleware(au, mockLimiter)
	requestIdHeader := "X-Request-Id"

	for _, tt := range testTable {

		handler := UMiddleware.Logger(tt.handleF)
		handler = UMiddleware.TraceControl(handler)
		handler = UMiddleware.PanicRecovery(handler)

		t.Run(tt.name, func(t *testing.T) {

			testReq := httptest.NewRequest(tt.method, tt.pattern, nil)
			testReq.Header.Set(requestIdHeader, tt.traceId)
			testReq.RemoteAddr = tt.resultIn["Ip"]
			testReq.Pattern = tt.resultIn["Pattern"]
			testReq.Host = tt.resultIn["Host"]
			testReq.Header.Set("Referer", tt.resultIn["Referer"])
			testReq.Header.Set("UserAgent", tt.resultIn["UserAgent"])

			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, testReq)
			logs := mock.TableResult[tt.traceId]

			if len(logs) != tt.countLog || len(logs) == 0 {
				t.Errorf("fail not all logs were recorded logs:%v countLogs: %v\n", len(logs), tt.countLog)
				return
			}

			for key, val := range logs[0].Metadata {
				if !slices.Contains(fieldsForCheckInt, key) {
					t.Errorf("fail log havn't field %v", key)
				} else {
					if val != tt.resultIn[key] {
						t.Errorf("fail log field %v dont equal", key)
					}
				}
			}

			if tt.countLog > 1 {

				for key, val := range logs[1].Metadata {
					if !slices.Contains(fieldsForCheckOut, key) {
						t.Errorf("fail log havn't field %v", key)
					} else {
						if val != tt.resultOut[key] {
							t.Errorf("fail log field %v dont equal", key)
						}
					}
				}

			}

		})

	}

}

func TestRateLimiterMiddleware(t *testing.T) {

	shardLimiter := limiter.NewShardLimiter(10, 1000, 10.0,
		5*time.Minute, 5*time.Minute)

	au := domain.GetMockAuditService()

	UMiddleware := middleware.NewMiddleware(au, shardLimiter)

	handlerF := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	})

	handler := UMiddleware.RateLimiterForIp(handlerF)
	handler = UMiddleware.Logger(handler)
	handler = UMiddleware.TraceControl(handler)
	handler = UMiddleware.PanicRecovery(handler)

	countQueryAttack := 500
	attackReq := httptest.NewRequest(http.MethodGet, "/", nil)
	attackReq.RemoteAddr = "1.1.1.1:8080"

	countQueryNormal := 5
	normalReq := httptest.NewRequest(http.MethodGet, "/", nil)
	normalReq.RemoteAddr = "2.2.2.2:8080"

	timer := time.NewTimer(12 * time.Second)
	tiker := time.NewTicker(time.Second)
	defer tiker.Stop()

	go func() {
		for {
			select {
			case <-timer.C:
				return
			case <-tiker.C:
				for range countQueryAttack {
					handler.ServeHTTP(httptest.NewRecorder(), attackReq)
				}
			}
		}
	}()

	go func() {
		for {
			select {
			case <-timer.C:
				return
			case <-tiker.C:
				for range countQueryNormal {
					rec := httptest.NewRecorder()
					handler.ServeHTTP(rec, normalReq)

					if rec.Code == http.StatusTooManyRequests {
						t.Error("fail normal don't get data")
					}
				}
			}
		}
	}()

	<-timer.C
	timer.Stop()

}

func TestGeneratePairTokenAuthMiddleWare(t *testing.T) {

	util.LoadEnvFile()

	auditMock := domain.GetMockEmptyAuditService()
	sessionMock := new(domain.SessionStoreMock)
	userStoreMock := new(domain.UserStoreMock)
	cm := config.NewConfigManager()
	cm.Init(context.TODO(), "")

	AuthMiddl := middleware.NewAuthMiddleware(auditMock, sessionMock, userStoreMock, cm)

	key1 := uuid.NewV7()
	key2 := uuid.NewV7()

	table := []struct {
		Name     string
		Comm     string
		IsError  bool
		UserId   uuid.UUID
		DeviceId string
		Agent    string
		Access   middleware.AccessToken
		Refresh  middleware.RefreshToken
	}{
		{
			Name:     "trying with empty fields",
			Comm:     "should return error",
			IsError:  true,
			UserId:   key1,
			DeviceId: "",
			Agent:    "",
			Access:   middleware.AccessToken{},
			Refresh:  middleware.RefreshToken{},
		},
		{
			Name:     "normal variant",
			Comm:     "after converting field should be equal",
			IsError:  false,
			UserId:   key2,
			DeviceId: "123456",
			Agent:    "chrome",
			Access: middleware.AccessToken{
				UserId:    key2,
				DeviceId:  "123456",
				Agent:     "chrome",
				TokenType: middleware.AccessTokenType,
				RegisteredClaims: jwt.RegisteredClaims{
					ID:        uuid.New().String(),
					Issuer:    "user-service",
					Subject:   key2.String(),
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
					IssuedAt:  jwt.NewNumericDate(time.Now()),
				},
			},
			Refresh: middleware.RefreshToken{
				UserId:    key2,
				TokenType: middleware.RefreshTokenType,
				RegisteredClaims: jwt.RegisteredClaims{
					ID:        uuid.New().String(),
					Issuer:    "user-service",
					Subject:   key2.String(),
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * 7 * time.Hour)),
					IssuedAt:  jwt.NewNumericDate(time.Now()),
				},
			},
		},
	}

	for _, val := range table {

		t.Run(val.Name, func(t *testing.T) {
			access, refresh, err := AuthMiddl.GeneratePairToken(val.UserId, val.DeviceId, val.Agent)
			if val.IsError {
				if err == nil {
					t.Errorf("fail generate pair token should return error")
				}
				return
			}

			if err != nil {
				t.Errorf("fail generate pair token error:%v", err)
			}

			token, err := jwt.ParseWithClaims(access,
				&middleware.AccessToken{},
				func(t *jwt.Token) (any, error) {
					return cm.Get().TokenConf.AccessBt, nil
				},
				jwt.WithValidMethods([]string{"HS256"}),
				jwt.WithIssuer(middleware.Issuer))

			if err != nil {
				t.Errorf("fail parse token error:%v", err)
			}

			claim, ok := token.Claims.(*middleware.AccessToken)
			if !ok || !token.Valid {
				t.Errorf("fail generate token access dont valid")
			}

			if claim.TokenType != val.Access.TokenType || claim.DeviceId != val.Access.DeviceId ||
				claim.Agent != val.Access.Agent || claim.UserId != val.Access.UserId {
				t.Errorf("fail generate token access field dont equal")
			}

			tokenRef, err := jwt.ParseWithClaims(refresh,
				&middleware.RefreshToken{},
				func(t *jwt.Token) (any, error) {
					return cm.Get().TokenConf.RefreshBt, nil
				},
				jwt.WithValidMethods([]string{"HS256"}),
				jwt.WithIssuer(middleware.Issuer))

			if err != nil {
				t.Errorf("fail parse token error:%v", err)
			}

			claimRef, ok := tokenRef.Claims.(*middleware.RefreshToken)
			if !ok || !tokenRef.Valid {
				t.Errorf("fail generate token refresh dont valid")
			}

			if claimRef.TokenType != val.Refresh.TokenType || claimRef.UserId != val.Refresh.UserId {
				t.Errorf("fail generate token refresh field dont equal")
			}

		})

	}

}

func TestValidAccessTokenAuthMiddleWare(t *testing.T) {

	util.LoadEnvFile()

	auditMock := domain.GetMockEmptyAuditService()
	sessionMock := new(domain.SessionStoreMock)
	userStoreMock := new(domain.UserStoreMock)
	cm := config.NewConfigManager()
	cm.Init(context.TODO(), "")

	AuthMiddl := middleware.NewAuthMiddleware(auditMock, sessionMock, userStoreMock, cm)

	invalidKey, err := GenerateSecret(32)
	if err != nil {
		t.Errorf("failed generate invalid key error:%v", err)
	}

	table := []struct {
		Name         string
		Comm         string
		IsError      bool
		CustomGen    bool
		UserId       uuid.UUID
		DeviceId     string
		Agent        string
		IssueAt      time.Time
		Exp          time.Time
		SignatureAlg string
		Key          []byte
		Err          *repoerrors.RepoError
	}{
		{
			Name:         "correct_token",
			Comm:         "should return nil",
			IsError:      false,
			CustomGen:    false,
			UserId:       uuid.NewV7(),
			DeviceId:     "12345",
			Agent:        "chrome",
			IssueAt:      time.Now(),
			Exp:          time.Now().Add(15 * time.Minute),
			SignatureAlg: "HS256",
			Key:          cm.Get().TokenConf.AccessBt,
			Err:          nil,
		},
		{
			Name:         "expired_token",
			Comm:         "should return error expired",
			IsError:      true,
			CustomGen:    false,
			UserId:       uuid.NewV7(),
			DeviceId:     "12345",
			Agent:        "chrome",
			IssueAt:      time.Now().Add(-20 * time.Minute),
			Exp:          time.Now().Add(-5 * time.Minute),
			SignatureAlg: "HS256",
			Key:          cm.Get().TokenConf.AccessBt,
			Err:          middleware.ErrExpToken,
		},
		{
			Name:         "no_correct_token",
			Comm:         "should return error dont correct token",
			IsError:      true,
			CustomGen:    true,
			UserId:       uuid.NewV7(),
			DeviceId:     "12345",
			Agent:        "",
			IssueAt:      time.Now(),
			Exp:          time.Now().Add(15 * time.Minute),
			SignatureAlg: "HS256",
			Key:          cm.Get().TokenConf.AccessBt,
			Err:          middleware.ErrInvalidToken,
		},
		{
			Name:         "token_issue_at_future_date",
			Comm:         "should return error issue future date",
			IsError:      true,
			CustomGen:    false,
			UserId:       uuid.NewV7(),
			DeviceId:     "12345",
			Agent:        "chrome",
			IssueAt:      time.Now().Add(15 * time.Minute),
			Exp:          time.Now().Add(30 * time.Minute),
			SignatureAlg: "HS256",
			Key:          cm.Get().TokenConf.AccessBt,
			Err:          middleware.ErrFutureDateToken,
		},
		{
			Name:         "invalid_token_signature",
			Comm:         "should return error invalid_token_signature",
			IsError:      true,
			CustomGen:    false,
			UserId:       uuid.NewV7(),
			DeviceId:     "12345",
			Agent:        "chrome",
			IssueAt:      time.Now(),
			Exp:          time.Now().Add(15 * time.Minute),
			SignatureAlg: "HS256",
			Key:          invalidKey,
			Err:          middleware.ErrInvalidSignToken,
		},
		{
			Name:         "empty_token",
			Comm:         "should return error empty field",
			IsError:      true,
			CustomGen:    false,
			UserId:       uuid.Nil(),
			DeviceId:     "",
			Agent:        "",
			IssueAt:      time.Now(),
			Exp:          time.Now().Add(15 * time.Minute),
			SignatureAlg: "",
			Key:          invalidKey,
			Err:          middleware.ErrFieldEmpty,
		},
	}

	for _, val := range table {

		t.Run(val.Name, func(t *testing.T) {

			var accessToken string
			if !val.CustomGen {
				accessStr := middleware.NewAccessToken(val.UserId, val.DeviceId, val.Agent)
				accessStr.RegisteredClaims.ExpiresAt = jwt.NewNumericDate(val.Exp)
				accessStr.RegisteredClaims.IssuedAt = jwt.NewNumericDate(val.IssueAt)

				token := jwt.NewWithClaims(jwt.SigningMethodHS256, accessStr)
				accessToken, err = token.SignedString(val.Key)
				if err != nil {
					t.Errorf("fail error signing token err:%v", err)
					return
				}
			} else {

				data := make(map[string]any)
				data["user_id"] = val.UserId.String()
				data["device_id"] = val.DeviceId
				data["agent"] = val.Agent

				dataJwt := jwt.MapClaims(data)

				if _, ok := dataJwt["exp"]; !ok {
					dataJwt["exp"] = jwt.NewNumericDate(time.Now().Add(15 * time.Minute))
				}

				if _, ok := dataJwt["iat"]; !ok {
					dataJwt["iat"] = jwt.NewNumericDate(time.Now())
				}

				token := jwt.NewWithClaims(jwt.SigningMethodHS256, dataJwt)

				accessToken, err = token.SignedString(val.Key)
				if err != nil {
					t.Errorf("fail error signing token err:%v", err)
					return
				}
			}

			if val.Name == "empty_token" {
				accessToken = ""
			}

			err = AuthMiddl.ValidAccessToken(accessToken)
			if val.IsError {
				if !val.Err.Is(err) {
					t.Errorf("fail error dont equal should err:%v returned err:%v", val.Err, err)
				}
			} else {
				if err != nil {
					t.Errorf("fail shouldnt return error, err:%v", err)
				}
			}

		})
	}

}

func TestValidRefreshTokenAuthMiddleWare(t *testing.T) {

	util.LoadEnvFile()

	auditMock := domain.GetMockEmptyAuditService()
	sessionMock := new(domain.SessionStoreMock)
	userStoreMock := new(domain.UserStoreMock)
	cm := config.NewConfigManager()
	cm.Init(context.TODO(), "")

	AuthMiddl := middleware.NewAuthMiddleware(auditMock, sessionMock, userStoreMock, cm)

	invalidKey, err := GenerateSecret(32)
	if err != nil {
		t.Errorf("failed generate invalid key error:%v", err)
	}

	table := []struct {
		Name         string
		Comm         string
		IsError      bool
		CustomGen    bool
		UserId       uuid.UUID
		DeviceId     string
		Agent        string
		IssueAt      time.Time
		Exp          time.Time
		SignatureAlg string
		Key          []byte
		Err          *repoerrors.RepoError
	}{
		{
			Name:         "correct_token",
			Comm:         "should return nil",
			IsError:      false,
			CustomGen:    false,
			UserId:       uuid.NewV7(),
			DeviceId:     "12345",
			Agent:        "chrome",
			IssueAt:      time.Now(),
			Exp:          time.Now().Add(15 * time.Minute),
			SignatureAlg: "HS256",
			Key:          cm.Get().TokenConf.RefreshBt,
			Err:          nil,
		},
		{
			Name:         "expired_token",
			Comm:         "should return error expired",
			IsError:      true,
			CustomGen:    false,
			UserId:       uuid.NewV7(),
			DeviceId:     "12345",
			Agent:        "chrome",
			IssueAt:      time.Now().Add(-20 * time.Minute),
			Exp:          time.Now().Add(-5 * time.Minute),
			SignatureAlg: "HS256",
			Key:          cm.Get().TokenConf.RefreshBt,
			Err:          middleware.ErrExpToken,
		},
		{
			Name:         "no_correct_token",
			Comm:         "should return error dont correct token",
			IsError:      true,
			CustomGen:    true,
			UserId:       uuid.Nil(),
			DeviceId:     "",
			Agent:        "",
			IssueAt:      time.Now(),
			Exp:          time.Now().Add(15 * time.Minute),
			SignatureAlg: "HS256",
			Key:          cm.Get().TokenConf.RefreshBt,
			Err:          middleware.ErrInvalidToken,
		},
		{
			Name:         "token_issue_at_future_date",
			Comm:         "should return error issue future date",
			IsError:      true,
			CustomGen:    false,
			UserId:       uuid.NewV7(),
			DeviceId:     "12345",
			Agent:        "chrome",
			IssueAt:      time.Now().Add(15 * time.Minute),
			Exp:          time.Now().Add(30 * time.Minute),
			SignatureAlg: "HS256",
			Key:          cm.Get().TokenConf.RefreshBt,
			Err:          middleware.ErrFutureDateToken,
		},
		{
			Name:         "invalid_token_signature",
			Comm:         "should return error invalid_token_signature",
			IsError:      true,
			CustomGen:    false,
			UserId:       uuid.NewV7(),
			DeviceId:     "12345",
			Agent:        "chrome",
			IssueAt:      time.Now(),
			Exp:          time.Now().Add(15 * time.Minute),
			SignatureAlg: "HS256",
			Key:          invalidKey,
			Err:          middleware.ErrInvalidSignToken,
		},
		{
			Name:         "empty_token",
			Comm:         "should return error empty field",
			IsError:      true,
			CustomGen:    false,
			UserId:       uuid.Nil(),
			DeviceId:     "",
			Agent:        "",
			IssueAt:      time.Now(),
			Exp:          time.Now().Add(15 * time.Minute),
			SignatureAlg: "",
			Key:          invalidKey,
			Err:          middleware.ErrFieldEmpty,
		},
	}

	for _, val := range table {

		t.Run(val.Name, func(t *testing.T) {

			var refreshToken string
			if !val.CustomGen {
				refreshStr := middleware.NewRefreshToken(val.UserId)
				refreshStr.RegisteredClaims.ExpiresAt = jwt.NewNumericDate(val.Exp)
				refreshStr.RegisteredClaims.IssuedAt = jwt.NewNumericDate(val.IssueAt)

				token := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshStr)
				refreshToken, err = token.SignedString(val.Key)
				if err != nil {
					t.Errorf("fail error signing token err:%v", err)
					return
				}
			} else {

				data := make(map[string]any)
				data["user_id"] = val.UserId.String()
				data["device_id"] = val.DeviceId
				data["agent"] = val.Agent

				dataJwt := jwt.MapClaims(data)

				if _, ok := dataJwt["exp"]; !ok {
					dataJwt["exp"] = jwt.NewNumericDate(time.Now().Add(15 * time.Minute))
				}

				if _, ok := dataJwt["iat"]; !ok {
					dataJwt["iat"] = jwt.NewNumericDate(time.Now())
				}

				token := jwt.NewWithClaims(jwt.SigningMethodHS256, dataJwt)

				refreshToken, err = token.SignedString(val.Key)
				if err != nil {
					t.Errorf("fail error signing token err:%v", err)
					return
				}
			}

			if val.Name == "empty_token" {
				refreshToken = ""
			}

			err = AuthMiddl.ValidRefreshToken(refreshToken)
			if val.IsError {
				if !val.Err.Is(err) {
					t.Errorf("fail error dont equal should err:%v returned err:%v", val.Err, err)
				}
			} else {
				if err != nil {
					t.Errorf("fail shouldnt return error, err:%v", err)
				}
			}

		})
	}

}

func GenerateSecret(nBytes int) ([]byte, error) {
	b := make([]byte, nBytes) // 32 байта = 256 бит
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil // для хранения в env
}

// gen ai
func generateRandomIPWithPort() string {

	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	ip := fmt.Sprintf("%d.%d.%d.%d", r.Intn(256), r.Intn(256), r.Intn(256), r.Intn(256))
	port := r.Intn(65535) + 1

	return fmt.Sprintf("%s:%d", ip, port)
}
