package test

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"testing"
	"time"
	"user_service/domain"
	"user_service/initial/middleware"
)

func TestPanicRecoveryMiddleware(t *testing.T) {

	mockAudit := domain.GetMockAuditService()

	handlerF := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("Fatal error")
	})

	MyMiddleware := middleware.NewMiddleware(mockAudit)

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

	UMiddleware := middleware.NewMiddleware(mockAudit)

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

	UMiddleware := middleware.NewMiddleware(au)
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

	au := domain.GetMockAuditService()

	UMiddleware := middleware.NewMiddleware(au)

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
