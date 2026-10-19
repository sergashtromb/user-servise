package middleware

import (
	"context"
	"encoding/hex"
	"net/http"
	"strconv"
	"user_service/domain"
	"user_service/initial/limiter"
	"uuid"
)

type ShellResponseWrite struct {
	http.ResponseWriter
	status   int
	bodySize int
}

func (sr *ShellResponseWrite) WriteHeader(statusCode int) {
	sr.status = statusCode
	sr.ResponseWriter.WriteHeader(statusCode)
}

func (sr *ShellResponseWrite) Write(b []byte) (int, error) {
	sr.bodySize = len(b)
	return sr.ResponseWriter.Write(b)
}

func (sr *ShellResponseWrite) Header() http.Header {
	return sr.ResponseWriter.Header()
}

type UtilMiddleware struct {
	audit   domain.AuditService
	limiter limiter.ShardRateLimiter
}

func NewMiddleware(audit domain.AuditService, sl limiter.ShardRateLimiter) *UtilMiddleware {
	return &UtilMiddleware{
		audit:   audit,
		limiter: sl,
	}
}

func (md *UtilMiddleware) PanicRecovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		defer func() {
			if err := recover(); err != nil {
				// FIXME add audit write
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)

			}
		}()

		next.ServeHTTP(w, r)
	})
}

func (md *UtilMiddleware) TraceControl(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		reqid := r.Header.Get("X-Request-Id")
		var traceId string

		if reqid == "" {
			id := uuid.NewV7()
			traceId = hex.EncodeToString(id[:])
		} else {
			traceId = reqid
		}

		ctx := context.WithValue(r.Context(), domain.TraceKey, traceId)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (md *UtilMiddleware) Logger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		data := make(map[string]string)
		data["Method"] = r.Method
		data["Host"] = r.Host
		data["Ip"] = r.RemoteAddr
		data["Pattern"] = r.Pattern
		data["UserAgent"] = r.UserAgent()
		data["ContentLenght"] = strconv.FormatInt(r.ContentLength, 10)
		data["ContentType"] = r.Header.Get("Content-Type")
		data["Referer"] = r.Header.Get("Referer")

		ctx := r.Context()
		traceId, ok := ctx.Value(domain.TraceKey).(string)
		if !ok {
			traceId = ""
		}

		event := domain.NewAuditEvent(domain.EventInboxRequestStart, domain.EventPlaceMiddleware,
			true, nil, "", traceId)
		md.audit.Log(r.Context(), event)

		shellWriter := ShellResponseWrite{
			ResponseWriter: w,
			status:         0,
			bodySize:       0,
		}

		w = &shellWriter
		next.ServeHTTP(w, r)

		event = domain.NewAuditEvent(domain.EventInboxRequestEnd, domain.EventPlaceMiddleware,
			true, nil, "", traceId)
		event.Metadata = make(map[string]any)
		event.Metadata["ContentLenght"] = strconv.Itoa(shellWriter.bodySize)
		event.Metadata["StatusCode"] = strconv.Itoa(shellWriter.status)
		md.audit.Log(r.Context(), event)

	})
}

func (md *UtilMiddleware) RateLimiterForIp(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		addr := r.RemoteAddr
		if md.limiter.Allow(addr) {
			next.ServeHTTP(w, r)
		} else {
			http.Error(w, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
		}

	})
}
