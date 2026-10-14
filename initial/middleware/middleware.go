package middleware

import (
	"context"
	"encoding/hex"
	"net/http"
	"strconv"
	"user_service/domain"
	"uuid"
)

type Middleware struct {
	audit domain.AuditService
}

func NewMiddleware(audit domain.AuditService) *Middleware {
	return &Middleware{
		audit: audit,
	}
}

func (md *Middleware) PanicRecovery(next http.Handler) http.Handler {
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

func (md *Middleware) TraceControl(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		reqid := r.Header.Get("X-Request-ID")
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

func (md *Middleware) Logger(next http.Handler) http.Handler {
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

		event := domain.NewAuditEvent(domain.EventInboxRequest, domain.EventPlaceMiddleware,
			true, nil, "", traceId)
		// FIXME change context
		md.audit.Log(context.TODO(), event)

		next.ServeHTTP(w, r)
	})
}
