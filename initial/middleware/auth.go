package middleware

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"user_service/config"
	"user_service/domain"
	"user_service/infrastructure/tokens"
	"uuid"

	"github.com/vfaronov/httpheader"
)

const (
	RepoName = "AUTH_MIDDLEWARE"

	HeadAuthorization   = "Authorization"
	HeadWWWAuthenticate = "WWW-Authenticate"
	HeadContentType     = "Content-Type"
	HeadUserAgent       = "User-Agent"
	HeadXRealIP         = "X-Real-IP"
	HeadForwarded       = "Forwarded"

	ValHeadAppJson = "application/json"
	ValHeadBearer  = "Bearer"
)

type AuthMiddleware struct {
	audit        domain.AuditService
	sessionStore domain.SessionStore
	repo         domain.UserStore
	cm           *config.ConfigManager
	tu           *tokens.TokenUtil
}

func NewAuthMiddleware(au domain.AuditService, ss domain.SessionStore, repo domain.UserStore,
	cm *config.ConfigManager, tu *tokens.TokenUtil) *AuthMiddleware {
	return &AuthMiddleware{
		audit:        au,
		sessionStore: ss,
		repo:         repo,
		cm:           cm,
		tu:           tu,
	}
}

type ErrBody struct {
	Err     string `json:"error"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (am *AuthMiddleware) CheckInboxAccessToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		ctx := r.Context()
		traceId, ok := ctx.Value(domain.TraceKey).(string)
		if !ok {
			traceId = ""
		}

		oc, ok := ctx.Value(domain.OperCtxKey).(*domain.OperationContext)
		if !ok {
			oc = &domain.OperationContext{Ctx: ctx, TraceId: traceId}
		}

		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			returnErrorEmptyToken(w, am.audit, traceId, ctx)
			return
		}

		token := strings.TrimPrefix(authHeader, ValHeadBearer+" ")
		if token == "" {
			returnErrorEmptyToken(w, am.audit, traceId, ctx)
			return
		}

		tokenData, errValid := am.tu.ValidAccessToken(token)
		if tokens.ErrExpToken.Is(errValid) {

			errBody := ErrBody{
				Err:     "Unauthorized",
				Code:    "TOKEN_EXPIRED",
				Message: "The access token expired",
			}

			wwwErr := "Bearer error=\"invalid_token\", error_description=\"The access token expired\""
			sendErrorPattern(w, am.audit, traceId, ctx, errBody, wwwErr, 0)
			return
		} else if errValid != nil {

			errBody := ErrBody{
				Err:     "Unauthorized",
				Code:    "TOKEN_INVALID",
				Message: "Access token invalid",
			}

			wwwErr := "Bearer error=\"invalid_token\", error_description=\"The access token invalid\""
			sendErrorPattern(w, am.audit, traceId, ctx, errBody, wwwErr, 0)
			return
		}

		if tokenData.UserId == uuid.Nil() || tokenData.FamilyId == uuid.Nil() ||
			tokenData.Agent == "" || tokenData.DeviceId == "" {
			errBody := ErrBody{
				Err:     "Unauthorized",
				Code:    "TOKEN_INVALID",
				Message: "Access token invalid",
			}

			wwwErr := "Bearer error=\"invalid_token\", error_description=\"The access token invalid\""
			sendErrorPattern(w, am.audit, traceId, ctx, errBody, wwwErr, 0)
			return
		}

		session, err := am.sessionStore.GetSessionByFamilyId(ctx, tokenData.UserId, tokenData.FamilyId)
		if err != nil {
			errBody := ErrBody{
				Err:     "Internal Server Error",
				Code:    "AUTH_SERVICE_ERROR",
				Message: "Authentication service is temporarily unavailable. Please try again later.",
			}
			sendErrorPattern(w, am.audit, traceId, ctx, errBody, "", http.StatusInternalServerError)
			return
		}

		if session == nil {
			errBody := ErrBody{
				Err:     "Unauthorized",
				Code:    "USER_NOT_FOUND",
				Message: "User session is invalid or user not found",
			}
			wwwErr := "Bearer error=\"invalid_token\", error_description=\"The access token is unknown or invalid\""
			sendErrorPattern(w, am.audit, traceId, ctx, errBody, wwwErr, 0)
			return
		}

		var deviceId string
		if oc.DeviceId == "" {
			cooki := r.Cookies()

			for _, val := range cooki {
				if val.Name == "DeviceId" {
					deviceId = val.Value
					oc.DeviceId = deviceId
					break
				}
			}
		} else {
			deviceId = oc.DeviceId
		}

		var ip string
		if oc.Ip == "" {
			ip := GetIpWithFallback(r)
			oc.Ip = ip
		} else {
			ip = oc.Ip
		}

		var agent string
		if oc.Agent == "" {
			agent := r.Header.Get(HeadUserAgent)
			oc.Agent = agent
		} else {
			agent = oc.Agent
		}

		userId := tokenData.UserId
		familyId := tokenData.FamilyId
		if ip == "" || deviceId == "" || agent == "" || userId == uuid.Nil() || familyId == uuid.Nil() {
			returnErrorSessionMiss(w, am.audit, traceId, ctx)
			return
		}

		var finderSessHeader bool
		var finderSessToken bool

		if session.UserId == userId && session.Agent == agent && session.DeviceId == deviceId && session.Ip == ip {
			finderSessHeader = true
		}
		if session.UserId == userId && session.Agent == tokenData.Agent && session.DeviceId == tokenData.DeviceId {
			finderSessToken = true
		}

		if !finderSessHeader || !finderSessToken {
			returnErrorSessionMiss(w, am.audit, traceId, ctx)
			return
		}

		if deviceId != tokenData.DeviceId || agent != tokenData.Agent {
			returnErrorSessionMiss(w, am.audit, traceId, ctx)
			return
		}

		oc.UserId = userId
		oc.Hexid = hex.EncodeToString(userId[:])
		oc.FamilyId = familyId

		newCtx := context.WithValue(r.Context(), domain.OperCtxKey, &oc)
		next.ServeHTTP(w, r.WithContext(newCtx))
	})
}

func (am *AuthMiddleware) GetImpotantParams(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		var oc domain.OperationContext

		ctx := r.Context()
		traceId, ok := ctx.Value(domain.TraceKey).(string)
		if !ok {
			traceId = ""
		}

		oc.Ctx = ctx
		oc.TraceId = traceId

		cooki := r.Cookies()
		var deviceId string

		for _, val := range cooki {
			if val.Name == "DeviceId" {
				deviceId = val.Value
				break
			}
		}

		ip := GetIpWithFallback(r)
		agent := r.Header.Get(HeadUserAgent)

		if ip == "" || deviceId == "" || agent == "" {
			returnErrorBadRequest(w, am.audit, traceId, ctx)
			return
		}

		oc.Agent = agent
		oc.DeviceId = deviceId
		oc.Ip = ip

		newCtx := context.WithValue(r.Context(), domain.OperCtxKey, &oc)
		next.ServeHTTP(w, r.WithContext(newCtx))
	})
}

func returnErrorSessionMiss(w http.ResponseWriter, audit domain.AuditService, traceId string, ctx context.Context) {
	errBody := ErrBody{
		Err:     "Unauthorized",
		Code:    "SESSION_COMPROMISED",
		Message: "Session context mismatch. Security violation.",
	}
	wwwErr := "Bearer error=\"invalid_token\", error_description=\"Session context mismatch. Security validation failed.\""
	sendErrorPattern(w, audit, traceId, ctx, errBody, wwwErr, 0)
}

func returnErrorBadRequest(w http.ResponseWriter, audit domain.AuditService, traceId string, ctx context.Context) {
	errBody := ErrBody{
		Err:     "bad request",
		Code:    "BAD_REQUEST",
		Message: "The request is missing important fields.",
	}
	sendErrorPattern(w, audit, traceId, ctx, errBody, "", http.StatusBadRequest)
}

func returnErrorEmptyToken(w http.ResponseWriter, audit domain.AuditService, traceId string, ctx context.Context) {

	errBody := ErrBody{
		Err:     "Unauthorized",
		Code:    "AUTH_HEADER_MISSING",
		Message: "Authorization header is missing",
	}

	jsonBt, err := json.Marshal(errBody)
	if err != nil {
		strerr := err.Error()
		event := domain.NewFailedEvent(domain.EventFailedParseErrAuthAnswer, domain.EventPlaceAuthMiddleware,
			&strerr, "", traceId)
		audit.Log(ctx, event)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	w.Header().Set(HeadWWWAuthenticate, ValHeadBearer+" realm=\"user-service\"")
	w.Header().Set(HeadContentType, ValHeadAppJson)
	w.WriteHeader(http.StatusUnauthorized)
	w.Write(jsonBt)

}

func sendErrorPattern(w http.ResponseWriter, audit domain.AuditService, traceId string, ctx context.Context,
	errBody ErrBody, wwwErr string, code int) {

	jsonBt, err := json.Marshal(errBody)
	if err != nil {
		strerr := err.Error()
		event := domain.NewFailedEvent(domain.EventFailedParseErrAuthAnswer, domain.EventPlaceAuthMiddleware,
			&strerr, "", traceId)
		audit.Log(ctx, event)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	if code == 0 {
		code = http.StatusUnauthorized
	}

	if wwwErr != "" {
		w.Header().Set(HeadWWWAuthenticate, wwwErr)
	}

	w.Header().Set(HeadContentType, ValHeadAppJson)

	w.WriteHeader(code)
	w.Write(jsonBt)

}

// GetIp извлекает реальный IP клиента с учётом прокси-заголовков.
// Порядок приоритета: X-Forwarded-For → X-Real-IP → Forwarded → RemoteAddr.
func GetIp(r *http.Request) (string, error) {

	xForwardedFor := r.Header.Get("X-Forwarded-For")
	if xForwardedFor != "" {
		ips := strings.Split(xForwardedFor, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0]), nil
		}
	}

	xRealIp := r.Header.Get(HeadXRealIP)
	if xRealIp != "" {
		return strings.TrimSpace(xRealIp), nil
	}

	data := httpheader.Forwarded(r.Header)
	if len(data) > 0 {
		return data[0].For.IP.String(), nil
	}

	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return "", err
	}

	return ip, nil
}

// GetIpWithFallback — обёртка над GetIp: при ошибке возвращает IP из RemoteAddr.
func GetIpWithFallback(r *http.Request) string {
	ip, err := GetIp(r)
	if err != nil {
		fallback, _, ferr := net.SplitHostPort(r.RemoteAddr)
		if ferr != nil {
			return ""
		}
		return fallback
	}
	return ip
}
