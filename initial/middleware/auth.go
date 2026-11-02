package middleware

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"user_service/config"
	"user_service/domain"
	"user_service/infrastructure/tokens"
	"uuid"
)

const (
	RepoName = "AUTH_MIDDLEWARE"

	HeadAuthorization   = "Authorization"
	HeadWWWAuthenticate = "WWW-Authenticate"
	HeadContentType     = "Content-Type"
	HeadUserAgent       = "User-Agent"

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

		cooki := r.Cookies()
		var deviceId string

		for _, val := range cooki {
			if val.Name == "DeviceId" {
				deviceId = val.Value
				break
			}
		}

		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			strerr := err.Error()
			event := domain.NewFailedEvent(domain.EventFailedParseIpFromRemoteAddr, domain.EventPlaceAuthMiddleware,
				&strerr, "", traceId)
			am.audit.Log(ctx, event)

			errBody := ErrBody{
				Err:     "Unauthorized",
				Code:    "USER_NOT_FOUND",
				Message: "User session is invalid or user not found",
			}
			wwwErr := "Bearer error=\"invalid_token\", error_description=\"The access token is unknown or invalid\""
			sendErrorPattern(w, am.audit, traceId, ctx, errBody, wwwErr, 0)
			return
		}

		agent := r.Header.Get(HeadUserAgent)
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
		next.ServeHTTP(w, r)
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
