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
	"user_service/infrastructure/reporedis/custerr"
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
	Bearer         = "bearer "
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

// SendError отправляет HTTP-ответ с ошибкой и логирует событие.
func SendError(w http.ResponseWriter, oc *domain.OperationContext, err *domain.OperationError,
	audit domain.AuditService, eventType domain.EventType) {

	if oc == nil || err == nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	jsonBt, marshalErr := json.Marshal(err)
	if marshalErr != nil {
		strErr := marshalErr.Error()
		event := domain.NewFailedEvent(domain.EventFailedParseErrAuthAnswer,
			domain.EventPlaceAuthMiddleware, &strErr, "", oc.TraceId)
		audit.Log(oc.Ctx, event)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	if err.WWWAns != "" {
		w.Header().Set(HeadWWWAuthenticate, err.WWWAns)
	}
	w.Header().Set(HeadContentType, ValHeadAppJson)

	code := err.StatusCode
	if code == 0 {
		code = http.StatusUnauthorized
	}

	w.WriteHeader(code)
	w.Write(jsonBt)

	event := domain.NewFailedEvent(eventType, domain.EventPlaceAuthMiddleware,
		&err.Message, "", oc.TraceId)
	audit.Log(oc.Ctx, event)
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

		authHeader := r.Header.Get(HeadAuthorization)
		if authHeader == "" {
			SendError(w, oc, &domain.ErrTokenInvalidMsg, am.audit, domain.EventAutheticationFailed)
			return
		}

		token, ok := getBearerData(authHeader)
		if !ok {
			SendError(w, oc, &domain.ErrTokenInvalidMsg, am.audit, domain.EventAutheticationFailed)
			return
		}

		if token == "" {
			SendError(w, oc, &domain.ErrTokenInvalidMsg, am.audit, domain.EventAutheticationFailed)
			return
		}

		tokenData, errValid := am.tu.ValidAccessToken(token)
		if tokens.ErrExpToken.Is(errValid) {
			SendError(w, oc, &domain.ErrTokenExpiredHandler, am.audit, domain.EventAutheticationFailed)
			return
		} else if tokens.ErrFutureDateToken.Is(errValid) {
			// Token with iat in future — revoke session
			sserr := am.sessionStore.DeleteByRefresh(oc.Ctx, tokenData.UserId, tokenData.FamilyId)
			if sserr != nil {
				srterr := sserr.Error()
				event := domain.NewFailedEvent(domain.EventAutheticationFailed, domain.EventPlaceAuthMiddleware,
					&srterr, "", oc.TraceId)
				am.audit.Log(oc.Ctx, event)
			}
			SendError(w, oc, &domain.ErrTokenReuseDetected, am.audit, domain.EventAutheticationFailed)
			return
		} else if errValid != nil {
			SendError(w, oc, &domain.ErrTokenInvalidMsg, am.audit, domain.EventAutheticationFailed)
			return
		}

		if tokenData.UserId == uuid.Nil() || tokenData.FamilyId == uuid.Nil() ||
			tokenData.Agent == "" || tokenData.DeviceId == "" {
			SendError(w, oc, &domain.ErrTokenInvalidMsg, am.audit, domain.EventAutheticationFailed)
			return
		}

		session, err := am.sessionStore.GetSessionByFamilyId(oc.Ctx, tokenData.UserId, tokenData.FamilyId)
		if err != nil {
			if custerr.ErrNotFound.Is(err) {
				SendError(w, oc, &domain.ErrSessionInvalid, am.audit, domain.EventAutheticationFailed)
				return
			}
			SendError(w, oc, &domain.ErrInternalServerError, am.audit, domain.EventAutheticationFailed)
			return
		}

		if session == nil {
			SendError(w, oc, &domain.ErrSessionInvalid, am.audit, domain.EventAutheticationFailed)
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
			ip = GetIpWithFallback(r)
			oc.Ip = ip
		} else {
			ip = oc.Ip
		}

		var agent string
		if oc.Agent == "" {
			agent = r.Header.Get(HeadUserAgent)
			oc.Agent = agent
		} else {
			agent = oc.Agent
		}

		userId := tokenData.UserId
		familyId := tokenData.FamilyId
		if ip == "" || deviceId == "" || agent == "" || userId == uuid.Nil() || familyId == uuid.Nil() {
			SendError(w, oc, &domain.ErrTokenInvalidMsg, am.audit, domain.EventAutheticationFailed)
			return
		}

		// Check session context: compare with token claims first
		if session.UserId != userId || session.Agent != tokenData.Agent || session.DeviceId != tokenData.DeviceId {
			sserr := am.sessionStore.DeleteByRefresh(oc.Ctx, userId, familyId)
			if sserr != nil {
				srterr := sserr.Error()
				event := domain.NewFailedEvent(domain.EventAutheticationFailed, domain.EventPlaceAuthMiddleware,
					&srterr, "", oc.TraceId)
				am.audit.Log(oc.Ctx, event)
			}
			SendError(w, oc, &domain.ErrTokenReuseDetected, am.audit, domain.EventAutheticationFailed)
			return
		}

		// Check session context: compare with request headers
		if session.Agent != agent || session.DeviceId != deviceId {
			sserr := am.sessionStore.DeleteByRefresh(oc.Ctx, userId, familyId)
			if sserr != nil {
				srterr := sserr.Error()
				event := domain.NewFailedEvent(domain.EventAutheticationFailed, domain.EventPlaceAuthMiddleware,
					&srterr, "", oc.TraceId)
				am.audit.Log(oc.Ctx, event)
			}
			SendError(w, oc, &domain.ErrSessionContextMismatch, am.audit, domain.EventAutheticationFailed)
			return
		}

		// Update IP if changed
		if session.Ip != oc.Ip {
			err := am.sessionStore.UpdateIpAdress(oc.Ctx, session.UserId, familyId, oc.Ip)
			if err != nil {
				srterr := err.Error()
				event := domain.NewFailedEvent(domain.EventAutheticationFailed, domain.EventPlaceAuthMiddleware,
					&srterr, oc.Hexid, oc.TraceId)
				am.audit.Log(oc.Ctx, event)
			}
		}

		oc.UserId = userId
		oc.Hexid = hex.EncodeToString(userId[:])
		oc.FamilyId = familyId

		newCtx := context.WithValue(r.Context(), domain.OperCtxKey, oc)
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
			SendError(w, &oc, &domain.ErrBadRequest, am.audit, domain.EventAutheticationFailed)
			return
		}

		oc.Agent = agent
		oc.DeviceId = deviceId
		oc.Ip = ip

		newCtx := context.WithValue(r.Context(), domain.OperCtxKey, &oc)
		next.ServeHTTP(w, r.WithContext(newCtx))
	})
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

func getBearerData(header string) (string, bool) {

	if len(header) < len(Bearer) {
		return "", false
	}

	if strings.ToLower(header[:len(Bearer)]) == Bearer {
		return strings.TrimSpace(header[len(Bearer):]), true
	}

	return "", false
}
