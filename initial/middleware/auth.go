package middleware

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"
	"user_service/config"
	"user_service/domain"
	"user_service/pkg/repoerrors"
	"uuid"

	"github.com/golang-jwt/jwt/v5"
)

type TokenType = string

const (
	AccessTokenType  TokenType = "access"
	RefreshTokenType TokenType = "refresh"

	Issuer   = "user-service"
	RepoName = "AUTH_MIDDLEWARE"

	HeadAuthorization   = "Authorization"
	HeadWWWAuthenticate = "WWW-Authenticate"
	HeadContentType     = "Content-Type"
	HeadUserAgent       = "User-Agent"

	ValHeadAppJson = "application/json"
	ValHeadBearer  = "Bearer"
)

var (
	ErrFieldEmpty       = repoerrors.NewError(RepoName, "important field is empty", "001")
	ErrExpToken         = repoerrors.NewError(RepoName, "token has expired", "002")
	ErrInvalidToken     = repoerrors.NewError(RepoName, "invalid token", "003")
	ErrFutureDateToken  = repoerrors.NewError(RepoName, "token with a future date", "004")
	ErrInvalidSignToken = repoerrors.NewError(RepoName, "invalid token signature", "005")
)

type AuthMiddleware struct {
	audit        domain.AuditService
	sessionStore domain.SessionStore
	repo         domain.UserStore
	cm           *config.ConfigManager
}

func NewAuthMiddleware(au domain.AuditService, ss domain.SessionStore, repo domain.UserStore,
	cm *config.ConfigManager) *AuthMiddleware {
	return &AuthMiddleware{
		audit:        au,
		sessionStore: ss,
		repo:         repo,
		cm:           cm,
	}
}

type AccessToken struct {
	UserId    uuid.UUID `json:"user_id,omitempty"`
	DeviceId  string    `json:"device_id,omitempty"`
	Agent     string    `json:"agent,omitempty"`
	TokenType TokenType `json:"token_type"`
	jwt.RegisteredClaims
}

func NewAccessToken(userId uuid.UUID, deviceId, agent string, lifetime int) *AccessToken {
	return &AccessToken{
		UserId:    userId,
		DeviceId:  deviceId,
		Agent:     agent,
		TokenType: AccessTokenType,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Duration(lifetime) * time.Minute)),
			Issuer:    Issuer,
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   userId.String(),
			ID:        uuid.New().String(),
		},
	}
}

type RefreshToken struct {
	UserId    uuid.UUID `json:"user_id,omitempty"`
	TokenType TokenType `json:"token_type"`
	jwt.RegisteredClaims
}

func NewRefreshToken(userId uuid.UUID, lifetime int) *RefreshToken {
	return &RefreshToken{
		UserId:    userId,
		TokenType: RefreshTokenType,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Duration(lifetime) * time.Minute)),
			Issuer:    Issuer,
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   userId.String(),
			ID:        uuid.New().String(),
		},
	}
}

func GeneratePairToken(userId uuid.UUID, deviceId, agent string, cm *config.ConfigManager) (string, string, error) {

	errFE := ErrFieldEmpty.Clone()
	if userId == uuid.Nil() {
		errFE.Fields = append(errFE.Fields, "user_id")
	}

	if deviceId == "" {
		errFE.Fields = append(errFE.Fields, "device_id")
	}

	if agent == "" {
		errFE.Fields = append(errFE.Fields, "agent")
	}

	if len(errFE.Fields) > 0 {
		return "", "", errFE
	}

	accessSecret := cm.Get().TokenConf.AccessBt
	refreshSecret := cm.Get().TokenConf.RefreshBt

	accessClaims := NewAccessToken(userId, deviceId, agent, cm.Get().TokenConf.AccessLifeTime)
	refreshClaims := NewRefreshToken(userId, cm.Get().TokenConf.RefreshLifeTime)

	access := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	signedAccess, err := access.SignedString(accessSecret)
	if err != nil {
		return "", "", err
	}

	refresh := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	signedRefresh, err := refresh.SignedString(refreshSecret)
	if err != nil {
		return "", "", err
	}

	return signedAccess, signedRefresh, nil
}

func (am *AuthMiddleware) ValidAccessToken(token string) (*AccessToken, error) {

	errFE := ErrFieldEmpty.Clone()
	if token == "" {
		errFE.Fields = append(errFE.Fields, "token")
		return nil, errFE
	}

	data, err := jwt.ParseWithClaims(token,
		&AccessToken{},
		func(t *jwt.Token) (any, error) {
			return am.cm.Get().TokenConf.AccessBt, nil
		},
		jwt.WithValidMethods([]string{"HS256"}),
		jwt.WithIssuer(Issuer),
		jwt.WithExpirationRequired())

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrExpToken
		} else if errors.Is(err, jwt.ErrTokenSignatureInvalid) {
			return nil, ErrInvalidSignToken
		} else if errors.Is(err, jwt.ErrTokenInvalidClaims) {
			return nil, ErrInvalidToken
		}
		return nil, err
	}

	tokenData, ok := data.Claims.(*AccessToken)
	if !ok || !data.Valid {
		return nil, ErrInvalidToken
	}

	isAt := tokenData.RegisteredClaims.IssuedAt.Time

	if isAt.After(time.Now()) {
		return nil, ErrFutureDateToken
	}

	return tokenData, nil
}

func (am *AuthMiddleware) ValidRefreshToken(token string) error {

	tokenData, err := am.ValidRefreshTokenWithClaims(token)
	if err != nil {
		return err
	}

	isAt := tokenData.RegisteredClaims.IssuedAt.Time

	if isAt.After(time.Now()) {
		return ErrFutureDateToken
	}

	return nil
}

func (am *AuthMiddleware) ValidRefreshTokenWithClaims(token string) (*RefreshToken, error) {

	errFE := ErrFieldEmpty.Clone()
	if token == "" {
		errFE.Fields = append(errFE.Fields, "token")
		return nil, errFE
	}

	data, err := jwt.ParseWithClaims(token,
		&RefreshToken{},
		func(t *jwt.Token) (any, error) {
			return am.cm.Get().TokenConf.RefreshBt, nil
		},
		jwt.WithValidMethods([]string{"HS256"}),
		jwt.WithIssuer(Issuer),
		jwt.WithExpirationRequired())

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrExpToken
		} else if errors.Is(err, jwt.ErrTokenSignatureInvalid) {
			return nil, ErrInvalidSignToken
		} else if errors.Is(err, jwt.ErrTokenInvalidClaims) {
			return nil, ErrInvalidToken
		}
		return nil, err
	}

	tokenData, ok := data.Claims.(*RefreshToken)
	if !ok || !data.Valid {
		return nil, ErrInvalidToken
	}

	return tokenData, nil
}

func ParseRefreshToken(token string, cm *config.ConfigManager) (*jwt.Token, error) {

	if token == "" {
		return nil, ErrFieldEmpty
	}

	data, err := jwt.ParseWithClaims(token,
		&RefreshToken{},
		func(t *jwt.Token) (any, error) {
			return cm.Get().TokenConf.RefreshBt, nil
		},
		jwt.WithValidMethods([]string{"HS256"}),
		jwt.WithIssuer(Issuer),
		jwt.WithExpirationRequired())

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrExpToken
		} else if errors.Is(err, jwt.ErrTokenSignatureInvalid) {
			return nil, ErrInvalidSignToken
		} else if errors.Is(err, jwt.ErrTokenInvalidClaims) {
			return nil, ErrInvalidToken
		}
		return nil, err
	}

	return data, nil
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

		tokenData, errValid := am.ValidAccessToken(token)
		if ErrExpToken.Is(errValid) {

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

		if tokenData.UserId == uuid.Nil() || tokenData.Agent == "" || tokenData.DeviceId == "" {
			errBody := ErrBody{
				Err:     "Unauthorized",
				Code:    "TOKEN_INVALID",
				Message: "Access token invalid",
			}

			wwwErr := "Bearer error=\"invalid_token\", error_description=\"The access token invalid\""
			sendErrorPattern(w, am.audit, traceId, ctx, errBody, wwwErr, 0)
			return
		}

		sessions, err := am.sessionStore.GetAllSession(ctx, tokenData.UserId)
		if err != nil {
			errBody := ErrBody{
				Err:     "Internal Server Error",
				Code:    "AUTH_SERVICE_ERROR",
				Message: "Authentication service is temporarily unavailable. Please try again later.",
			}
			sendErrorPattern(w, am.audit, traceId, ctx, errBody, "", http.StatusInternalServerError)
			return
		}

		if len(sessions) == 0 {
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
		if ip == "" || deviceId == "" || agent == "" || userId == uuid.Nil() {
			returnErrorSessionMiss(w, am.audit, traceId, ctx)
			return
		}

		var finderSessHeader bool
		var finderSessToken bool
		for _, ss := range sessions {
			if ss.UserId == userId && ss.Agent == agent && ss.DeviceId == deviceId && ss.Ip == ip {
				finderSessHeader = true
			}
			if ss.UserId == userId && ss.Agent == tokenData.Agent && ss.DeviceId == tokenData.DeviceId {
				finderSessToken = true
			}

			if finderSessHeader && finderSessToken {
				break
			}
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
