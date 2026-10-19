package middleware

import (
	"errors"
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

func NewAccessToken(userId uuid.UUID, deviceId, agent string) *AccessToken {
	return &AccessToken{
		UserId:    userId,
		DeviceId:  deviceId,
		Agent:     agent,
		TokenType: AccessTokenType,
		RegisteredClaims: jwt.RegisteredClaims{
			// FIXME exp time get from config(dinamic opt)
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
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

func NewRefreshToken(userId uuid.UUID) *RefreshToken {
	return &RefreshToken{
		UserId:    userId,
		TokenType: RefreshTokenType,
		RegisteredClaims: jwt.RegisteredClaims{
			// FIXME exp time get from config(dinamic opt)
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * 7 * time.Hour)),
			Issuer:    Issuer,
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   userId.String(),
			ID:        uuid.New().String(),
		},
	}
}

func (am *AuthMiddleware) GeneratePairToken(userId uuid.UUID, deviceId, agent string) (string, string, error) {

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

	accessSecret := am.cm.Get().TokenConf.AccessBt
	refreshSecret := am.cm.Get().TokenConf.RefreshBt

	accessClaims := NewAccessToken(userId, deviceId, agent)
	refreshClaims := NewRefreshToken(userId)

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

func (am *AuthMiddleware) ValidAccessToken(token string) error {

	errFE := ErrFieldEmpty.Clone()
	if token == "" {
		errFE.Fields = append(errFE.Fields, "token")
		return errFE
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
			return ErrExpToken
		} else if errors.Is(err, jwt.ErrTokenSignatureInvalid) {
			return ErrInvalidSignToken
		} else if errors.Is(err, jwt.ErrTokenInvalidClaims) {
			return ErrInvalidToken
		}
		return err
	}

	tokenData, ok := data.Claims.(*AccessToken)
	if !ok || !data.Valid {
		return ErrInvalidToken
	}

	isAt := tokenData.RegisteredClaims.IssuedAt.Time

	if isAt.After(time.Now()) {
		return ErrFutureDateToken
	}

	return nil
}

func (am *AuthMiddleware) ValidRefreshToken(token string) error {

	errFE := ErrFieldEmpty.Clone()
	if token == "" {
		errFE.Fields = append(errFE.Fields, "token")
		return errFE
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
			return ErrExpToken
		} else if errors.Is(err, jwt.ErrTokenSignatureInvalid) {
			return ErrInvalidSignToken
		} else if errors.Is(err, jwt.ErrTokenInvalidClaims) {
			return ErrInvalidToken
		}
		return err
	}

	tokenData, ok := data.Claims.(*RefreshToken)
	if !ok || !data.Valid {
		return ErrInvalidToken
	}

	isAt := tokenData.RegisteredClaims.IssuedAt.Time

	if isAt.After(time.Now()) {
		return ErrFutureDateToken
	}

	return nil
}

// TODO make handler check valid access token
// with using cache
