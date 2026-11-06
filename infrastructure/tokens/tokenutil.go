package tokens

import (
	"errors"
	"strconv"
	"strings"
	"time"
	"user_service/config"
	"user_service/pkg/repoerrors"
	"uuid"

	"github.com/golang-jwt/jwt/v5"
)

type TokenType = string

const (
	AccessTokenType  TokenType = "access"
	RefreshTokenType TokenType = "refresh"

	Issuer              = "user-service"
	RepoName            = "TokenUtils"
	HeadAuthorization   = "Authorization"
	HeadWWWAuthenticate = "WWW-Authenticate"
	HeadContentType     = "Content-Type"
	HeadUserAgent       = "User-Agent"
	FirstVersion        = "jwt-1"
)

var (
	ErrFieldEmpty       = repoerrors.NewError(RepoName, "important field is empty", "001")
	ErrExpToken         = repoerrors.NewError(RepoName, "token has expired", "002")
	ErrInvalidToken     = repoerrors.NewError(RepoName, "invalid token", "003")
	ErrFutureDateToken  = repoerrors.NewError(RepoName, "token with a future date", "004")
	ErrInvalidSignToken = repoerrors.NewError(RepoName, "invalid token signature", "005")
	ErrInvalidVersion   = repoerrors.NewError(RepoName, "invalid version", "006")
)

type AccessToken struct {
	UserId    uuid.UUID `json:"user_id,omitempty"`
	FamilyId  uuid.UUID `json:"family_id,omitempty"`
	DeviceId  string    `json:"device_id,omitempty"`
	Agent     string    `json:"agent,omitempty"`
	TokenType TokenType `json:"token_type"`
	Version   string    `json:"version"`
	jwt.RegisteredClaims
}

func NewAccessToken(userId, familyId uuid.UUID, deviceId, agent, version string, lifetime int) *AccessToken {
	return &AccessToken{
		UserId:    userId,
		FamilyId:  familyId,
		DeviceId:  deviceId,
		Agent:     agent,
		TokenType: AccessTokenType,
		Version:   version,
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
	FamilyId  uuid.UUID `json:"family_id,omitempty"`
	TokenType TokenType `json:"token_type"`
	Version   string    `json:"version"`
	jwt.RegisteredClaims
}

func NewRefreshToken(userId, familyId uuid.UUID, version string, lifetime int) *RefreshToken {
	return &RefreshToken{
		UserId:    userId,
		FamilyId:  familyId,
		TokenType: RefreshTokenType,
		Version:   version,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Duration(lifetime) * time.Minute)),
			Issuer:    Issuer,
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   userId.String(),
			ID:        uuid.New().String(),
		},
	}
}

type TokenUtil struct {
	cm *config.ConfigManager
}

func NewTokenUtil(cm *config.ConfigManager) *TokenUtil {
	return &TokenUtil{
		cm: cm,
	}
}

func (tu *TokenUtil) GeneratePairToken(userId, familyId uuid.UUID, deviceId, agent string) (string, string, error) {

	errFE := ErrFieldEmpty.Clone()
	if userId == uuid.Nil() {
		errFE.Fields = append(errFE.Fields, "user_id")
	}

	if familyId == uuid.Nil() {
		errFE.Fields = append(errFE.Fields, "family_id")
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

	accessSecret := tu.cm.Get().TokenConf.AccessBt
	refreshSecret := tu.cm.Get().TokenConf.RefreshBt

	accessClaims := NewAccessToken(userId, familyId, deviceId, agent, FirstVersion, tu.cm.Get().TokenConf.AccessLifeTime)
	refreshClaims := NewRefreshToken(userId, familyId, FirstVersion, tu.cm.Get().TokenConf.RefreshLifeTime)

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

func (tu *TokenUtil) ValidAccessToken(token string) (*AccessToken, error) {

	errFE := ErrFieldEmpty.Clone()
	if token == "" {
		errFE.Fields = append(errFE.Fields, "token")
		return nil, errFE
	}

	data, err := jwt.ParseWithClaims(token,
		&AccessToken{},
		func(t *jwt.Token) (any, error) {
			return tu.cm.Get().TokenConf.AccessBt, nil
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
	if !ok || !data.Valid || tokenData == nil {
		return nil, ErrInvalidToken
	}

	if tokenData.RegisteredClaims.IssuedAt != nil &&
		tokenData.RegisteredClaims.IssuedAt.After(time.Now()) {
		return nil, ErrFutureDateToken
	}

	return tokenData, nil
}

func (tu *TokenUtil) ValidRefreshToken(token string) (*RefreshToken, error) {

	tokenData, err := tu.validRefreshTokenWithClaims(token)
	if err != nil || tokenData == nil {
		return nil, err
	}

	if tokenData.RegisteredClaims.IssuedAt != nil &&
		tokenData.RegisteredClaims.IssuedAt.After(time.Now()) {
		return tokenData, ErrFutureDateToken
	}

	return tokenData, nil
}

func (tu *TokenUtil) validRefreshTokenWithClaims(token string) (*RefreshToken, error) {

	errFE := ErrFieldEmpty.Clone()
	if token == "" {
		errFE.Fields = append(errFE.Fields, "token")
		return nil, errFE
	}

	data, err := jwt.ParseWithClaims(token,
		&RefreshToken{},
		func(t *jwt.Token) (any, error) {
			return tu.cm.Get().TokenConf.RefreshBt, nil
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

func CompareVersions(v1, v2 string) (int, error) {
	p1 := strings.Split(v1, "-")
	p2 := strings.Split(v2, "-")

	if len(p1) < 2 || len(p2) < 2 {
		return 0, ErrInvalidVersion
	}

	if p1[0] != "jwt" || p2[0] != "jwt" {
		return 0, ErrInvalidVersion
	}

	n1, err := strconv.ParseInt(p1[1], 10, 64)
	if err != nil {
		return 0, ErrInvalidVersion
	}

	n2, err := strconv.ParseInt(p2[1], 10, 64)
	if err != nil {
		return 0, ErrInvalidVersion
	}

	if n1 > n2 {
		return 1, nil
	} else if n1 < n2 {
		return -1, nil
	}
	return 0, nil
}

func UpdateVersion(version string) (string, error) {

	parts := strings.Split(version, "-")
	if len(parts) < 2 {
		return "", ErrInvalidVersion
	}

	if parts[0] != "jwt" {
		return "", ErrInvalidVersion
	}

	number, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return "", ErrInvalidVersion
	}

	number++
	parts[1] = strconv.FormatInt(number, 10)

	newVer := strings.Join(parts, "-")
	return newVer, nil
}
