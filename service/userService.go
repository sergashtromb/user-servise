package service

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"
	"user_service/config"
	"user_service/domain"
	dm "user_service/domain"
	"user_service/infrastructure/postgres"
	"user_service/infrastructure/reporedis/custerr"
	"user_service/infrastructure/tokens"
	"uuid"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/sync/singleflight"
)

var (
	InvalidRequest = dm.OperationError{Err: "invalid_request", Code: "INVALID_REQUEST"}
	InvalidGrant   = dm.OperationError{Err: "invalid_grant", Code: "INVALID_GRANT",
		StatusCode: http.StatusBadRequest}
	InvalidToken = dm.OperationError{Err: "invalid_token", Code: "INVALID_TOKEN",
		Message:    "The token is invalid or malformed.",
		StatusCode: http.StatusBadRequest}
	SessionContextMismatch = dm.OperationError{Err: "invalid_grant", Code: "SESSION_CONTEXT_MISMATCH",
		Message:    "Session context mismatch. Please log in again.",
		StatusCode: http.StatusBadRequest}
	InternalServerError = dm.OperationError{Err: "internal_server_error", Code: "AUTH_SERVICE_ERROR",
		Message:    "Authentication service is temporarily unavailable. Please try again later.",
		StatusCode: http.StatusInternalServerError}
)

type UserService struct {
	audit        dm.AuditService
	userCache    dm.UserCacheStore
	userStore    dm.UserStore
	sessionStore dm.SessionStore
	tokenUtil    *tokens.TokenUtil
	conf         *config.ConfigManager
	sgr          singleflight.Group
	fakePass     []byte
}

func NewUserService(uc dm.UserCacheStore, us dm.UserStore, ss dm.SessionStore,
	ah dm.AuditService, tu *tokens.TokenUtil, conf *config.ConfigManager) *UserService {
	return &UserService{
		audit:        ah,
		userCache:    uc,
		userStore:    us,
		sessionStore: ss,
		tokenUtil:    tu,
		conf:         conf,
	}
}

func (us *UserService) UpdateRefreshToken(oc *dm.OperationContext, refresh string) (*dm.OperationTokens, *dm.OperationError) {

	var opTokens dm.OperationTokens

	tokenData, err := us.tokenUtil.ValidRefreshToken(refresh)
	if err != nil {

		us.logFailEvent(oc.Ctx, dm.EventUpdateVersionTokenFailed, err.Error(), "", oc.TraceId)

		if tokens.ErrExpToken.Is(err) {

			opErr := InvalidGrant
			opErr.Message = "The refresh token has expired. Please re-authenticate."
			opErr.StatusCode = http.StatusBadRequest

			return nil, &opErr

		} else if tokens.ErrInvalidSignToken.Is(err) || tokens.ErrInvalidToken.Is(err) {
			return nil, &InvalidToken
		} else if tokens.ErrFutureDateToken.Is(err) {

			opErr := InvalidToken
			opErr.Message = "Token reuse detected. Session has been revoked."

			err = us.sessionStore.DeleteByRefresh(oc.Ctx, tokenData.UserId, tokenData.FamilyId)
			if err != nil {
				us.logFailEvent(oc.Ctx, dm.EventUpdateVersionTokenFailed, err.Error(), "", oc.TraceId)
			}
			return nil, &opErr

		} else {
			return nil, &InternalServerError
		}
	}

	newVer, err := tokens.UpdateVersion(tokenData.Version)
	if err != nil {
		us.logFailEvent(oc.Ctx, dm.EventUpdateVersionTokenFailed, err.Error(), "", oc.TraceId)
		return nil, &InvalidToken
	}

	session, err := us.sessionStore.GetSessionByFamilyId(oc.Ctx, tokenData.UserId, tokenData.FamilyId)
	if err != nil {

		us.logFailEvent(oc.Ctx, dm.EventGetSessionUserFailed, err.Error(), "", oc.TraceId)

		if custerr.ErrBadArgs.Is(err) {
			return nil, &InvalidToken
		} else if custerr.ErrNotFound.Is(err) {
			opErr := InvalidToken
			opErr.Message = "The session is invalid or has been revoked."
			opErr.WWWAns = `Bearer error="invalid_token", error_description="The session is invalid or has been revoked."`

			return nil, &opErr

		} else {
			return nil, &InternalServerError
		}
	}

	oc.UserId = session.UserId
	oc.Hexid = hex.EncodeToString(session.UserId[:])

	if session.DeviceId != oc.DeviceId || session.Agent != oc.Agent {

		us.logFailEvent(oc.Ctx, dm.EventGetSessionUserFailed, "impotant field dont equal session and header",
			oc.Hexid, oc.TraceId)

		opErr := SessionContextMismatch
		opErr.WWWAns = `Bearer error="invalid_grant", error_description="Session context mismatch. Please log in again."`

		err := us.sessionStore.DeleteByRefresh(oc.Ctx, session.UserId, tokenData.FamilyId)
		if err != nil {
			us.logFailEvent(oc.Ctx, dm.EventGetSessionUserFailed, err.Error(), oc.Hexid, oc.TraceId)
		}

		return nil, &opErr
	}

	newVerFromSs, err := tokens.UpdateVersion(session.Version)
	if err != nil {
		us.logFailEvent(oc.Ctx, dm.EventGetSessionUserFailed, err.Error(), oc.Hexid, oc.TraceId)
		return nil, &InternalServerError
	}

	// check version from session and token
	compareResult, err := tokens.CompareVersions(newVer, newVerFromSs)
	if err != nil {
		us.logFailEvent(oc.Ctx, dm.EventGetSessionUserFailed, "fail compare version, invalid version",
			oc.Hexid, oc.TraceId)
		return nil, &InternalServerError
	}

	isError := false
	errBody := InvalidGrant
	var errMes string

	switch compareResult {
	case 1:
		isError = true

		errBody.Code = "FUTURE_TOKEN_DETECTED"
		errBody.Message = "Token version conflict. Session has been revoked."
		errMes = "Token from the future detected. Incoming version > session version. Session revoked." // Внутренний лог для разработчиков/Security

	case -1:
		isError = true

		errBody.Code = "TOKEN_REUSE_DETECTED"
		errBody.Message = "Token reuse detected. Session has been revoked."
		errMes = "Token reuse detected. Session has been revoked."

	case 0:
	default:
		us.logFailEvent(oc.Ctx, dm.EventGetSessionUserFailed, "fail compare version, returned an invalid value",
			oc.Hexid, oc.TraceId)
		return nil, &InternalServerError
	}

	if isError {

		us.logFailEvent(oc.Ctx, dm.EventGetSessionUserFailed, errMes, oc.Hexid, oc.TraceId)
		errBody.WWWAns = fmt.Sprintf(`Bearer error="invalid_token", error_description="%v"`, errBody.Message)

		err := us.sessionStore.DeleteByRefresh(oc.Ctx, session.UserId, tokenData.FamilyId)
		if err != nil {
			us.logFailEvent(oc.Ctx, dm.EventGetSessionUserFailed, err.Error(), oc.Hexid, oc.TraceId)
		}

		return nil, &errBody
	}

	// try get from grace periodic
	access, refresh, err := us.sessionStore.GetFromGracePeriodic(oc.Ctx, session.UserId, tokenData.FamilyId, newVer)
	if custerr.ErrGracePeriodicNoExists.Is(err) {

		newAccess, newRefresh, err := us.tokenUtil.GeneratePairToken(session.UserId, tokenData.FamilyId, session.DeviceId, session.Agent)
		if err != nil {
			us.logFailEvent(oc.Ctx, dm.EventGetSessionUserFailed, err.Error(), oc.Hexid, oc.TraceId)
			return nil, &InternalServerError
		}

		gracePeriodic := dm.GracePeriodic{
			Version: newVer,
			Access:  newAccess,
			Refresh: newRefresh,
		}

		// if grace no exist then create
		err = us.sessionStore.CreateGracePeriodic(oc.Ctx, session.UserId, tokenData.FamilyId, &gracePeriodic)
		if err != nil {

			us.logFailEvent(oc.Ctx, dm.EventGetSessionUserFailed, err.Error(), oc.Hexid, oc.TraceId)

			if custerr.ErrGracePeriodicAlredyExist.Is(err) {
				return nil, &InternalServerError

			} else if custerr.ErrSuspiciousRefreshRate.Is(err) {

				opErr := InvalidGrant
				opErr.Code = "TOKEN_REUSE_DETECTED"
				opErr.Message = "Token reuse detected. Session has been revoked."
				opErr.WWWAns = `Bearer error="invalid_token", error_description="Token reuse detected. Session has been revoked."`
				opErr.StatusCode = http.StatusBadRequest

				err := us.sessionStore.DeleteByRefresh(oc.Ctx, session.UserId, tokenData.FamilyId)
				if err != nil {
					us.logFailEvent(oc.Ctx, dm.EventGetSessionUserFailed, err.Error(), oc.Hexid, oc.TraceId)
				}

				return nil, &opErr

			} else {
				return nil, &InternalServerError
			}

		}

		access = newAccess
		refresh = newRefresh

	} else if err != nil {

		us.logFailEvent(oc.Ctx, dm.EventGetSessionUserFailed, err.Error(), oc.Hexid, oc.TraceId)
		return nil, &InternalServerError
	}

	opTokens.AccessToken = access
	opTokens.RefreshToken = refresh
	opTokens.TokenType = "Bearer"
	opTokens.ExpiresIn = int(us.conf.Get().TokenConf.AccessLifeTime) * 60

	return &opTokens, nil
}

func (us *UserService) RegistrationUser(oc *dm.OperationContext) (*dm.OperationTokens, *dm.OperationError) {

	if strings.TrimSpace(oc.UserData.UserName) == "" || strings.TrimSpace(oc.UserData.Password) == "" {

		us.logFailEvent(oc.Ctx, dm.EventRegistrationFailed, "The request is missing important fields.", "", oc.TraceId)

		errBody := dm.OperationError{
			Err:        "invalid_request",
			Code:       "VALIDATION_ERROR",
			Message:    "Username and password are required.",
			StatusCode: http.StatusBadRequest,
		}

		return nil, &errBody
	}

	err := us.addPasswordHashInExContext(oc, domain.EventRegistrationFailed)
	if err != nil {
		return nil, err
	}

	key := fmt.Sprintf("%s%s%s", oc.UserData.UserName, oc.UserData.Email, oc.UserData.Phone)

	idDt, dbErr, _ := us.sgr.Do(key, func() (any, error) {
		id, err := us.userStore.Create(context.WithoutCancel(oc.Ctx), oc.UserData)
		return id, err
	})

	if postgres.ErrUserAlreadyExists.Is(dbErr) {
		// add info event
		errBody := dm.OperationError{
			Err:        "conflict",
			Code:       "REGISTRATION_FAILED",
			Message:    "Registration failed. Please check your details or try logging in.",
			StatusCode: http.StatusConflict,
		}

		return nil, &errBody

	} else if dbErr != nil {
		us.logFailEvent(oc.Ctx, domain.EventRegistrationFailed, dbErr.Error(), "", oc.TraceId)
		return nil, &InternalServerError
	}

	id, ok := idDt.(uuid.UUID)
	if !ok {
		us.logFailEvent(oc.Ctx, domain.EventRegistrationFailed, "fail convert any in uuid", "", oc.TraceId)
		return nil, &InternalServerError
	}

	hexId := hex.EncodeToString(id[:])
	oc.Hexid = hexId
	oc.UserData.Id = id

	err = us.regSession(oc, domain.EventRegistrationFailed)
	if err != nil {
		return nil, err
	}

	access, refresh, err := us.genTokens(oc, domain.EventRegistrationFailed)
	if err != nil {
		return nil, err
	}

	optTokens := dm.OperationTokens{
		AccessToken:  access,
		RefreshToken: refresh,
		ExpiresIn:    int(us.conf.Get().TokenConf.AccessLifeTime) * 60,
		TokenType:    "Bearer",
	}

	return &optTokens, nil
}

func (us *UserService) SingIn(oc *dm.OperationContext) (*dm.OperationTokens, *dm.OperationError) {

	if !(strings.TrimSpace(oc.UserData.UserName) != "" || strings.TrimSpace(oc.UserData.Email) != "" || strings.TrimSpace(oc.UserData.Phone) != "") ||
		strings.TrimSpace(oc.UserData.Password) == "" {
		us.logFailEvent(oc.Ctx, domain.EventLoginFailed, "The request is missing important fields.", "", oc.TraceId)

		errBody := InvalidRequest
		errBody.Code = "VALIDATION_ERROR"
		errBody.Message = "Username and password are required."
		errBody.StatusCode = http.StatusBadRequest

		return nil, &errBody
	}

	userOpt := domain.ToUserOpt(oc.UserData)

	key := fmt.Sprintf("%s%s%s", oc.UserData.UserName, oc.UserData.Email, oc.UserData.Phone)

	userDt, err, _ := us.sgr.Do(key, func() (any, error) {
		trueUser, err := us.userStore.GetByOpt(context.WithoutCancel(oc.Ctx), userOpt)
		return trueUser, err
	})

	if postgres.ErrUserDontExist.Is(err) {
		// fake time work
		_ = bcrypt.CompareHashAndPassword(us.fakePass, []byte(oc.UserData.Password))
		//add info event

		errBody := InvalidGrant
		errBody.Code = "INVALID_CREDENTIALS"
		errBody.Message = "Invalid username or password."
		errBody.StatusCode = http.StatusUnauthorized

		return nil, &errBody

	} else if err != nil {
		us.logFailEvent(oc.Ctx, dm.EventLoginFailed, err.Error(), "", oc.TraceId)
		return nil, &InternalServerError
	}

	userFromDb, ok := userDt.(*domain.User)
	if !ok {
		us.logFailEvent(oc.Ctx, dm.EventLoginFailed, "Failed convert any user for *domain.User", "", oc.TraceId)
		return nil, &InternalServerError
	}

	if err := bcrypt.CompareHashAndPassword([]byte(userFromDb.Password), []byte(oc.UserData.Password)); err != nil {
		//add info event
		errBody := InvalidGrant
		errBody.Code = "INVALID_CREDENTIALS"
		errBody.Message = "Invalid username or password."
		errBody.StatusCode = http.StatusUnauthorized

		return nil, &errBody
	}

	oc.UserData = userFromDb
	id := userFromDb.Id
	hexId := hex.EncodeToString(id[:])
	oc.Hexid = hexId

	errBody := us.regSession(oc, dm.EventLoginFailed)
	if errBody != nil {
		return nil, errBody
	}

	access, refresh, errBody := us.genTokens(oc, dm.EventLoginFailed)
	if errBody != nil {
		return nil, errBody
	}

	tokens := dm.OperationTokens{
		AccessToken:  access,
		RefreshToken: refresh,
		ExpiresIn:    int(us.conf.Get().TokenConf.AccessLifeTime) * 60,
		TokenType:    "Bearer",
	}

	return &tokens, nil
}

func (us *UserService) logFailEvent(ctx context.Context, typeEvent dm.EventType, err, entId, traceId string) {
	event := dm.NewFailedEvent(typeEvent, dm.EventPlaceService,
		&err, entId, traceId)
	us.audit.Log(ctx, event)
}

func (us *UserService) regSession(oc *dm.OperationContext, eventType domain.EventType) *dm.OperationError {

	familyId := uuid.NewV7()
	oc.FamilyId = familyId
	session := domain.Session{
		UserId:     oc.UserData.Id,
		DeviceId:   oc.DeviceId,
		Agent:      oc.Agent,
		Ip:         oc.Ip,
		Version:    tokens.FirstVersion,
		CreatedAt:  time.Now(),
		LastUpdate: time.Now(),
	}

	err := us.sessionStore.Registration(oc.Ctx, &session, familyId)
	if err != nil {
		us.logFailEvent(oc.Ctx, eventType, err.Error(), oc.Hexid, oc.TraceId)
		return &InternalServerError
	}

	return nil
}

func (us *UserService) genTokens(oc *dm.OperationContext, eventType domain.EventType) (string, string, *dm.OperationError) {

	access, refresh, err := us.tokenUtil.GeneratePairToken(oc.UserData.Id, oc.FamilyId, oc.DeviceId, oc.Agent)
	if err != nil {

		cherr := us.rollbackForCache(oc.Ctx, oc.UserData.Id, oc.FamilyId)
		if cherr != nil {
			us.logFailEvent(oc.Ctx, eventType, cherr.Error(), oc.Hexid, oc.TraceId)
		}

		us.logFailEvent(oc.Ctx, eventType, err.Error(), oc.Hexid, oc.TraceId)

		return "", "", &InternalServerError
	}

	return access, refresh, nil
}

func (us *UserService) rollbackForCache(ctx context.Context, userId, familyId uuid.UUID) error {
	err := us.sessionStore.DeleteByRefresh(ctx, userId, familyId)
	return err
}

func hashPassword(password string) (string, error) {

	hash, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	if err != nil {
		return "", err
	}

	return string(hash), nil
}

func (us *UserService) addPasswordHashInExContext(oc *domain.OperationContext, eventType domain.EventType) *dm.OperationError {

	if oc.UserData == nil {
		return &InternalServerError
	}

	hash, err := hashPassword(oc.UserData.Password)
	if err != nil {
		us.logFailEvent(oc.Ctx, eventType, err.Error(), "", oc.TraceId)
		return &InternalServerError
	}

	oc.HashPass = hash
	return nil
}
