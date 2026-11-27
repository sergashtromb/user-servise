package service

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"
	"user_service/config"
	"user_service/domain"
	dm "user_service/domain"
	"user_service/infrastructure/postgres"
	"user_service/infrastructure/reporedis/custerr"
	"user_service/infrastructure/tokens"
	"user_service/pkg/repoerrors"
	"uuid"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/sync/singleflight"
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
			return nil, &dm.ErrTokenExpiredHandler
		} else if tokens.ErrInvalidSignToken.Is(err) || tokens.ErrInvalidToken.Is(err) {
			return nil, &dm.ErrTokenInvalid
		} else if tokens.ErrFutureDateToken.Is(err) {

			err := us.sessionStore.DeleteByRefresh(oc.Ctx, tokenData.UserId, tokenData.FamilyId)
			if err != nil {
				us.logFailEvent(oc.Ctx, dm.EventUpdateVersionTokenFailed, err.Error(), "", oc.TraceId)
			}
			return nil, &dm.ErrTokenReuseDetected

		} else {
			return nil, &dm.ErrInternalServerError
		}
	}

	newVer, err := tokens.UpdateVersion(tokenData.Version)
	if err != nil {
		us.logFailEvent(oc.Ctx, dm.EventUpdateVersionTokenFailed, err.Error(), "", oc.TraceId)
		return nil, &dm.ErrTokenInvalid
	}

	session, err := us.sessionStore.GetSessionByFamilyId(oc.Ctx, tokenData.UserId, tokenData.FamilyId)
	if err != nil {

		us.logFailEvent(oc.Ctx, dm.EventGetSessionUserFailed, err.Error(), "", oc.TraceId)

		if custerr.ErrBadArgs.Is(err) {
			return nil, &dm.ErrTokenInvalid
		} else if custerr.ErrNotFound.Is(err) {
			return nil, &dm.ErrSessionInvalid
		} else {
			return nil, &dm.ErrInternalServerError
		}
	}

	oc.UserId = session.UserId
	oc.Hexid = hex.EncodeToString(session.UserId[:])

	if session.DeviceId != oc.DeviceId || session.Agent != oc.Agent {

		us.logFailEvent(oc.Ctx, dm.EventGetSessionUserFailed, "impotant field dont equal session and header",
			oc.Hexid, oc.TraceId)

		err := us.sessionStore.DeleteByRefresh(oc.Ctx, session.UserId, tokenData.FamilyId)
		if err != nil {
			us.logFailEvent(oc.Ctx, dm.EventGetSessionUserFailed, err.Error(), oc.Hexid, oc.TraceId)
		}

		return nil, &dm.ErrSessionContextMismatch
	}

	newVerFromSs, err := tokens.UpdateVersion(session.Version)
	if err != nil {
		us.logFailEvent(oc.Ctx, dm.EventGetSessionUserFailed, err.Error(), oc.Hexid, oc.TraceId)
		return nil, &dm.ErrInternalServerError
	}

	// check version from session and token
	compareResult, err := tokens.CompareVersions(newVer, newVerFromSs)
	if err != nil {
		us.logFailEvent(oc.Ctx, dm.EventGetSessionUserFailed, "fail compare version, invalid version",
			oc.Hexid, oc.TraceId)
		return nil, &dm.ErrInternalServerError
	}

	switch compareResult {
	case 1:
		us.logFailEvent(oc.Ctx, dm.EventGetSessionUserFailed, "Token from the future detected. Incoming version > session version. Session revoked.",
			oc.Hexid, oc.TraceId)
		err := us.sessionStore.DeleteByRefresh(oc.Ctx, session.UserId, tokenData.FamilyId)
		if err != nil {
			us.logFailEvent(oc.Ctx, dm.EventGetSessionUserFailed, err.Error(), oc.Hexid, oc.TraceId)
		}
		return nil, &dm.ErrTokenReuseDetected

	case -1:
		us.logFailEvent(oc.Ctx, dm.EventGetSessionUserFailed, "Token reuse detected. Session has been revoked.",
			oc.Hexid, oc.TraceId)
		err := us.sessionStore.DeleteByRefresh(oc.Ctx, session.UserId, tokenData.FamilyId)
		if err != nil {
			us.logFailEvent(oc.Ctx, dm.EventGetSessionUserFailed, err.Error(), oc.Hexid, oc.TraceId)
		}
		return nil, &dm.ErrTokenReuseDetected

	case 0:
	default:
		us.logFailEvent(oc.Ctx, dm.EventGetSessionUserFailed, "fail compare version, returned an invalid value",
			oc.Hexid, oc.TraceId)
		return nil, &dm.ErrInternalServerError
	}

	// try get from grace periodic
	access, refresh, err := us.sessionStore.GetFromGracePeriodic(oc.Ctx, session.UserId, tokenData.FamilyId, newVer)
	if custerr.ErrGracePeriodicNoExists.Is(err) {

		newAccess, newRefresh, err := us.tokenUtil.GeneratePairToken(session.UserId, tokenData.FamilyId, session.DeviceId, session.Agent)
		if err != nil {
			us.logFailEvent(oc.Ctx, dm.EventGetSessionUserFailed, err.Error(), oc.Hexid, oc.TraceId)
			return nil, &dm.ErrInternalServerError
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
				return nil, &dm.ErrInternalServerError

			} else if custerr.ErrSuspiciousRefreshRate.Is(err) {

				err := us.sessionStore.DeleteByRefresh(oc.Ctx, session.UserId, tokenData.FamilyId)
				if err != nil {
					us.logFailEvent(oc.Ctx, dm.EventGetSessionUserFailed, err.Error(), oc.Hexid, oc.TraceId)
				}

				return nil, &dm.ErrTokenReuseDetected

			} else {
				return nil, &dm.ErrInternalServerError
			}

		}

		access = newAccess
		refresh = newRefresh

	} else if err != nil {

		us.logFailEvent(oc.Ctx, dm.EventGetSessionUserFailed, err.Error(), oc.Hexid, oc.TraceId)
		return nil, &dm.ErrInternalServerError
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

		errBody := dm.ErrBadRequest
		errBody.Code = "VALIDATION_ERROR"
		errBody.Message = "Username and password are required."

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
		errBody := dm.ErrConflictUsername
		errBody.Message = "Registration failed. Please check your details or try logging in."

		return nil, &errBody

	} else if dbErr != nil {
		us.logFailEvent(oc.Ctx, domain.EventRegistrationFailed, dbErr.Error(), "", oc.TraceId)
		return nil, &dm.ErrInternalServerError
	}

	id, ok := idDt.(uuid.UUID)
	if !ok {
		us.logFailEvent(oc.Ctx, domain.EventRegistrationFailed, "fail convert any in uuid", "", oc.TraceId)
		return nil, &dm.ErrInternalServerError
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

		errBody := dm.ErrBadRequest
		errBody.Code = "VALIDATION_ERROR"
		errBody.Message = "Username and password are required."

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

		errBody := dm.OperationError{
			Err:        "invalid_grant",
			Code:       "INVALID_CREDENTIALS",
			Message:    "Invalid username or password.",
			StatusCode: http.StatusUnauthorized,
		}

		return nil, &errBody

	} else if err != nil {
		us.logFailEvent(oc.Ctx, dm.EventLoginFailed, err.Error(), "", oc.TraceId)
		return nil, &dm.ErrInternalServerError
	}

	userFromDb, ok := userDt.(*domain.User)
	if !ok {
		us.logFailEvent(oc.Ctx, dm.EventLoginFailed, "Failed convert any user for *domain.User", "", oc.TraceId)
		return nil, &dm.ErrInternalServerError
	}

	if err := bcrypt.CompareHashAndPassword([]byte(userFromDb.Password), []byte(oc.UserData.Password)); err != nil {
		//add info event
		errBody := dm.OperationError{
			Err:        "invalid_grant",
			Code:       "INVALID_CREDENTIALS",
			Message:    "Invalid username or password.",
			StatusCode: http.StatusUnauthorized,
		}

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

func (us *UserService) GetUserData(oc *dm.OperationContext) (*dm.OperationUserData, *dm.OperationError) {

	var getFromDb = false
	var user *domain.User

	key := fmt.Sprintf("%s", oc.UserId)

	userFromCache, err := us.userCache.Get(oc.Ctx, oc.UserId)
	if err != nil {
		us.logFailEvent(oc.Ctx, dm.EventGetUserIntoCacheFailed, err.Error(), oc.Hexid, oc.TraceId)
	}

	if userFromCache != nil {
		user = userFromCache
	} else {

		userFromDb, err, _ := us.sgr.Do(key, func() (any, error) {
			userFromDb, err := us.userStore.GetByID(context.WithoutCancel(oc.Ctx), oc.UserId)
			return userFromDb, err
		})
		if postgres.ErrUserDontExist.Is(err) {
			return nil, &dm.ErrUserNotFound
		} else if err != nil {

			us.logFailEvent(oc.Ctx, dm.EventGetUser, err.Error(), oc.Hexid, oc.TraceId)
			return nil, &dm.ErrInternalServerError
		}

		if userFromDb != nil {
			user = userFromDb.(*domain.User)
			getFromDb = true
		} else {
			return nil, &dm.ErrUserNotFound
		}
	}

	if user.IsDeleted {
		return nil, &dm.ErrUserNotFound
	}

	if getFromDb {
		err = us.userCache.Set(oc.Ctx, user)
		if err != nil {
			us.logFailEvent(oc.Ctx, dm.EventSendUserIntoCacheFailed, err.Error(), oc.Hexid, oc.TraceId)
		}
	}

	oc.UserData = user

	rUser := dm.OperationUserData{
		Username:   user.UserName,
		Email:      user.Email,
		Phone:      user.Phone,
		CreatedAt:  user.CreatedAt,
		StatusCode: http.StatusOK,
	}

	return &rUser, nil
}

func (us *UserService) UpdateUserData(oc *dm.OperationContext, userOpt *dm.UserOpt) *dm.OperationError {

	if userOpt.UserName.Define && !userOpt.UserName.Valid {
		return &dm.ErrValidationUsernameRequired
	}

	hexid := hex.EncodeToString(oc.UserId[:])
	key := fmt.Sprintf("%s%s%s%s%v", hexid, userOpt.UserName.Value, userOpt.Email.Value,
		userOpt.Phone.Value, userOpt.IsDeleted.Value)

	_, err, _ := us.sgr.Do(key, func() (any, error) {
		err := us.userStore.Update(context.WithoutCancel(oc.Ctx), oc.UserId, userOpt)
		return nil, err
	})

	if postgres.ErrUserAlreadyExists.Is(err) {
		errWitnFields := err.(*repoerrors.RepoError)
		if slices.Contains(errWitnFields.Fields, "email") {
			return &dm.ErrConflictEmail
		} else if slices.Contains(errWitnFields.Fields, "phone") {
			return &dm.ErrConflictPhone
		} else if slices.Contains(errWitnFields.Fields, "username") {
			return &dm.ErrConflictUsername
		} else {
			us.logFailEvent(oc.Ctx, domain.EventUpdateUser, "err dont have fields", oc.Hexid, oc.TraceId)
			return &dm.ErrInternalServerError
		}

	} else if err != nil {
		us.logFailEvent(oc.Ctx, domain.EventUpdateUser, err.Error(), oc.Hexid, oc.TraceId)
		return &dm.ErrInternalServerError
	}

	err = us.userCache.Update(oc.Ctx, oc.UserId, userOpt)
	if err != nil {
		us.logFailEvent(oc.Ctx, domain.EventUpdateUser, err.Error(), oc.Hexid, oc.TraceId)
	}

	return nil
}

func (us *UserService) DeleteUser(oc *dm.OperationContext) *dm.OperationError {

	key := oc.Hexid
	_, err, _ := us.sgr.Do(key, func() (any, error) {
		err := us.userStore.Delete(context.WithoutCancel(oc.Ctx), oc.UserId)
		return nil, err
	})

	if err != nil {
		us.logFailEvent(oc.Ctx, domain.EventDeletedUser, err.Error(), oc.HashPass, oc.TraceId)
		return &dm.ErrInternalServerError
	}

	err = us.userCache.Del(oc.Ctx, oc.UserId)
	if err != nil {
		return &dm.ErrInternalServerError
	}

	err = us.sessionStore.DeleteAll(oc.Ctx, oc.UserId)
	if err != nil {
		strerr := err.Error()
		event := domain.NewFailedEvent(domain.EventDeleteSessionFailed, domain.EventPlaceHandler,
			&strerr, key, oc.TraceId)
		us.audit.Log(oc.Ctx, event)
	}

	return nil
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
		return &dm.ErrInternalServerError
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

		return "", "", &dm.ErrInternalServerError
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
		return &dm.ErrInternalServerError
	}

	hash, err := hashPassword(oc.UserData.Password)
	if err != nil {
		us.logFailEvent(oc.Ctx, eventType, err.Error(), "", oc.TraceId)
		return &dm.ErrInternalServerError
	}

	oc.HashPass = hash
	return nil
}
