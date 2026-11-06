package handler

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
	"user_service/config"
	"user_service/domain"
	"user_service/infrastructure/postgres"
	"user_service/infrastructure/reporedis/custerr"
	"user_service/infrastructure/tokens"
	"user_service/initial/middleware"
	"uuid"

	"github.com/vfaronov/httpheader"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/sync/singleflight"
)

const (
	GrantType    = "grant_type"
	RefreshToken = "refresh_token"

	HeadContentType   = "Content-Type"
	HeadUserAgent     = "User-Agent"
	HeadDeviceId      = "Device-Id"
	HeadCacheControle = "Cache-Control"
	HeadPragma        = "Pragma"
	HeadXForwardedFor = "X-Forwarded-For"
	HeadXRealIP       = "X-Real-IP"
	HeadForwarded     = "Forwarded"

	ValHeadAppJson      = "application/json"
	MaxRegistrationBody = 64 << 10 // 64 KiB
)

type ValidData struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
}

type AuthHandler struct {
	cm       *config.ConfigManager
	audit    domain.AuditService
	ss       domain.SessionStore
	tu       *tokens.TokenUtil
	sgr      singleflight.Group
	usBd     domain.UserStore
	fakePass []byte
}

type executionContext struct {
	ctx      context.Context
	traceId  string
	ip       string
	deviceId string
	agent    string
	user     *domain.User
	hexid    string
	hashPass string
	familyId uuid.UUID
}

func NewAuthHandler(cm *config.ConfigManager, audit domain.AuditService, ss domain.SessionStore, tu *tokens.TokenUtil,
	usBd domain.UserStore) *AuthHandler {
	// все условия соблюдены, единственная причина почему отвалился это не сработал rand с системными вызовами
	//	тогда в целом вся система не сможет работать корректно и коректно выдавать хеши пароль, ставим панику
	fakePass, err := bcrypt.GenerateFromPassword([]byte("fake_password"), 10)
	if err != nil {
		panic("failed generate fake password hash, system cannot work!!!")
	}

	return &AuthHandler{
		cm:       cm,
		audit:    audit,
		ss:       ss,
		tu:       tu,
		usBd:     usBd,
		fakePass: fakePass,
	}
}

func (ah *AuthHandler) UpdateRefreshToken(w http.ResponseWriter, r *http.Request) {

	ctx := r.Context()

	traceId, ok := ctx.Value(domain.TraceKey).(string)
	if !ok {
		traceId = ""
	}

	DeviceIdFromReq := r.Header.Get(HeadDeviceId)
	AgentFromReq := r.Header.Get(HeadUserAgent)
	if strings.TrimSpace(DeviceIdFromReq) == "" || strings.TrimSpace(AgentFromReq) == "" {
		sendBadrequest(w, traceId, "impotent field is empty", ctx, ah.audit)
		return
	}

	if err := r.ParseForm(); err != nil {
		strerr := err.Error()
		event := domain.NewFailedEvent(domain.EventUpdateVersionTokenFailed, domain.EventPlaceHandler,
			&strerr, "", traceId)
		ah.audit.Log(ctx, event)
		sendBadrequest(w, traceId, strerr, ctx, ah.audit)
		return
	}
	grantType := r.PostFormValue(GrantType)
	reftoken := r.PostFormValue(RefreshToken)

	if grantType != RefreshToken {
		strerr := "Field grant_type is not refresh_token."
		event := domain.NewFailedEvent(domain.EventUpdateVersionTokenFailed, domain.EventPlaceHandler,
			&strerr, "", traceId)
		ah.audit.Log(ctx, event)

		errBody := middleware.ErrBody{
			Err:     "bad request",
			Code:    "BAD_REQUEST",
			Message: "grant_type must be refresh_token.",
		}

		sendErr(w, errBody, traceId, "", ctx, http.StatusBadRequest, ah.audit)
		return
	}

	if reftoken == "" {
		strerr := "Field refresh_token is not exist."
		event := domain.NewFailedEvent(domain.EventUpdateVersionTokenFailed, domain.EventPlaceHandler,
			&strerr, "", traceId)
		ah.audit.Log(ctx, event)

		errBody := middleware.ErrBody{
			Err:     "invalid_request",
			Code:    "INVALID_REQUEST",
			Message: "refresh_token is required",
		}
		sendErr(w, errBody, traceId, "", ctx, http.StatusBadRequest, ah.audit)
		return
	}

	// check token validation
	tokenData, err := ah.tu.ValidRefreshToken(reftoken)
	if err != nil {

		strerr := err.Error()
		event := domain.NewFailedEvent(domain.EventUpdateVersionTokenFailed, domain.EventPlaceHandler,
			&strerr, "", traceId)
		ah.audit.Log(ctx, event)

		if tokens.ErrExpToken.Is(err) {
			httperr := middleware.ErrBody{
				Err:     "invalid_grant",
				Code:    "INVALID_GRANT",
				Message: "The refresh token has expired. Please re-authenticate.",
			}
			sendErr(w, httperr, traceId,
				`Bearer error="invalid_token", error_description="The access token expired"`,
				ctx, http.StatusBadRequest, ah.audit)
			return

		} else if tokens.ErrInvalidSignToken.Is(err) || tokens.ErrInvalidToken.Is(err) {
			sendInvalidToken(w, traceId, ctx, ah.audit)
			return

		} else if tokens.ErrFutureDateToken.Is(err) {
			httperr := middleware.ErrBody{
				Err:     "invalid_token",
				Code:    "INVALID_TOKEN",
				Message: "Token reuse detected. Session has been revoked.",
			}
			sendErr(w, httperr, traceId,
				`Bearer error="invalid_token", error_description="Token reuse detected. Session has been revoked."`,
				ctx, http.StatusBadRequest, ah.audit)

			err = ah.ss.DeleteByRefresh(ctx, tokenData.UserId, tokenData.FamilyId)
			if err != nil {
				strerr := err.Error()
				event := domain.NewFailedEvent(domain.EventUpdateVersionTokenFailed, domain.EventPlaceHandler,
					&strerr, "", traceId)
				ah.audit.Log(ctx, event)
			}
			return

		} else {
			sendIternalServerError(w, traceId, ctx, ah.audit)
			return

		}
	}

	newVer, err := tokens.UpdateVersion(tokenData.Version)
	if err != nil {

		strerr := err.Error()
		event := domain.NewFailedEvent(domain.EventUpdateVersionTokenFailed, domain.EventPlaceHandler,
			&strerr, "", traceId)
		ah.audit.Log(ctx, event)
		sendInvalidToken(w, traceId, ctx, ah.audit)
		return
	}

	session, err := ah.ss.GetSessionByFamilyId(ctx, tokenData.UserId, tokenData.FamilyId)
	if err != nil {
		strerr := err.Error()
		event := domain.NewFailedEvent(domain.EventGetSessionUserFailed, domain.EventPlaceHandler,
			&strerr, "", traceId)
		ah.audit.Log(ctx, event)

		if custerr.ErrBadArgs.Is(err) {
			sendInvalidToken(w, traceId, ctx, ah.audit)
			return
		} else if custerr.ErrNotFound.Is(err) {
			httperr := middleware.ErrBody{
				Err:     "invalid_token",
				Code:    "INVALID_TOKEN",
				Message: "The session is invalid or has been revoked.",
			}
			sendErr(w, httperr, traceId,
				`Bearer error="invalid_token", error_description="The session is invalid or has been revoked."`,
				ctx, http.StatusBadRequest, ah.audit)
			return
		} else {
			sendIternalServerError(w, traceId, ctx, ah.audit)
			return
		}

	}

	if session.DeviceId != DeviceIdFromReq || session.Agent != AgentFromReq {

		strerr := "impotant field dont equal session and header"
		event := domain.NewFailedEvent(domain.EventGetSessionUserFailed, domain.EventPlaceHandler,
			&strerr, hex.EncodeToString(session.UserId[:]), traceId)
		ah.audit.Log(ctx, event)

		httperr := middleware.ErrBody{
			Err:     "invalid_grant",
			Code:    "SESSION_CONTEXT_MISMATCH",
			Message: "Session context mismatch. Please log in again.",
		}
		sendErr(w, httperr, traceId,
			`Bearer error="invalid_grant", error_description="Session context mismatch. Please log in again."`,
			ctx, http.StatusBadRequest, ah.audit)

		err := ah.ss.DeleteByRefresh(ctx, session.UserId, tokenData.FamilyId)
		if err != nil {
			strerr := err.Error()
			event := domain.NewFailedEvent(domain.EventGetSessionUserFailed, domain.EventPlaceHandler,
				&strerr, hex.EncodeToString(session.UserId[:]), traceId)
			ah.audit.Log(ctx, event)
		}
		return
	}

	newVerFromSs, err := tokens.UpdateVersion(session.Version)
	if err != nil {
		strerr := err.Error()
		event := domain.NewFailedEvent(domain.EventGetSessionUserFailed, domain.EventPlaceHandler,
			&strerr, hex.EncodeToString(session.UserId[:]), traceId)
		ah.audit.Log(ctx, event)
		sendIternalServerError(w, traceId, ctx, ah.audit)
		return
	}

	// check version from session and token
	compareResult, err := tokens.CompareVersions(newVer, newVerFromSs)
	if err != nil {
		strerr := "fail compare version, invalid version"
		event := domain.NewFailedEvent(domain.EventGetSessionUserFailed, domain.EventPlaceHandler,
			&strerr, hex.EncodeToString(session.UserId[:]), traceId)
		ah.audit.Log(ctx, event)
		sendIternalServerError(w, traceId, ctx, ah.audit)
		return
	}
	isError := false
	var errBody middleware.ErrBody
	var errMes string

	switch compareResult {
	case 1:
		isError = true

		errBody.Err = "invalid_grant"
		errBody.Code = "FUTURE_TOKEN_DETECTED"
		errBody.Message = "Token version conflict. Session has been revoked."
		errMes = "Token from the future detected. Incoming version > session version. Session revoked." // Внутренний лог для разработчиков/Security

	case -1:
		isError = true

		errBody.Err = "invalid_grant"
		errBody.Code = "TOKEN_REUSE_DETECTED"
		errBody.Message = "Token reuse detected. Session has been revoked."
		errMes = "Token reuse detected. Session has been revoked."

	case 0:
	default:
		strerr := "fail compare version, returned an invalid value"
		event := domain.NewFailedEvent(domain.EventGetSessionUserFailed, domain.EventPlaceHandler,
			&strerr, hex.EncodeToString(session.UserId[:]), traceId)
		ah.audit.Log(ctx, event)
		sendIternalServerError(w, traceId, ctx, ah.audit)
		return
	}

	if isError {
		strerr := errMes
		event := domain.NewFailedEvent(domain.EventGetSessionUserFailed, domain.EventPlaceHandler,
			&strerr, hex.EncodeToString(session.UserId[:]), traceId)
		ah.audit.Log(ctx, event)

		sendErr(w, errBody, traceId,
			fmt.Sprintf(`Bearer error="invalid_token", error_description="%v"`, errBody.Message),
			ctx, http.StatusBadRequest, ah.audit)

		err := ah.ss.DeleteByRefresh(ctx, session.UserId, tokenData.FamilyId)
		if err != nil {
			strerr := err.Error()
			event := domain.NewFailedEvent(domain.EventGetSessionUserFailed, domain.EventPlaceHandler,
				&strerr, hex.EncodeToString(session.UserId[:]), traceId)
			ah.audit.Log(ctx, event)
		}
		return
	}

	// try get from grace periodic
	access, refresh, err := ah.ss.GetFromGracePeriodic(ctx, session.UserId, tokenData.FamilyId, newVer)
	if custerr.ErrGracePeriodicNoExists.Is(err) {

		newAccess, newRefresh, err := ah.tu.GeneratePairToken(session.UserId, tokenData.FamilyId, session.DeviceId, session.Agent)
		if err != nil {
			strerr := err.Error()
			event := domain.NewFailedEvent(domain.EventGetSessionUserFailed, domain.EventPlaceHandler,
				&strerr, hex.EncodeToString(session.UserId[:]), traceId)
			ah.audit.Log(ctx, event)
			sendIternalServerError(w, traceId, ctx, ah.audit)
			return
		}

		gracePeriodic := domain.GracePeriodic{
			Version: newVer,
			Access:  newAccess,
			Refresh: newRefresh,
		}

		// if grace no exist then create
		err = ah.ss.CreateGracePeriodic(ctx, session.UserId, tokenData.FamilyId, &gracePeriodic)
		if err != nil {

			strerr := err.Error()
			event := domain.NewFailedEvent(domain.EventGetSessionUserFailed, domain.EventPlaceHandler,
				&strerr, hex.EncodeToString(session.UserId[:]), traceId)
			ah.audit.Log(ctx, event)

			if custerr.ErrGracePeriodicAlredyExist.Is(err) {

				sendIternalServerError(w, traceId, ctx, ah.audit)
				return

			} else if custerr.ErrSuspiciousRefreshRate.Is(err) {

				httperr := middleware.ErrBody{
					Err:     "invalid_grant",
					Code:    "TOKEN_REUSE_DETECTED",
					Message: "Token reuse detected. Session has been revoked.",
				}
				sendErr(w, httperr, traceId,
					`Bearer error="invalid_token", error_description="Token reuse detected. Session has been revoked."`,
					ctx, http.StatusBadRequest, ah.audit)

				err := ah.ss.DeleteByRefresh(ctx, session.UserId, tokenData.FamilyId)
				if err != nil {
					strerr := err.Error()
					event := domain.NewFailedEvent(domain.EventGetSessionUserFailed, domain.EventPlaceHandler,
						&strerr, hex.EncodeToString(session.UserId[:]), traceId)
					ah.audit.Log(ctx, event)
				}
				return

			} else {
				sendIternalServerError(w, traceId, ctx, ah.audit)
				return
			}

		}

		access = newAccess
		refresh = newRefresh
	} else if err != nil {
		strerr := err.Error()
		event := domain.NewFailedEvent(domain.EventGetSessionUserFailed, domain.EventPlaceHandler,
			&strerr, hex.EncodeToString(session.UserId[:]), traceId)
		ah.audit.Log(ctx, event)
		sendIternalServerError(w, traceId, ctx, ah.audit)
		return
	}

	validData := ValidData{
		AccessToken:  access,
		TokenType:    "Bearer",
		ExpiresIn:    int(ah.cm.Get().TokenConf.AccessLifeTime) * 60,
		RefreshToken: refresh,
	}

	jsonData, err := json.Marshal(&validData)
	if err != nil {
		strerr := err.Error()
		event := domain.NewFailedEvent(domain.EventGetSessionUserFailed, domain.EventPlaceHandler,
			&strerr, hex.EncodeToString(session.UserId[:]), traceId)
		ah.audit.Log(ctx, event)
		sendIternalServerError(w, traceId, ctx, ah.audit)
		return
	}

	event := domain.NewSuccessEvent(domain.EventGetSessionUserSuccess, domain.EventPlaceHandler,
		hex.EncodeToString(session.UserId[:]), traceId)
	ah.audit.Log(ctx, event)

	w.Header().Add(HeadContentType, ValHeadAppJson)
	w.Header().Set(HeadCacheControle, "no-store")
	w.Header().Set(HeadPragma, "no-cache")
	w.WriteHeader(http.StatusOK)
	w.Write(jsonData)
}

func (ah *AuthHandler) RegistrationUser(w http.ResponseWriter, r *http.Request) {

	ec, toReturn := ah.validateCheck(w, r, domain.EventRegistrationFailed)
	if toReturn {
		return
	}

	if strings.TrimSpace(ec.user.UserName) == "" || strings.TrimSpace(ec.user.Password) == "" {
		err := "The request is missing important fields."
		event := domain.NewFailedEvent(domain.EventRegistrationFailed, domain.EventPlaceHandler, &err, "", ec.traceId)
		ah.audit.Log(ec.ctx, event)

		errBody := middleware.ErrBody{
			Err:     "invalid_request",
			Code:    "VALIDATION_ERROR",
			Message: "Username and password are required.",
		}
		sendErr(w, errBody, ec.traceId, "", ec.ctx, http.StatusBadRequest, ah.audit)
		return
	}

	toReturn = ah.addPasswordHashInExContext(w, ec, domain.EventRegistrationFailed)
	if toReturn {
		return
	}

	ec.user.Password = ec.hashPass

	key := fmt.Sprintf("%s%s%s", ec.user.UserName, ec.user.Email, ec.user.Phone)

	idDt, err, _ := ah.sgr.Do(key, func() (any, error) {
		id, err := ah.usBd.Create(ec.ctx, ec.user)
		return id, err
	})

	if postgres.ErrUserAlreadyExists.Is(err) {
		// add info event
		errBody := middleware.ErrBody{
			Err:     "conflict",
			Code:    "REGISTRATION_FAILED",
			Message: "Registration failed. Please check your details or try logging in.",
		}
		sendErr(w, errBody, ec.traceId, "", ec.ctx, http.StatusConflict, ah.audit)
		return

	} else if err != nil {
		strerr := err.Error()
		event := domain.NewFailedEvent(domain.EventRegistrationFailed, domain.EventPlaceHandler, &strerr, "", ec.traceId)
		ah.audit.Log(ec.ctx, event)
		sendIternalServerError(w, ec.traceId, ec.ctx, ah.audit)
		return
	}

	id, ok := idDt.(uuid.UUID)
	if !ok {
		strerr := "fail convert any in uuid"
		event := domain.NewFailedEvent(domain.EventRegistrationFailed, domain.EventPlaceHandler, &strerr, "", ec.traceId)
		ah.audit.Log(ec.ctx, event)
		sendIternalServerError(w, ec.traceId, ec.ctx, ah.audit)
		return
	}

	hexId := hex.EncodeToString(id[:])
	ec.hexid = hexId
	ec.user.Id = id

	toReturn = ah.regSession(w, ec, domain.EventRegistrationFailed)
	if toReturn {
		return
	}

	access, refresh, toReturn := ah.genTokens(w, ec, domain.EventRegistrationFailed)
	if toReturn {
		return
	}

	jsonBytes, toReturn := ah.makeBodyWithTokens(w, ec, access, refresh, domain.EventRegistrationFailed)
	if toReturn {
		return
	}

	event := domain.NewSuccessEvent(domain.EventRegistrationSucces, domain.EventPlaceHandler, hexId, ec.traceId)
	ah.audit.Log(ec.ctx, event)

	w.Header().Add(HeadContentType, ValHeadAppJson)
	w.Header().Add(HeadCacheControle, "no-store")
	w.Header().Add(HeadPragma, "no-cache")
	w.WriteHeader(http.StatusCreated)
	w.Write(jsonBytes)
}

func (ah *AuthHandler) SingIn(w http.ResponseWriter, r *http.Request) {

	ec, toReturn := ah.validateCheck(w, r, domain.EventLoginFailed)
	if toReturn {
		return
	}

	if !(strings.TrimSpace(ec.user.UserName) != "" || strings.TrimSpace(ec.user.Email) != "" || strings.TrimSpace(ec.user.Phone) != "") ||
		strings.TrimSpace(ec.user.Password) == "" {
		err := "The request is missing important fields."
		event := domain.NewFailedEvent(domain.EventLoginFailed, domain.EventPlaceHandler, &err, "", ec.traceId)
		ah.audit.Log(ec.ctx, event)

		errBody := middleware.ErrBody{
			Err:     "invalid_request",
			Code:    "VALIDATION_ERROR",
			Message: "Username and password are required.",
		}
		sendErr(w, errBody, ec.traceId, "", ec.ctx, http.StatusBadRequest, ah.audit)
		return
	}

	userOpt := domain.ToUserOpt(ec.user)

	key := fmt.Sprintf("%s%s%s", ec.user.UserName, ec.user.Email, ec.user.Phone)

	userDt, err, _ := ah.sgr.Do(key, func() (any, error) {
		trueUser, err := ah.usBd.GetByOpt(ec.ctx, userOpt)
		return trueUser, err
	})

	if postgres.ErrUserDontExist.Is(err) {
		// fake time work
		_ = bcrypt.CompareHashAndPassword(ah.fakePass, []byte(ec.user.Password))
		//add info event
		errBody := middleware.ErrBody{
			Err:     "invalid_grant",
			Code:    "INVALID_CREDENTIALS",
			Message: "Invalid username or password.",
		}
		sendErr(w, errBody, ec.traceId, "", ec.ctx, http.StatusUnauthorized, ah.audit)
		return

	} else if err != nil {
		strerr := err.Error()
		event := domain.NewFailedEvent(domain.EventLoginFailed, domain.EventPlaceHandler, &strerr, "", ec.traceId)
		ah.audit.Log(ec.ctx, event)

		sendIternalServerError(w, ec.traceId, ec.ctx, ah.audit)
		return
	}

	userFromDb, ok := userDt.(*domain.User)
	if !ok {
		strerr := "Failed convert any user for *domain.User"
		event := domain.NewFailedEvent(domain.EventLoginFailed, domain.EventPlaceHandler, &strerr, "", ec.traceId)
		ah.audit.Log(ec.ctx, event)

		sendIternalServerError(w, ec.traceId, ec.ctx, ah.audit)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(userFromDb.Password), []byte(ec.user.Password)); err != nil {
		//add info event
		errBody := middleware.ErrBody{
			Err:     "invalid_grant",
			Code:    "INVALID_CREDENTIALS",
			Message: "Invalid username or password.",
		}
		sendErr(w, errBody, ec.traceId, "", ec.ctx, http.StatusUnauthorized, ah.audit)
		return
	}

	id := userFromDb.Id
	hexId := hex.EncodeToString(id[:])
	ec.hexid = hexId

	toReturn = ah.regSession(w, ec, domain.EventLoginFailed)
	if toReturn {
		return
	}

	access, refresh, toReturn := ah.genTokens(w, ec, domain.EventLoginFailed)
	if toReturn {
		return
	}

	jsonBytes, toReturn := ah.makeBodyWithTokens(w, ec, access, refresh, domain.EventLoginFailed)
	if toReturn {
		return
	}

	event := domain.NewSuccessEvent(domain.EventLoginSucces, domain.EventPlaceHandler, hexId, ec.traceId)
	ah.audit.Log(ec.ctx, event)

	w.Header().Add(HeadContentType, ValHeadAppJson)
	w.Header().Add(HeadCacheControle, "no-store")
	w.Header().Add(HeadPragma, "no-cache")
	w.WriteHeader(http.StatusOK)
	w.Write(jsonBytes)
}

func (ah *AuthHandler) validateCheck(w http.ResponseWriter, r *http.Request, failEvent domain.EventType) (*executionContext, bool) {

	ec := &executionContext{}

	ctx := r.Context()
	traceId, ok := ctx.Value(domain.TraceKey).(string)
	if !ok {
		traceId = ""
	}

	ec.ctx = ctx
	ec.traceId = traceId

	contentType, _ := httpheader.ContentType(r.Header)
	if contentType != ValHeadAppJson {
		err := "Unsupported media type."
		event := domain.NewFailedEvent(failEvent, domain.EventPlaceHandler, &err, "", traceId)
		ah.audit.Log(ctx, event)

		errBody := middleware.ErrBody{
			Err:     "invalid_body",
			Code:    "INVALID_BODY",
			Message: "Unsupported Media Type",
		}

		sendErr(w, errBody, traceId, "", ctx, http.StatusUnsupportedMediaType, ah.audit)
		return nil, true
	}

	IP, err := getIp(r)
	if err != nil {
		err := "The request is missing important fields."
		event := domain.NewFailedEvent(failEvent, domain.EventPlaceHandler, &err, "", traceId)
		ah.audit.Log(ctx, event)

		sendBadrequest(w, traceId, err, ctx, ah.audit)
		return nil, true
	}

	ec.ip = IP

	DeviceId := r.Header.Get(HeadDeviceId)
	Agent := r.Header.Get(HeadUserAgent)

	if IP == "" || DeviceId == "" || Agent == "" {
		err := "The request is missing important fields."
		event := domain.NewFailedEvent(failEvent, domain.EventPlaceHandler, &err, "", traceId)
		ah.audit.Log(ctx, event)

		sendBadrequest(w, traceId, err, ctx, ah.audit)
		return nil, true
	}

	ec.deviceId = DeviceId
	ec.agent = Agent

	r.Body = http.MaxBytesReader(w, r.Body, MaxRegistrationBody)
	jsonData, err := io.ReadAll(r.Body)
	if err != nil {

		strerr := err.Error()
		event := domain.NewFailedEvent(failEvent, domain.EventPlaceHandler, &strerr, "", traceId)
		ah.audit.Log(ctx, event)

		sendBadrequest(w, traceId, "The request body contains invalid or missing fields.", ctx, ah.audit)
		return nil, true
	}

	var user domain.User
	err = json.Unmarshal(jsonData, &user)
	if err != nil {

		strerr := err.Error()
		event := domain.NewFailedEvent(failEvent, domain.EventPlaceHandler, &strerr, "", traceId)
		ah.audit.Log(ctx, event)

		sendBadrequest(w, traceId, "The request body contains invalid or missing fields.", ctx, ah.audit)
		return nil, true
	}

	ec.user = &user

	return ec, false
}

func (ah *AuthHandler) addPasswordHashInExContext(w http.ResponseWriter, ec *executionContext, eventType domain.EventType) bool {
	if ec.user == nil {
		return true
	}

	hash, err := hashPassword(ec.user.Password)
	if err != nil {
		strerr := err.Error()
		event := domain.NewFailedEvent(eventType, domain.EventPlaceHandler, &strerr, "", ec.traceId)
		ah.audit.Log(ec.ctx, event)

		sendIternalServerError(w, ec.traceId, ec.ctx, ah.audit)
		return true
	}

	ec.hashPass = hash

	return false
}

func (ah *AuthHandler) regSession(w http.ResponseWriter, ec *executionContext, eventType domain.EventType) bool {

	familyId := uuid.NewV7()
	ec.familyId = familyId
	session := domain.Session{
		UserId:     ec.user.Id,
		DeviceId:   ec.deviceId,
		Agent:      ec.agent,
		Ip:         ec.ip,
		Version:    tokens.FirstVersion,
		CreatedAt:  time.Now(),
		LastUpdate: time.Now(),
	}

	err := ah.ss.Registration(ec.ctx, &session, familyId)
	if err != nil {

		strerr := err.Error()
		event := domain.NewFailedEvent(eventType, domain.EventPlaceHandler, &strerr, ec.hexid, ec.traceId)
		ah.audit.Log(ec.ctx, event)

		sendIternalServerError(w, ec.traceId, ec.ctx, ah.audit)
		return true
	}

	return false
}

func (ah *AuthHandler) genTokens(w http.ResponseWriter, ec *executionContext, eventType domain.EventType) (string, string, bool) {
	access, refresh, err := ah.tu.GeneratePairToken(ec.user.Id, ec.familyId, ec.deviceId, ec.agent)
	if err != nil {

		cherr := ah.rollbackForCache(ec.ctx, ec.user.Id, ec.familyId)
		if cherr != nil {
			strerr := cherr.Error()
			event := domain.NewFailedEvent(eventType, domain.EventPlaceHandler, &strerr, ec.hexid, ec.traceId)
			ah.audit.Log(ec.ctx, event)
		}

		strerr := err.Error()
		event := domain.NewFailedEvent(eventType, domain.EventPlaceHandler, &strerr, ec.hexid, ec.traceId)
		ah.audit.Log(ec.ctx, event)

		sendIternalServerError(w, ec.traceId, ec.ctx, ah.audit)
		return "", "", true
	}

	return access, refresh, false
}

func (ah *AuthHandler) makeBodyWithTokens(w http.ResponseWriter, ec *executionContext, access, refresh string, eventType domain.EventType) ([]byte, bool) {

	validData := ValidData{
		AccessToken:  access,
		TokenType:    "Bearer",
		ExpiresIn:    ah.cm.Get().TokenConf.AccessLifeTime * 60,
		RefreshToken: refresh,
	}

	jsonBytes, err := json.Marshal(validData)
	if err != nil {

		cherr := ah.rollbackForCache(ec.ctx, ec.user.Id, ec.familyId)
		if cherr != nil {
			strerr := cherr.Error()
			event := domain.NewFailedEvent(eventType, domain.EventPlaceHandler, &strerr, ec.hexid, ec.traceId)
			ah.audit.Log(ec.ctx, event)
		}

		strerr := err.Error()
		event := domain.NewFailedEvent(eventType, domain.EventPlaceHandler, &strerr, ec.hexid, ec.traceId)
		ah.audit.Log(ec.ctx, event)

		sendIternalServerError(w, ec.traceId, ec.ctx, ah.audit)
		return nil, true
	}

	return jsonBytes, false
}

func sendErr(w http.ResponseWriter, errBody middleware.ErrBody, traceId, wwwErr string, ctx context.Context, code int,
	audit domain.AuditService) {

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
		w.Header().Set(middleware.HeadWWWAuthenticate, wwwErr)
	}

	w.Header().Set(middleware.HeadContentType, middleware.ValHeadAppJson)

	w.WriteHeader(code)
	w.Write(jsonBt)
}

func sendIternalServerError(w http.ResponseWriter, traceId string, ctx context.Context, audit domain.AuditService) {
	httperr := middleware.ErrBody{
		Err:     "Internal Server Error",
		Code:    "AUTH_SERVICE_ERROR",
		Message: "Authentication service is temporarily unavailable. Please try again later.",
	}
	sendErr(w, httperr, traceId, "", ctx, http.StatusInternalServerError, audit)
}

func sendBadrequest(w http.ResponseWriter, traceId, errstr string, ctx context.Context, audit domain.AuditService) {
	httperr := middleware.ErrBody{
		Err:     "bad request",
		Code:    "BAD_REQUEST",
		Message: errstr,
	}
	sendErr(w, httperr, traceId, "", ctx, http.StatusBadRequest, audit)
}

func sendInvalidToken(w http.ResponseWriter, traceId string, ctx context.Context, audit domain.AuditService) {
	httperr := middleware.ErrBody{
		Err:     "invalid_token",
		Code:    "INVALID_TOKEN",
		Message: "The token is invalid or malformed.",
	}
	sendErr(w, httperr, traceId,
		`Bearer error="invalid_token", error_description="The token is invalid or malformed."`,
		ctx, http.StatusBadRequest, audit)
}

func hashPassword(password string) (string, error) {

	hash, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	if err != nil {
		return "", err
	}

	return string(hash), nil
}

func (ah *AuthHandler) rollbackForCache(ctx context.Context, userId, familyId uuid.UUID) error {
	err := ah.ss.DeleteByRefresh(ctx, userId, familyId)
	return err
}

func getIp(r *http.Request) (string, error) {

	xForwardedFor := r.Header.Get(HeadXForwardedFor)
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

	IP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return "", err
	}

	return IP, nil
}
