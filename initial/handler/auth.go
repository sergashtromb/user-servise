package handler

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"time"
	"user_service/config"
	"user_service/domain"
	"user_service/infrastructure/postgres"
	"user_service/infrastructure/reporedis/custerr"
	"user_service/infrastructure/tokens"
	"user_service/initial/middleware"
	"user_service/pkg/repoerrors"
	"user_service/service"
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
	HeadCacheControle = "Cache-Control"
	HeadPragma        = "Pragma"
	HeadXForwardedFor = "X-Forwarded-For"
	HeadXRealIP       = "X-Real-IP"
	HeadForwarded     = "Forwarded"
	Bearer            = "bearer "

	CookieDeviceId = "DeviceId"

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
	usCh     domain.UserCacheStore
	us       *service.UserService
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
	userId   uuid.UUID
}

var NotFoundBody = middleware.ErrBody{
	Err:     "not_found",
	Code:    "USER_NOT_FOUND",
	Message: "User not found or has been deleted.",
}

func NewAuthHandler(cm *config.ConfigManager, audit domain.AuditService, ss domain.SessionStore, tu *tokens.TokenUtil,
	usBd domain.UserStore, usCh domain.UserCacheStore, us *service.UserService) *AuthHandler {
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
		usCh:     usCh,
		fakePass: fakePass,
		us:       us,
	}
}

func (ah *AuthHandler) UpdateRefreshToken(w http.ResponseWriter, r *http.Request) {

	oc := getOpContextFromReq(r)

	deviceId, agentFromReq, err := parseDeviceIdAndAgent(r)
	if err != nil {
		sendBadrequest(w, oc.TraceId, err.Error(), oc.Ctx, ah.audit)
		return
	}

	oc.DeviceId = deviceId
	oc.Agent = agentFromReq

	if err := r.ParseForm(); err != nil {
		ah.logFailedEvent(oc.Ctx, domain.EventUpdateVersionTokenFailed, err.Error(), "", oc.TraceId)
		sendBadrequest(w, oc.TraceId, err.Error(), oc.Ctx, ah.audit)
		return
	}
	grantType := r.PostFormValue(GrantType)
	reftoken := r.PostFormValue(RefreshToken)

	if grantType != RefreshToken {
		ah.logFailedEvent(oc.Ctx, domain.EventUpdateVersionTokenFailed, "Field grant_type is not refresh_token.",
			"", oc.TraceId)

		errBody := middleware.ErrBody{
			Err:     "bad request",
			Code:    "BAD_REQUEST",
			Message: "grant_type must be refresh_token.",
		}

		sendErr(w, errBody, oc.TraceId, "", oc.Ctx, http.StatusBadRequest, ah.audit)
		return
	}

	if reftoken == "" {
		ah.logFailedEvent(oc.Ctx, domain.EventUpdateVersionTokenFailed, "Field refresh_token is not exist.",
			"", oc.TraceId)

		errBody := middleware.ErrBody{
			Err:     "invalid_request",
			Code:    "INVALID_REQUEST",
			Message: "refresh_token is required",
		}
		sendErr(w, errBody, oc.TraceId, "", oc.Ctx, http.StatusBadRequest, ah.audit)
		return
	}

	// check token validation
	validData, errBody := ah.us.UpdateRefreshToken(oc, reftoken)
	if errBody != nil {
		ah.sendErrBody(w, errBody, oc)
		return
	}

	jsonData, err := json.Marshal(&validData)
	if err != nil {
		ah.logFailedEvent(oc.Ctx, domain.EventGetSessionUserFailed, err.Error(), oc.Hexid, oc.TraceId)
		sendIternalServerError(w, oc.TraceId, oc.Ctx, ah.audit)
		return
	}

	event := domain.NewSuccessEvent(domain.EventGetSessionUserSuccess, domain.EventPlaceHandler,
		oc.Hexid, oc.TraceId)
	ah.audit.Log(oc.Ctx, event)

	w.Header().Add(HeadContentType, ValHeadAppJson)
	w.Header().Set(HeadCacheControle, "no-store")
	w.Header().Set(HeadPragma, "no-cache")
	w.WriteHeader(http.StatusOK)
	w.Write(jsonData)
}

func (ah *AuthHandler) RegistrationUser(w http.ResponseWriter, r *http.Request) {

	ctx := r.Context()
	oc, ok := ctx.Value(domain.OperCtxKey).(*domain.OperationContext)
	if !ok {
		ah.logFailedEvent(ctx, domain.EventRegistrationFailed, "request don't have operation context",
			"", "")
		sendIternalServerError(w, "", ctx, ah.audit)
		return
	}

	toReturn := ah.getUserFromBody(w, r, oc, domain.EventRegistrationFailed)
	if toReturn {
		return
	}

	tokens, errOp := ah.us.RegistrationUser(oc)
	if errOp != nil {
		ah.sendErrBody(w, errOp, oc)
		return
	}

	jsonBytes, err := json.Marshal(&tokens)
	if err != nil {
		ah.logFailedEvent(oc.Ctx, domain.EventRegistrationFailed, err.Error(), "", oc.TraceId)
		sendIternalServerError(w, oc.TraceId, oc.Ctx, ah.audit)
		return
	}

	event := domain.NewSuccessEvent(domain.EventRegistrationSucces, domain.EventPlaceHandler, oc.Hexid, oc.TraceId)
	ah.audit.Log(oc.Ctx, event)

	w.Header().Add(HeadContentType, ValHeadAppJson)
	w.Header().Add(HeadCacheControle, "no-store")
	w.Header().Add(HeadPragma, "no-cache")
	w.WriteHeader(http.StatusCreated)
	w.Write(jsonBytes)
}

// FIXME refactor
func (ah *AuthHandler) SingIn(w http.ResponseWriter, r *http.Request) {

	ctx := r.Context()
	oc, ok := ctx.Value(domain.OperCtxKey).(*domain.OperationContext)
	if !ok {
		ah.logFailedEvent(ctx, domain.EventLoginFailed, "request don't have operation context",
			"", "")
		sendIternalServerError(w, "", ctx, ah.audit)
		return
	}

	toReturn := ah.getUserFromBody(w, r, oc, domain.EventLoginFailed)
	if toReturn {
		return
	}

	tokens, errBody := ah.us.SingIn(oc)
	if errBody != nil {
		ah.sendErrBody(w, errBody, oc)
		return
	}

	jsonBytes, err := json.Marshal(tokens)
	if err != nil {
		ah.logFailedEvent(ctx, domain.EventLoginFailed, err.Error(),
			"", oc.TraceId)
		sendIternalServerError(w, oc.TraceId, oc.Ctx, ah.audit)
		return
	}

	event := domain.NewSuccessEvent(domain.EventLoginSucces, domain.EventPlaceHandler, oc.Hexid, oc.TraceId)
	ah.audit.Log(oc.Ctx, event)

	w.Header().Add(HeadContentType, ValHeadAppJson)
	w.Header().Add(HeadCacheControle, "no-store")
	w.Header().Add(HeadPragma, "no-cache")
	w.WriteHeader(http.StatusOK)
	w.Write(jsonBytes)
}

// FIXME refactor
func (ah *AuthHandler) Authentication(w http.ResponseWriter, r *http.Request) {

	_, toReturn := ah.checkAuth(w, r)
	if toReturn {
		return
	}

	w.WriteHeader(http.StatusOK)
}

// FIXME refactor
func (ah *AuthHandler) GetUserData(w http.ResponseWriter, r *http.Request) {

	ex, toReturn := ah.checkAuth(w, r)
	if toReturn {
		return
	}

	var getFromDb = false
	var user *domain.User

	key := fmt.Sprintf("%s", ex.userId)

	userFromCache, err := ah.usCh.Get(ex.ctx, ex.userId)
	if err != nil {
		strerr := err.Error()
		event := domain.NewFailedEvent(domain.EventGetUserIntoCacheFailed, domain.EventPlaceHandler, &strerr, "", ex.traceId)
		ah.audit.Log(ex.ctx, event)
	}

	if userFromCache != nil {
		user = userFromCache
	} else {

		userFromDb, err, _ := ah.sgr.Do(key, func() (any, error) {
			userFromDb, err := ah.usBd.GetByID(ex.ctx, ex.userId)
			return userFromDb, err
		})
		if postgres.ErrUserDontExist.Is(err) {

			sendErr(w, NotFoundBody, ex.traceId, "", ex.ctx, http.StatusNotFound, ah.audit)
			return
		} else if err != nil {

			strerr := err.Error()
			event := domain.NewFailedEvent(domain.EventGetUser, domain.EventPlaceHandler, &strerr, "", ex.traceId)
			ah.audit.Log(ex.ctx, event)
			sendIternalServerError(w, ex.traceId, ex.ctx, ah.audit)
			return
		}

		if userFromDb != nil {
			user = userFromDb.(*domain.User)
			getFromDb = true
		} else {
			sendErr(w, NotFoundBody, ex.traceId, "", ex.ctx, http.StatusNotFound, ah.audit)
			return
		}
	}

	if user.IsDeleted {
		sendErr(w, NotFoundBody, ex.traceId, "", ex.ctx, http.StatusNotFound, ah.audit)
		return
	}

	if getFromDb {
		err = ah.usCh.Set(ex.ctx, user)
		if err != nil {
			strerr := err.Error()
			event := domain.NewFailedEvent(domain.EventSendUserIntoCacheFailed, domain.EventPlaceHandler, &strerr, "", ex.traceId)
			ah.audit.Log(ex.ctx, event)
		}
	}

	data := map[string]interface{}{
		"username":   user.UserName,
		"phone":      user.Phone,
		"email":      user.Email,
		"created_at": user.CreatedAt,
	}

	jsonData, err := json.Marshal(&data)
	if err != nil {
		strerr := err.Error()
		event := domain.NewFailedEvent(domain.EventGetUser, domain.EventPlaceHandler, &strerr, "", ex.traceId)
		ah.audit.Log(ex.ctx, event)
		sendIternalServerError(w, ex.traceId, ex.ctx, ah.audit)
		return
	}

	w.Header().Add(HeadContentType, ValHeadAppJson)
	w.Header().Add(HeadCacheControle, "no-store")
	w.Header().Add(HeadPragma, "no-cache")

	w.WriteHeader(http.StatusOK)
	w.Write(jsonData)
}

// FIXME refactor
func (ah *AuthHandler) UpdateUserData(w http.ResponseWriter, r *http.Request) {

	ec, toReturn := ah.checkAuth(w, r)
	if toReturn {
		return
	}

	jsonBody, err := io.ReadAll(r.Body)
	if err != nil {
		sendBadrequest(w, ec.traceId, "The request body contains invalid or missing fields.", ec.ctx, ah.audit)
		return
	}

	var userOpt domain.UserOpt
	err = json.Unmarshal(jsonBody, &userOpt)
	if err != nil {
		sendBadrequest(w, ec.traceId, "The request body contains invalid or missing fields.", ec.ctx, ah.audit)
		return
	}

	if !userOpt.UserName.Define && !userOpt.Email.Define && !userOpt.Phone.Define && !userOpt.IsDeleted.Define {
		errBody := middleware.ErrBody{
			Err:     "bad request",
			Code:    "BAD_REQUEST",
			Message: "The request body contains invalid or missing fields.",
		}
		sendErr(w, errBody, ec.traceId, "", ec.ctx, http.StatusBadRequest, ah.audit)
		return
	}

	if userOpt.UserName.Define && !userOpt.UserName.Valid {
		errBody := middleware.ErrBody{
			Err:     "invalid_request",
			Code:    "VALIDATION_ERROR",
			Message: "Username cannot be null or empty.",
		}
		sendErr(w, errBody, ec.traceId, "", ec.ctx, http.StatusBadRequest, ah.audit)
		return
	}

	hexid := hex.EncodeToString(ec.userId[:])
	key := fmt.Sprintf("%s%s%s%s%v", hexid, userOpt.UserName.Value, userOpt.Email.Value,
		userOpt.Phone.Value, userOpt.IsDeleted.Value)

	_, err, _ = ah.sgr.Do(key, func() (any, error) {
		err := ah.usBd.Update(ec.ctx, ec.userId, &userOpt)
		return nil, err
	})

	if postgres.ErrUserAlreadyExists.Is(err) {
		errBody := middleware.ErrBody{
			Err:  "conflict",
			Code: "CONFLICT",
		}

		errWitnFields := err.(*repoerrors.RepoError)
		if slices.Contains(errWitnFields.Fields, "email") {
			errBody.Message = "The email is already in use by another user."
		} else if slices.Contains(errWitnFields.Fields, "phone") {
			errBody.Message = "The phone is already in use by another user."
		} else if slices.Contains(errWitnFields.Fields, "username") {
			errBody.Message = "The username is already in use by another user."
		} else {
			strerr := "err dont have fields"
			event := domain.NewFailedEvent(domain.EventUpdateUser, domain.EventPlaceHandler, &strerr,
				hexid, ec.traceId)
			ah.audit.Log(ec.ctx, event)
			sendIternalServerError(w, ec.traceId, ec.ctx, ah.audit)
			return
		}

		sendErr(w, errBody, ec.traceId, "", ec.ctx, http.StatusConflict, ah.audit)
		return

	} else if err != nil {
		strerr := err.Error()
		event := domain.NewFailedEvent(domain.EventUpdateUser, domain.EventPlaceHandler, &strerr,
			hexid, ec.traceId)
		ah.audit.Log(ec.ctx, event)
		sendIternalServerError(w, ec.traceId, ec.ctx, ah.audit)
		return
	}

	err = ah.usCh.Update(ec.ctx, ec.userId, &userOpt)
	if err != nil {
		strerr := err.Error()
		event := domain.NewFailedEvent(domain.EventUpdateUser, domain.EventPlaceHandler, &strerr,
			hexid, ec.traceId)
		ah.audit.Log(ec.ctx, event)
	}

	w.WriteHeader(http.StatusOK)
}

// FIXME refactor
func (ah *AuthHandler) DeleteUser(w http.ResponseWriter, r *http.Request) {

	ex, toReturn := ah.checkAuth(w, r)
	if toReturn {
		return
	}

	key := hex.EncodeToString(ex.userId[:])
	_, err, _ := ah.sgr.Do(key, func() (any, error) {
		err := ah.usBd.Delete(ex.ctx, ex.userId)
		return nil, err
	})

	if err != nil {
		strerr := err.Error()
		event := domain.NewFailedEvent(domain.EventDeletedUser, domain.EventPlaceHandler,
			&strerr, key, ex.traceId)
		ah.audit.Log(ex.ctx, event)
		sendIternalServerError(w, ex.traceId, ex.ctx, ah.audit)
		return
	}

	err = ah.usCh.Del(ex.ctx, ex.userId)
	if err != nil {
		sendIternalServerError(w, ex.traceId, ex.ctx, ah.audit)
		return
	}

	err = ah.ss.DeleteAll(ex.ctx, ex.userId)
	if err != nil {
		strerr := err.Error()
		event := domain.NewFailedEvent(domain.EventDeleteSessionFailed, domain.EventPlaceHandler,
			&strerr, key, ex.traceId)
		ah.audit.Log(ex.ctx, event)
	}

	w.WriteHeader(http.StatusOK)
}

func (ah *AuthHandler) checkAuth(w http.ResponseWriter, r *http.Request) (*executionContext, bool) {
	ec, toReturn := ah.validateCheck(w, r, domain.EventAutheticationFailed, false)
	if toReturn {
		return nil, true
	}

	// Проверка Bearer-токена
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		err := "Non bearer scheme"
		event := domain.NewFailedEvent(domain.EventAutheticationFailed, domain.EventPlaceHandler, &err, "", ec.traceId)
		ah.audit.Log(ec.ctx, event)
		sendInvalidToken(w, ec.traceId, ec.ctx, ah.audit, http.StatusUnauthorized)
		return nil, true
	}

	token, ok := getBearerData(authHeader)
	if !ok {
		err := "Non bearer scheme"
		event := domain.NewFailedEvent(domain.EventAutheticationFailed, domain.EventPlaceHandler, &err, "", ec.traceId)
		ah.audit.Log(ec.ctx, event)
		sendInvalidToken(w, ec.traceId, ec.ctx, ah.audit, http.StatusUnauthorized)
		return nil, true
	}

	if token == "" {
		sendInvalidToken(w, ec.traceId, ec.ctx, ah.audit, http.StatusUnauthorized)
		return nil, true
	}

	accessToken, err := ah.tu.ValidAccessToken(token)
	if tokens.ErrExpToken.Is(err) {

		strerr := err.Error()
		event := domain.NewFailedEvent(domain.EventAutheticationFailed, domain.EventPlaceHandler, &strerr, "", ec.traceId)
		ah.audit.Log(ec.ctx, event)

		errBody := middleware.ErrBody{
			Err:     "invalid_grant",
			Code:    "INVALID_GRANT",
			Message: "The access token has expired. Please re-authenticate.",
		}
		sendErr(w, errBody, ec.traceId, `Bearer error="invalid_token", error_description="The access token expired"`,
			ec.ctx, http.StatusUnauthorized, ah.audit)
		return nil, true

	} else if tokens.ErrFutureDateToken.Is(err) {

		strerr := err.Error()
		event := domain.NewFailedEvent(domain.EventAutheticationFailed, domain.EventPlaceHandler, &strerr, "", ec.traceId)
		ah.audit.Log(ec.ctx, event)

		sserr := ah.ss.DeleteByRefresh(ec.ctx, accessToken.UserId, accessToken.FamilyId)
		if sserr != nil {
			strerr = sserr.Error()
			event := domain.NewFailedEvent(domain.EventAutheticationFailed, domain.EventPlaceHandler, &strerr,
				hex.EncodeToString(accessToken.UserId[:]), ec.traceId)
			ah.audit.Log(ec.ctx, event)
		}

		errBody := middleware.ErrBody{
			Err:     "invalid_token",
			Code:    "INVALID_TOKEN",
			Message: "Token reuse detected. Session has been revoked.",
		}
		sendErr(w, errBody, ec.traceId, `Bearer error="invalid_token", error_description="Token reuse detected. Session has been revoked."`,
			ec.ctx, http.StatusUnauthorized, ah.audit)

		return nil, true
	} else if tokens.ErrInvalidSignToken.Is(err) || tokens.ErrInvalidToken.Is(err) {
		sendInvalidToken(w, ec.traceId, ec.ctx, ah.audit, http.StatusUnauthorized)
		return nil, true
	}

	session, err := ah.ss.GetSessionByFamilyId(ec.ctx, accessToken.UserId, accessToken.FamilyId)
	if custerr.ErrNotFound.Is(err) {
		errBody := middleware.ErrBody{
			Err:     "invalid_token",
			Code:    "INVALID_TOKEN",
			Message: "The session is invalid or has been revoked.",
		}
		sendErr(w, errBody, ec.traceId,
			`Bearer error="invalid_token", error_description="The session is invalid or has been revoked."`,
			ec.ctx, http.StatusUnauthorized, ah.audit)
		return nil, true
	} else if err != nil {
		sendIternalServerError(w, ec.traceId, ec.ctx, ah.audit)
		return nil, true
	}

	if (session.UserId != accessToken.UserId || session.Agent != accessToken.Agent || session.DeviceId != accessToken.DeviceId ||
		session.Version != accessToken.Version) || (session.Agent != ec.agent || session.DeviceId != ec.deviceId) {

		strerr := "Session context mismatch"
		event := domain.NewFailedEvent(domain.EventAutheticationFailed, domain.EventPlaceHandler, &strerr, "", ec.traceId)
		ah.audit.Log(ec.ctx, event)

		sserr := ah.ss.DeleteByRefresh(ec.ctx, accessToken.UserId, accessToken.FamilyId)
		if sserr != nil {
			strerr = sserr.Error()
			event := domain.NewFailedEvent(domain.EventAutheticationFailed, domain.EventPlaceHandler, &strerr,
				hex.EncodeToString(accessToken.UserId[:]), ec.traceId)
			ah.audit.Log(ec.ctx, event)
		}

		errBody := middleware.ErrBody{
			Err:     "invalid_grant",
			Code:    "SESSION_CONTEXT_MISMATCH",
			Message: "Session context mismatch. Please log in again.",
		}
		sendErr(w, errBody, ec.traceId,
			`Bearer error="invalid_grant", error_description="Session context mismatch. Please log in again."`,
			ec.ctx, http.StatusUnauthorized, ah.audit)
		return nil, true
	}

	if ec.ip != session.Ip {
		err = ah.ss.UpdateIpAdress(ec.ctx, session.UserId, accessToken.FamilyId, ec.ip)
		if err != nil {
			strerr := err.Error()
			event := domain.NewFailedEvent(domain.EventUpdateSessionIPFailed, domain.EventPlaceHandler, &strerr,
				hex.EncodeToString(accessToken.UserId[:]), ec.traceId)
			ah.audit.Log(ec.ctx, event)
		}
	}

	ec.userId = session.UserId

	return ec, false
}

func (ah *AuthHandler) validateCheck(w http.ResponseWriter, r *http.Request, failEvent domain.EventType, haveBody bool) (*executionContext, bool) {

	ec := &executionContext{}

	ctx := r.Context()
	traceId, ok := ctx.Value(domain.TraceKey).(string)
	if !ok {
		traceId = ""
	}

	ec.ctx = ctx
	ec.traceId = traceId

	if haveBody {
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

	deviceId, agentVal, err := parseDeviceIdAndAgent(r)
	if err != nil {
		err := "The request is missing important fields."
		event := domain.NewFailedEvent(failEvent, domain.EventPlaceHandler, &err, "", traceId)
		ah.audit.Log(ctx, event)

		sendBadrequest(w, traceId, err, ctx, ah.audit)
		return nil, true
	}

	ec.deviceId = deviceId
	ec.agent = agentVal

	return ec, false
}

func (ah *AuthHandler) getUserFromBody(w http.ResponseWriter, r *http.Request, oc *domain.OperationContext, failEvent domain.EventType) bool {

	r.Body = http.MaxBytesReader(w, r.Body, MaxRegistrationBody)
	jsonData, err := io.ReadAll(r.Body)
	if err != nil {
		ah.logFailedEvent(oc.Ctx, failEvent, err.Error(), "", oc.TraceId)
		sendBadrequest(w, oc.TraceId, "The request body contains invalid or missing fields.", oc.Ctx, ah.audit)
		return true
	}

	var user domain.User
	err = json.Unmarshal(jsonData, &user)
	if err != nil {
		ah.logFailedEvent(oc.Ctx, failEvent, err.Error(), "", oc.TraceId)
		sendBadrequest(w, oc.TraceId, "The request body contains invalid or missing fields.", oc.Ctx, ah.audit)
		return true
	}

	oc.UserData = &user
	return false
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
		Err:     "internal_server_error",
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

func sendInvalidToken(w http.ResponseWriter, traceId string, ctx context.Context, audit domain.AuditService, code int) {
	if code == 0 {
		code = http.StatusBadRequest
	}
	httperr := middleware.ErrBody{
		Err:     "invalid_token",
		Code:    "INVALID_TOKEN",
		Message: "The token is invalid or malformed.",
	}
	sendErr(w, httperr, traceId,
		`Bearer error="invalid_token", error_description="The token is invalid or malformed."`,
		ctx, code, audit)
}

func (ah *AuthHandler) sendErrBody(w http.ResponseWriter, errBody *domain.OperationError, oc *domain.OperationContext) {

	jsonBt, err := json.Marshal(errBody)
	if err != nil {
		ah.logFailedEvent(oc.Ctx, domain.EventFailedParseErrAuthAnswer, err.Error(), "", oc.TraceId)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	if errBody.WWWAns != "" {
		w.Header().Set(middleware.HeadWWWAuthenticate, errBody.WWWAns)
	}

	w.Header().Set(middleware.HeadContentType, middleware.ValHeadAppJson)

	w.WriteHeader(errBody.StatusCode)
	w.Write(jsonBt)
}

func (ah *AuthHandler) logFailedEvent(ctx context.Context, eventType domain.EventType, err, entId, traceId string) {
	event := domain.NewFailedEvent(eventType, domain.EventPlaceHandler,
		&err, "", traceId)
	ah.audit.Log(ctx, event)
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

func getBearerData(header string) (string, bool) {

	if len(header) < len(Bearer) {
		return "", false
	}

	if strings.ToLower(header[:len(Bearer)]) == Bearer {
		return strings.TrimSpace(header[len(Bearer):]), true
	}

	return "", false
}

func getOpContextFromReq(r *http.Request) *domain.OperationContext {

	ctx := r.Context()

	oc, ok := ctx.Value(domain.OperCtxKey).(*domain.OperationContext)
	if !ok {
		return nil
	}

	return oc
}

// parseDeviceIdAndAgent извлекает deviceId из cookie DeviceId и agent из заголовка User-Agent.
func parseDeviceIdAndAgent(r *http.Request) (string, string, error) {

	cookie, err := r.Cookie(CookieDeviceId)
	if err != nil || strings.TrimSpace(cookie.Value) == "" {
		return "", "", fmt.Errorf("missing DeviceId cookie")
	}

	agent := strings.TrimSpace(r.Header.Get(HeadUserAgent))
	if agent == "" {
		return "", "", fmt.Errorf("missing User-Agent header")
	}

	return cookie.Value, agent, nil
}
