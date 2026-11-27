package handler

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"user_service/config"
	"user_service/domain"
	"user_service/infrastructure/tokens"
	"user_service/initial/middleware"
	"user_service/service"

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

	ctx := r.Context()
	oc, ok := ctx.Value(domain.OperCtxKey).(*domain.OperationContext)
	if !ok {
		ah.logFailedEvent(ctx, domain.EventUpdateVersionTokenFailed, "request don't have operation context",
			"", "")
		middleware.SendError(w, domain.NewOperationContext(ctx, ""), &domain.ErrInternalServerError, ah.audit, domain.EventUpdateVersionTokenFailed)
		return
	}

	if err := r.ParseForm(); err != nil {
		ah.logFailedEvent(oc.Ctx, domain.EventUpdateVersionTokenFailed, err.Error(), "", oc.TraceId)
		middleware.SendError(w, oc, &domain.ErrBadRequest, ah.audit, domain.EventUpdateVersionTokenFailed)
		return
	}
	grantType := r.PostFormValue(GrantType)
	reftoken := r.PostFormValue(RefreshToken)

	if grantType != RefreshToken {
		ah.logFailedEvent(oc.Ctx, domain.EventUpdateVersionTokenFailed, "Field grant_type is not refresh_token.",
			"", oc.TraceId)

		middleware.SendError(w, oc, &domain.ErrGrantTypeInvalid, ah.audit, domain.EventUpdateVersionTokenFailed)
		return
	}

	if reftoken == "" {
		ah.logFailedEvent(oc.Ctx, domain.EventUpdateVersionTokenFailed, "Field refresh_token is not exist.",
			"", oc.TraceId)

		middleware.SendError(w, oc, &domain.ErrRefreshTokenRequired, ah.audit, domain.EventUpdateVersionTokenFailed)
		return
	}

	// check token validation
	validData, errBody := ah.us.UpdateRefreshToken(oc, reftoken)
	if errBody != nil {
		middleware.SendError(w, oc, errBody, ah.audit, domain.EventUpdateVersionTokenFailed)
		return
	}

	jsonData, err := json.Marshal(&validData)
	if err != nil {
		ah.logFailedEvent(oc.Ctx, domain.EventGetSessionUserFailed, err.Error(), oc.Hexid, oc.TraceId)
		middleware.SendError(w, oc, &domain.ErrInternalServerError, ah.audit, domain.EventGetSessionUserFailed)
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
		middleware.SendError(w, domain.NewOperationContext(ctx, ""), &domain.ErrInternalServerError, ah.audit, domain.EventRegistrationFailed)
		return
	}

	toReturn := ah.getUserFromBody(w, r, oc, domain.EventRegistrationFailed)
	if toReturn {
		return
	}

	tokens, errOp := ah.us.RegistrationUser(oc)
	if errOp != nil {
		middleware.SendError(w, oc, errOp, ah.audit, domain.EventRegistrationFailed)
		return
	}

	jsonBytes, err := json.Marshal(&tokens)
	if err != nil {
		ah.logFailedEvent(oc.Ctx, domain.EventRegistrationFailed, err.Error(), "", oc.TraceId)
		middleware.SendError(w, oc, &domain.ErrInternalServerError, ah.audit, domain.EventRegistrationFailed)
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

func (ah *AuthHandler) SingIn(w http.ResponseWriter, r *http.Request) {

	ctx := r.Context()
	oc, ok := ctx.Value(domain.OperCtxKey).(*domain.OperationContext)
	if !ok {
		ah.logFailedEvent(ctx, domain.EventLoginFailed, "request don't have operation context",
			"", "")
		middleware.SendError(w, domain.NewOperationContext(ctx, ""), &domain.ErrInternalServerError, ah.audit, domain.EventLoginFailed)
		return
	}

	toReturn := ah.getUserFromBody(w, r, oc, domain.EventLoginFailed)
	if toReturn {
		return
	}

	tokens, errBody := ah.us.SingIn(oc)
	if errBody != nil {
		middleware.SendError(w, oc, errBody, ah.audit, domain.EventLoginFailed)
		return
	}

	jsonBytes, err := json.Marshal(tokens)
	if err != nil {
		ah.logFailedEvent(ctx, domain.EventLoginFailed, err.Error(),
			"", oc.TraceId)
		middleware.SendError(w, oc, &domain.ErrInternalServerError, ah.audit, domain.EventLoginFailed)
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

func (ah *AuthHandler) Authentication(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func (ah *AuthHandler) GetUserData(w http.ResponseWriter, r *http.Request) {

	ctx := r.Context()
	oc, ok := ctx.Value(domain.OperCtxKey).(*domain.OperationContext)
	if !ok {
		ah.logFailedEvent(ctx, domain.EventGetUser, "request don't have operation context",
			"", "")
		middleware.SendError(w, domain.NewOperationContext(ctx, ""), &domain.ErrInternalServerError, ah.audit, domain.EventGetUser)
		return
	}

	user, opErr := ah.us.GetUserData(oc)
	if opErr != nil {
		middleware.SendError(w, oc, opErr, ah.audit, domain.EventGetUser)
		return
	}

	data := map[string]interface{}{
		"username":   user.Username,
		"phone":      user.Phone,
		"email":      user.Email,
		"created_at": user.CreatedAt,
	}

	jsonData, err := json.Marshal(&data)
	if err != nil {
		ah.logFailedEvent(oc.Ctx, domain.EventGetUser, err.Error(), oc.Hexid, oc.TraceId)
		middleware.SendError(w, oc, &domain.ErrInternalServerError, ah.audit, domain.EventGetUser)
		return
	}

	w.Header().Add(HeadContentType, ValHeadAppJson)
	w.Header().Add(HeadCacheControle, "no-store")
	w.Header().Add(HeadPragma, "no-cache")

	w.WriteHeader(http.StatusOK)
	w.Write(jsonData)
}

func (ah *AuthHandler) UpdateUserData(w http.ResponseWriter, r *http.Request) {

	ctx := r.Context()
	oc, ok := ctx.Value(domain.OperCtxKey).(*domain.OperationContext)
	if !ok {
		ah.logFailedEvent(ctx, domain.EventUpdateUser, "request don't have operation context",
			"", "")
		middleware.SendError(w, domain.NewOperationContext(ctx, ""), &domain.ErrInternalServerError, ah.audit, domain.EventUpdateUser)
		return
	}

	jsonBody, err := io.ReadAll(r.Body)
	if err != nil {
		middleware.SendError(w, oc, &domain.ErrInvalidBodyFields, ah.audit, domain.EventUpdateUser)
		return
	}

	var userOpt domain.UserOpt
	err = json.Unmarshal(jsonBody, &userOpt)
	if err != nil {
		middleware.SendError(w, oc, &domain.ErrInvalidBodyFields, ah.audit, domain.EventUpdateUser)
		return
	}

	if !userOpt.UserName.Define && !userOpt.Email.Define && !userOpt.Phone.Define && !userOpt.IsDeleted.Define {
		middleware.SendError(w, oc, &domain.ErrInvalidBodyFields, ah.audit, domain.EventUpdateUser)
		return
	}

	errBody := ah.us.UpdateUserData(oc, &userOpt)
	if errBody != nil {
		middleware.SendError(w, oc, errBody, ah.audit, domain.EventUpdateUser)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (ah *AuthHandler) DeleteUser(w http.ResponseWriter, r *http.Request) {

	ctx := r.Context()
	oc, ok := ctx.Value(domain.OperCtxKey).(*domain.OperationContext)
	if !ok {
		ah.logFailedEvent(ctx, domain.EventDeletedUser, "request don't have operation context",
			"", "")
		middleware.SendError(w, domain.NewOperationContext(ctx, ""), &domain.ErrInternalServerError, ah.audit, domain.EventDeletedUser)
		return
	}

	errBody := ah.us.DeleteUser(oc)
	if errBody != nil {
		middleware.SendError(w, oc, errBody, ah.audit, domain.EventDeletedUser)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (ah *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	oc, ok := ctx.Value(domain.OperCtxKey).(*domain.OperationContext)
	if !ok {
		ah.logFailedEvent(ctx, domain.EventLogoutFailed, "request don't have operation context",
			"", "")
		middleware.SendError(w, domain.NewOperationContext(ctx, ""), &domain.ErrInternalServerError, ah.audit, domain.EventLogoutFailed)
		return
	}

	onceLogout, errBody := ah.us.Logout(oc)
	if errBody != nil {
		middleware.SendError(w, oc, errBody, ah.audit, domain.EventLogoutFailed)
		return
	}

	if onceLogout {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusNoContent)
	}
}

func (ah *AuthHandler) LogoutAll(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	oc, ok := ctx.Value(domain.OperCtxKey).(*domain.OperationContext)
	if !ok {
		ah.logFailedEvent(ctx, domain.EventLogoutAllFailed, "request don't have operation context",
			"", "")
		middleware.SendError(w, domain.NewOperationContext(ctx, ""), &domain.ErrInternalServerError, ah.audit, domain.EventLogoutAllFailed)
		return
	}

	errBody := ah.us.LogoutAll(oc)
	if errBody != nil {
		middleware.SendError(w, oc, errBody, ah.audit, domain.EventLogoutAllFailed)
	}

	w.WriteHeader(http.StatusOK)
}

func (ah *AuthHandler) getUserFromBody(w http.ResponseWriter, r *http.Request, oc *domain.OperationContext, failEvent domain.EventType) bool {

	r.Body = http.MaxBytesReader(w, r.Body, MaxRegistrationBody)
	jsonData, err := io.ReadAll(r.Body)
	if err != nil {
		ah.logFailedEvent(oc.Ctx, failEvent, err.Error(), "", oc.TraceId)
		middleware.SendError(w, oc, &domain.ErrInvalidBodyFields, ah.audit, failEvent)
		return true
	}

	var user domain.User
	err = json.Unmarshal(jsonData, &user)
	if err != nil {
		ah.logFailedEvent(oc.Ctx, failEvent, err.Error(), "", oc.TraceId)
		middleware.SendError(w, oc, &domain.ErrInvalidBodyFields, ah.audit, failEvent)
		return true
	}

	oc.UserData = &user
	return false
}

func (ah *AuthHandler) logFailedEvent(ctx context.Context, eventType domain.EventType, err, entId, traceId string) {
	event := domain.NewFailedEvent(eventType, domain.EventPlaceHandler,
		&err, "", traceId)
	ah.audit.Log(ctx, event)
}
