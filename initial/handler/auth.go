package handler

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"user_service/config"
	"user_service/domain"
	"user_service/infrastructure/reporedis/custerr"
	"user_service/infrastructure/tokens"
	"user_service/initial/middleware"
)

const (
	GrantType    = "grant_type"
	RefreshToken = "refresh_token"

	HeadContentType   = "Content-Type"
	HeadUserAgent     = "User-Agent"
	HeadDeviceId      = "Device-Id"
	HeadCacheControle = "Cache-Control"
	HeadPragma        = "Pragma"

	ValHeadAppJson = "application/json"
)

type ValidData struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
}

type AuthHandler struct {
	cm    *config.ConfigManager
	audit domain.AuditService
	ss    domain.SessionStore
	tu    *tokens.TokenUtil
}

func NewAuthHandler(cm *config.ConfigManager, audit domain.AuditService, ss domain.SessionStore, tu *tokens.TokenUtil) *AuthHandler {
	return &AuthHandler{
		cm:    cm,
		audit: audit,
		ss:    ss,
		tu:    tu,
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
	if DeviceIdFromReq == "" || AgentFromReq == "" {
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
