package domain

// Error implements the error interface for OperationError.
func (oe *OperationError) Error() string {
	if oe.Message != "" {
		return oe.Message
	}
	return oe.Err
}

// ============================================================================
// Authentication & Authorization Errors (Middleware)
// ============================================================================

var (
	// ErrTokenExpired — access token expired
	ErrTokenExpired = OperationError{
		Err:        "Unauthorized",
		Code:       "TOKEN_EXPIRED",
		Message:    "The access token expired",
		StatusCode: 401,
		WWWAns:     `Bearer error="invalid_token", error_description="The access token expired"`,
	}

	// ErrTokenInvalid — access token is invalid or malformed
	ErrTokenInvalid = OperationError{
		Err:        "Unauthorized",
		Code:       "TOKEN_INVALID",
		Message:    "Access token invalid",
		StatusCode: 401,
		WWWAns:     `Bearer error="invalid_token", error_description="The access token invalid"`,
	}

	// ErrTokenUnknown — access token is unknown or invalid
	ErrTokenUnknown = OperationError{
		Err:        "Unauthorized",
		Code:       "TOKEN_INVALID",
		Message:    "The access token is unknown or invalid",
		StatusCode: 401,
		WWWAns:     `Bearer error="invalid_token", error_description="The access token is unknown or invalid"`,
	}

	// ErrAuthHeaderMissing — Authorization header is missing
	ErrAuthHeaderMissing = OperationError{
		Err:        "Unauthorized",
		Code:       "AUTH_HEADER_MISSING",
		Message:    "Authorization header is missing",
		StatusCode: 401,
		WWWAns:     `Bearer realm="user-service"`,
	}

	// ErrSessionNotFound — user session is invalid or user not found
	ErrSessionNotFound = OperationError{
		Err:        "Unauthorized",
		Code:       "USER_NOT_FOUND",
		Message:    "User session is invalid or user not found",
		StatusCode: 401,
		WWWAns:     `Bearer error="invalid_token", error_description="The access token is unknown or invalid"`,
	}

	// ErrSessionCompromised — session context mismatch (security violation)
	ErrSessionCompromised = OperationError{
		Err:        "Unauthorized",
		Code:       "SESSION_COMPROMISED",
		Message:    "Session context mismatch. Security violation.",
		StatusCode: 401,
		WWWAns:     `Bearer error="invalid_token", error_description="Session context mismatch. Security validation failed."`,
	}
)

// ============================================================================
// Handler Errors — Token & Session
// ============================================================================

var (
	// ErrTokenExpiredHandler — access token expired (handler flow)
	ErrTokenExpiredHandler = OperationError{
		Err:        "invalid_grant",
		Code:       "INVALID_GRANT",
		Message:    "The access token has expired. Please re-authenticate.",
		StatusCode: 401,
		WWWAns:     `Bearer error="invalid_token", error_description="The access token expired"`,
	}

	// ErrTokenReuseDetected — token reuse detected, session revoked
	ErrTokenReuseDetected = OperationError{
		Err:        "invalid_token",
		Code:       "INVALID_TOKEN",
		Message:    "Token reuse detected. Session has been revoked.",
		StatusCode: 401,
		WWWAns:     `Bearer error="invalid_token", error_description="Token reuse detected. Session has been revoked."`,
	}

	// ErrSessionInvalid — session is invalid or has been revoked
	ErrSessionInvalid = OperationError{
		Err:        "invalid_token",
		Code:       "INVALID_TOKEN",
		Message:    "The session is invalid or has been revoked.",
		StatusCode: 401,
		WWWAns:     `Bearer error="invalid_token", error_description="The session is invalid or has been revoked."`,
	}

	// ErrSessionContextMismatch — session context mismatch (handler flow)
	ErrSessionContextMismatch = OperationError{
		Err:        "invalid_grant",
		Code:       "SESSION_CONTEXT_MISMATCH",
		Message:    "Session context mismatch. Please log in again.",
		StatusCode: 401,
		WWWAns:     `Bearer error="invalid_grant", error_description="Session context mismatch. Please log in again."`,
	}
)

// ============================================================================
// Handler Errors — Request Validation
// ============================================================================

var (
	// ErrBadRequest — generic bad request
	ErrBadRequest = OperationError{
		Err:        "bad request",
		Code:       "BAD_REQUEST",
		Message:    "The request is missing important fields.",
		StatusCode: 400,
	}

	// ErrGrantTypeInvalid — grant_type is not refresh_token
	ErrGrantTypeInvalid = OperationError{
		Err:        "bad request",
		Code:       "BAD_REQUEST",
		Message:    "grant_type must be refresh_token.",
		StatusCode: 400,
	}

	// ErrRefreshTokenRequired — refresh_token field is empty
	ErrRefreshTokenRequired = OperationError{
		Err:        "invalid_request",
		Code:       "INVALID_REQUEST",
		Message:    "refresh_token is required",
		StatusCode: 400,
	}

	// ErrInvalidBody — unsupported media type
	ErrInvalidBody = OperationError{
		Err:        "invalid_body",
		Code:       "INVALID_BODY",
		Message:    "Unsupported Media Type",
		StatusCode: 415,
	}
)

// ============================================================================
// Handler Errors — User Not Found / Conflict
// ============================================================================

var (
	// ErrUserNotFound — user not found or has been deleted
	ErrUserNotFound = OperationError{
		Err:        "not_found",
		Code:       "USER_NOT_FOUND",
		Message:    "User not found or has been deleted.",
		StatusCode: 404,
	}

	// ErrConflictEmail — email is already in use
	ErrConflictEmail = OperationError{
		Err:        "conflict",
		Code:       "CONFLICT",
		Message:    "The email is already in use by another user.",
		StatusCode: 409,
	}

	// ErrConflictPhone — phone is already in use
	ErrConflictPhone = OperationError{
		Err:        "conflict",
		Code:       "CONFLICT",
		Message:    "The phone is already in use by another user.",
		StatusCode: 409,
	}

	// ErrConflictUsername — username is already in use
	ErrConflictUsername = OperationError{
		Err:        "conflict",
		Code:       "CONFLICT",
		Message:    "The username is already in use by another user.",
		StatusCode: 409,
	}
)

// ============================================================================
// Handler Errors — Credentials & Validation
// ============================================================================

var (
	// ErrInvalidCredentials — invalid username/email/phone or password
	ErrInvalidCredentials = OperationError{
		Err:        "invalid_grant",
		Code:       "INVALID_CREDENTIALS",
		Message:    "Invalid username or password.",
		StatusCode: 401,
	}

	// ErrValidationRequired — username and password are required (used by RegistrationUser/SingIn)
	ErrValidationRequired = OperationError{
		Err:        "bad request",
		Code:       "VALIDATION_ERROR",
		Message:    "Username and password are required.",
		StatusCode: 400,
	}

	// ErrValidationUsernameRequired — username cannot be null or empty (UpdateUserData)
	ErrValidationUsernameRequired = OperationError{
		Err:        "invalid_request",
		Code:       "VALIDATION_ERROR",
		Message:    "Username cannot be null or empty.",
		StatusCode: 400,
	}

	// ErrRegistrationConflictUsername — username already taken during registration
	ErrRegistrationConflictUsername = OperationError{
		Err:        "conflict",
		Code:       "CONFLICT",
		Message:    "Registration failed. Please check your details or try logging in.",
		StatusCode: 409,
	}

	// ErrRegistrationConflictEmail — email already taken during registration
	ErrRegistrationConflictEmail = OperationError{
		Err:        "conflict",
		Code:       "CONFLICT",
		Message:    "Registration failed. Please check your details or try logging in.",
		StatusCode: 409,
	}

	// ErrRegistrationConflictPhone — phone already taken during registration
	ErrRegistrationConflictPhone = OperationError{
		Err:        "conflict",
		Code:       "CONFLICT",
		Message:    "Registration failed. Please check your details or try logging in.",
		StatusCode: 409,
	}

	// ErrInvalidBodyFields — request body contains invalid or missing fields
	ErrInvalidBodyFields = OperationError{
		Err:        "bad request",
		Code:       "BAD_REQUEST",
		Message:    "The request body contains invalid or missing fields.",
		StatusCode: 400,
	}

	// ErrRegistrationFailed — registration failed (duplicate after UNIQUE check)
	ErrRegistrationFailed = OperationError{
		Err:        "conflict",
		Code:       "REGISTRATION_FAILED",
		Message:    "Registration failed. Please check your details or try logging in.",
		StatusCode: 409,
	}
)

// ============================================================================
// Handler Errors — Token Invalid (generic)
// ============================================================================

var (
	// ErrTokenInvalidMsg — generic invalid token message (RFC 6750)
	ErrTokenInvalidMsg = OperationError{
		Err:        "invalid_token",
		Code:       "INVALID_TOKEN",
		Message:    "The token is invalid or malformed.",
		StatusCode: 401,
		WWWAns:     `Bearer error="invalid_token", error_description="The token is invalid or malformed."`,
	}
)

// ============================================================================
// Internal / Service Errors
// ============================================================================

var (
	// ErrInternalServerError — authentication service unavailable
	ErrInternalServerError = OperationError{
		Err:        "internal_server_error",
		Code:       "AUTH_SERVICE_ERROR",
		Message:    "Authentication service is temporarily unavailable. Please try again later.",
		StatusCode: 500,
	}
)
