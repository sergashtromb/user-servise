package domain

import (
	"context"
	"time"
	"user_service/pkg/opt"
	"uuid"
)

// context keys
const TraceKey = "trace_id"
const OperCtxKey = "operation_context"

type User struct {
	Id        uuid.UUID
	UserName  string
	Password  string //hash summ
	Email     string
	Phone     string
	CreatedAt time.Time
	IsDeleted bool
}

type UserOpt struct {
	UserName  opt.Field[string] `json:"username"`
	Email     opt.Field[string] `json:"email"`
	Phone     opt.Field[string] `json:"phone"`
	IsDeleted opt.Field[bool]   `json:"is_delete"`
}

// ToUserOpt converts a User to a UserOpt.
// String fields are Define/Valid only when non-empty.
func ToUserOpt(u *User) *UserOpt {
	if u == nil {
		return nil
	}
	return &UserOpt{
		UserName:  opt.Field[string]{Value: u.UserName, Define: u.UserName != "", Valid: u.UserName != ""},
		Email:     opt.Field[string]{Value: u.Email, Define: u.Email != "", Valid: u.Email != ""},
		Phone:     opt.Field[string]{Value: u.Phone, Define: u.Phone != "", Valid: u.Phone != ""},
		IsDeleted: opt.Field[bool]{Value: u.IsDeleted, Define: true, Valid: true},
	}
}

type Session struct {
	UserId     uuid.UUID
	DeviceId   string
	Ip         string
	Agent      string
	CreatedAt  time.Time
	Version    string
	LastUpdate time.Time
}

type GracePeriodic struct {
	Version string
	Access  string // hash from real tokens
	Refresh string
}

type OperationContext struct {
	Ctx      context.Context
	TraceId  string
	Ip       string
	DeviceId string
	Agent    string
	UserId   uuid.UUID
	FamilyId uuid.UUID
	UserData *User
	HashPass string
	Hexid    string
}

func NewOperationContext(ctx context.Context, traceId string) *OperationContext {
	return &OperationContext{
		Ctx:     ctx,
		TraceId: traceId,
	}
}

type OperationTokens struct {
	StatusCode   int
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
}

type OperationUserData struct {
	StatusCode int
	Username   string    `json:"username"`
	Email      string    `json:"email"`
	Phone      string    `json:"phone"`
	CreatedAt  time.Time `json:"created_at"`
}

type OperationError struct {
	StatusCode int
	WWWAns     string
	Err        string `json:"error"`
	Code       string `json:"code"`
	Message    string `json:"message"`
}
