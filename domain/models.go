package domain

import (
	"time"
	"user_service/pkg/opt"
	"uuid"
)

// context keys
const TraceKey = "trace_id"

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
