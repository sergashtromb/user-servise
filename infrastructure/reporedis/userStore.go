package reporedis

import (
	"encoding/hex"
	"log/slog"
	"time"
	"user_service/domain"
	"uuid"
)

type UserCache struct {
	Id        string // hex from uuid domain.User
	UserName  string
	Email     string
	Phone     string
	CreatedAt int64  // unix
	IsDeleted string // "1" or "0"
}

func (uc *UserCache) ToDomainUser() *domain.User {

	id, err := hexToUuid(uc.Id)
	if err != nil {
		slog.Error("Failed convert hex string to uuid", "err", err)
		return nil
	}

	return &domain.User{
		Id:        id,
		UserName:  uc.UserName,
		Email:     uc.Email,
		Phone:     uc.Phone,
		CreatedAt: time.Unix(uc.CreatedAt, 0),
		IsDeleted: deleteBoolFromString(uc.IsDeleted),
	}
}

func UserCacheFromDomainUser(user *domain.User) *UserCache {
	return &UserCache{
		Id:        hex.EncodeToString(user.Id[:]),
		UserName:  user.UserName,
		Email:     user.Email,
		Phone:     user.Phone,
		CreatedAt: user.CreatedAt.Unix(),
		IsDeleted: deleteStatusFromBool(user.IsDeleted),
	}
}

func deleteStatusFromBool(st bool) string {
	if st {
		return "1"
	} else {
		return "0"
	}
}

func deleteBoolFromString(st string) bool {
	return st == "1"
}

func hexToUuid(strhex string) (uuid.UUID, error) {

	b, err := hex.DecodeString(strhex)
	if err != nil {
		return uuid.Nil(), err
	}

	return uuid.MustParse(string(b)), nil
}
