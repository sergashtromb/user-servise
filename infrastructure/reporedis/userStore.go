package reporedis

import (
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strconv"
	"time"
	"user_service/domain"
	"user_service/pkg/opt"
	"uuid"

	"github.com/redis/go-redis/v9"
)

const UserKey = "user:"

const (
	FieldId        = "id"
	FieldUserName  = "user_name"
	FieldEmail     = "email"
	FieldPhone     = "phone"
	FieldCreatedAt = "created_at"
	FieldIsDeleted = "is_deleted"
)

type UserStore struct {
	repo  *Repository
	audit domain.AuditService
	ttl   time.Duration
}

func NewUserStore(repo *Repository, audit domain.AuditService, ttl time.Duration) *UserStore {
	return &UserStore{
		repo:  repo,
		audit: audit,
		ttl:   ttl,
	}
}

func (us *UserStore) Set(ctx context.Context, user *domain.User) error {

	data, key := UserCacheFromDomainUser(user).ToMapInterface()
	err := us.repo.Do(ctx, func(ctx context.Context, client *redis.Client) error {

		pipe := client.Pipeline()
		pipe.HSet(ctx, key, data)
		pipe.Expire(ctx, key, us.ttl)

		_, err := pipe.Exec(ctx)
		if err != nil {
			errString := err.Error()

			event := domain.NewFailedEvent(domain.EventSendUserIntoCacheFailed, domain.EventPlaceRedis,
				&errString, user.Id.String())
			us.audit.Log(ctx, event)
			return err
		}

		event := domain.NewSuccessEvent(domain.EventSendUserIntoCacheSuccess, domain.EventPlaceRedis,
			user.Id.String())
		us.audit.Log(ctx, event)

		return nil
	})
	return err
}

func (us *UserStore) Get(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	// FIXME replace event
	key := fmt.Sprintf("%s%s", UserKey, hex.EncodeToString(id[:]))
	var user *domain.User
	err := us.repo.Do(ctx, func(ctx context.Context, client *redis.Client) error {

		pipe := client.Pipeline()
		getCmd := pipe.HGetAll(ctx, key)
		// update ttl
		pipe.Expire(ctx, key, us.ttl)

		_, err := pipe.Exec(ctx)
		if err != nil {
			errString := err.Error()

			event := domain.NewFailedEvent(domain.EventSendUserIntoCacheFailed, domain.EventPlaceRedis,
				&errString, id.String())
			us.audit.Log(ctx, event)

			return err
		}

		data, err := getCmd.Result()
		if err != nil {
			errString := err.Error()

			event := domain.NewFailedEvent(domain.EventSendUserIntoCacheFailed, domain.EventPlaceRedis,
				&errString, id.String())
			us.audit.Log(ctx, event)

			return err
		}

		user = UserCacheFromMapString(data).ToDomainUser()
		return nil
	})

	if err != nil {
		return nil, err
	}

	return user, nil
}

// for update and modify individual field
type UserCacheOpt struct {
	Id        string
	UserName  opt.Field[string]
	Email     opt.Field[string]
	Phone     opt.Field[string]
	CreatedAt opt.Field[int64]
	IsDeleted opt.Field[string]
}

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

func (uc *UserCache) ToMapInterface() (map[string]interface{}, string) {
	return map[string]interface{}{
		FieldId:        uc.Id,
		FieldUserName:  uc.UserName,
		FieldEmail:     uc.Email,
		FieldPhone:     uc.Phone,
		FieldCreatedAt: uc.CreatedAt,
		FieldIsDeleted: uc.IsDeleted,
	}, fmt.Sprintf("%s%s", UserKey, uc.Id)
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

func UserCacheFromMapString(data map[string]string) *UserCache {

	createdAt, err := strconv.ParseInt(data[FieldCreatedAt], 10, 64)
	if err != nil {
		createdAt = 0
	}

	return &UserCache{
		Id:        data[FieldId],
		UserName:  data[FieldUserName],
		Email:     data[FieldEmail],
		Phone:     data[FieldPhone],
		CreatedAt: createdAt,
		IsDeleted: data[FieldIsDeleted],
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

	var u uuid.UUID
	copy(u[:], b)

	return u, nil
}
