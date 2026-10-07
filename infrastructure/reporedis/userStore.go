package reporedis

import (
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strconv"
	"time"
	dm "user_service/domain"
	"user_service/infrastructure/reporedis/custerr"
	"user_service/infrastructure/reporedis/index"
	"user_service/infrastructure/reporedis/patch"
	"user_service/infrastructure/reporedis/upgrateplan"
	"uuid"

	"github.com/redis/go-redis/v9"
)

const (
	UserKey  = "user:"
	IndexKey = "user:index:"
	RepoName = "Redis"
)

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
	audit dm.AuditService
	ttl   time.Duration
}

func NewUserStore(repo *Repository, audit dm.AuditService, ttl time.Duration) *UserStore {
	return &UserStore{
		repo:  repo,
		audit: audit,
		ttl:   ttl,
	}
}

func (us *UserStore) Set(ctx context.Context, user *dm.User) error {

	userCache := UserCacheFromDomainUser(user)
	err := us.repo.Do(ctx, func(ctx context.Context, client *redis.Client) error {

		data, key := userCache.ToMapInterface()

		iManager := userCache.GetIndexManager()
		indexs, hasIndex := iManager.GetIndexs()
		if hasIndex {
			err := upgrateplan.ReservedIndex(ctx, client, indexs, userCache.Id, us.ttl)
			if err != nil {
				errString := err.Error()

				event := dm.NewFailedEvent(dm.EventSendUserIntoCacheFailed, dm.EventPlaceRedis,
					&errString, user.Id.String())
				us.audit.Log(ctx, event)
				return err
			}
		}

		pipe := client.TxPipeline()
		pipe.HSet(ctx, key, data)
		pipe.Expire(ctx, key, us.ttl)

		if hasIndex {
			for _, index := range indexs {
				pipe.Expire(ctx, index, us.ttl)
			}
		}

		_, err := pipe.Exec(ctx)
		if err != nil {

			if err := upgrateplan.RollbackIndex(ctx, client, indexs); err != nil {
				errString := err.Error()

				event := dm.NewFailedEvent(dm.EventSendUserIntoCacheFailed, dm.EventPlaceRedis,
					&errString, user.Id.String())
				us.audit.Log(ctx, event)
				return err
			}

			errString := err.Error()

			event := dm.NewFailedEvent(dm.EventSendUserIntoCacheFailed, dm.EventPlaceRedis,
				&errString, user.Id.String())
			us.audit.Log(ctx, event)
			return err
		}

		event := dm.NewSuccessEvent(dm.EventSendUserIntoCacheSuccess, dm.EventPlaceRedis,
			user.Id.String())
		us.audit.Log(ctx, event)

		return nil
	})
	return err
}

func (us *UserStore) Del(ctx context.Context, key string) error {
	err := us.repo.Do(ctx, func(ctx context.Context, client *redis.Client) error {
		cmd := client.Del(ctx, key)
		return cmd.Err()
	})
	return err
}

func (us *UserStore) Get(ctx context.Context, id uuid.UUID) (*dm.User, error) {

	key := fmt.Sprintf("%s%s", UserKey, hex.EncodeToString(id[:]))
	var user *dm.User
	err := us.repo.Do(ctx, func(ctx context.Context, client *redis.Client) error {

		pipe := client.Pipeline()
		getCmd := pipe.HGetAll(ctx, key)
		// update ttl
		pipe.Expire(ctx, key, us.ttl)

		_, err := pipe.Exec(ctx)
		if err != nil {
			errString := err.Error()

			event := dm.NewFailedEvent(dm.EventGetUserIntoCacheFailed, dm.EventPlaceRedis,
				&errString, id.String())
			us.audit.Log(ctx, event)

			return err
		}

		data, err := getCmd.Result()
		if err != nil {
			errString := err.Error()

			event := dm.NewFailedEvent(dm.EventGetUserIntoCacheFailed, dm.EventPlaceRedis,
				&errString, id.String())
			us.audit.Log(ctx, event)

			return err
		}

		user = UserCacheFromMapString(data).ToDomainUser()

		sucEvent := dm.NewSuccessEvent(dm.EventGetUserIntoCacheSuccess, dm.EventPlaceRedis,
			user.Id.String())
		us.audit.Log(ctx, sucEvent)

		return nil
	})

	if err != nil {
		return nil, err
	}

	return user, nil
}

func (us *UserStore) Update(ctx context.Context, id uuid.UUID, userOpt *dm.UserOpt) error {

	hexid := hex.EncodeToString(id[:])
	key := fmt.Sprintf("%s%s", UserKey, hexid)

	userCacheOpt := UserCacheOptFromDomainOpt(userOpt)

	err := us.repo.Do(ctx, func(ctx context.Context, client *redis.Client) error {

		data, err := client.HGetAll(ctx, key).Result()
		if err != nil {
			strerr := err.Error()
			event := dm.NewFailedEvent(dm.EventGetUserIntoCacheFailed, dm.EventPlaceRedis,
				&strerr, id.String())
			us.audit.Log(ctx, event)

			return err
		}

		upgratePlan := us.BuildUpgratePlan(UserCacheFromMapString(data), userCacheOpt.Patches())
		err = upgratePlan.Apply(ctx, client, key, hexid, us.ttl)
		if err != nil {
			strerr := err.Error()
			event := dm.NewFailedEvent(dm.EventSendUserIntoCacheFailed, dm.EventPlaceRedis,
				&strerr, id.String())
			us.audit.Log(ctx, event)
			return err
		}

		event := dm.NewSuccessEvent(dm.EventSendUserIntoCacheSuccess, dm.EventPlaceRedis, id.String())
		us.audit.Log(ctx, event)

		return nil
	})

	return err
}

type UserCacheOpt struct {
	dm.UserOpt
}

func UserCacheOptFromDomainOpt(opt *dm.UserOpt) *UserCacheOpt {
	return &UserCacheOpt{*opt}
}

func (uco *UserCacheOpt) Patches() []patch.FieldPatch {

	patches := []patch.FieldPatch{}

	if uco.UserName.Define && uco.UserName.Valid {
		patches = append(patches, patch.NewSetFPatch(FieldUserName, uco.UserName.Value))
	}

	if uco.IsDeleted.Define && uco.IsDeleted.Valid {
		patches = append(patches, patch.NewSetFPatch(FieldIsDeleted, deleteStatusFromBool(uco.IsDeleted.Value)))
	}

	if uco.Email.Define {
		if uco.Email.Valid {
			patches = append(patches, patch.NewSetFPatch(FieldEmail, uco.Email.Value))
		} else {
			patches = append(patches, patch.NewClearFPatch(FieldEmail))
		}
	}

	if uco.Phone.Define {
		if uco.Phone.Valid {
			patches = append(patches, patch.NewSetFPatch(FieldPhone, uco.Phone.Value))
		} else {
			patches = append(patches, patch.NewClearFPatch(FieldPhone))
		}
	}

	return patches
}

func (uco *UserCacheOpt) GetIndexManager() *index.IndexManager {

	im := NewUserIndexManager()

	if uco.UserName.Define && uco.UserName.Valid {
		im.SetIndex(FieldUserName, uco.UserName.Value)
	}

	if uco.Email.Define && uco.Email.Valid {
		im.SetIndex(FieldEmail, uco.Email.Value)
	}

	if uco.Phone.Define && uco.Phone.Valid {
		im.SetIndex(FieldPhone, uco.Phone.Value)
	}

	return im
}

type UserCache struct {
	Id        string // hex from uuid dm.User
	UserName  string
	Email     string
	Phone     string
	CreatedAt int64  // unix
	IsDeleted string // "1" or "0"
}

func (uc *UserCache) ToDomainUser() *dm.User {

	id, err := hexToUuid(uc.Id)
	if err != nil {
		slog.Error("Failed convert hex string to uuid", "err", err)
		return nil
	}

	return &dm.User{
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

func (uc *UserCache) GetIndexManager() *index.IndexManager {

	im := NewUserIndexManager()
	im.SetIndex(FieldUserName, uc.UserName)

	if uc.Email != "" {
		im.SetIndex(FieldEmail, uc.Email)
	}

	if uc.Phone != "" {
		im.SetIndex(FieldPhone, uc.Phone)
	}

	return im
}

func UserCacheFromDomainUser(user *dm.User) *UserCache {
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

func GetDataMapFromUserOpt(user *dm.UserOpt) map[string]interface{} {

	data := make(map[string]interface{})

	if user.UserName.Define && user.UserName.Valid {
		data[FieldUserName] = user.UserName.Value
	}

	if user.IsDeleted.Define && user.IsDeleted.Valid {
		data[FieldIsDeleted] = user.IsDeleted.Value
	}

	if user.Email.Define {
		if user.Email.Valid {
			data[FieldEmail] = user.Email.Value
		} else {
			data[FieldEmail] = ""
		}
	}

	if user.Phone.Define {
		if user.Phone.Valid {
			data[FieldPhone] = user.Phone.Value
		} else {
			data[FieldPhone] = ""
		}
	}

	return data
}

func (us *UserStore) BuildUpgratePlan(old *UserCache, patchs []patch.FieldPatch) *upgrateplan.UpdatePlan {

	plan := upgrateplan.UpdatePlan{}

	plan.SetField, plan.DelField = upgrateplan.DataOption(patchs)

	oldIm := old.GetIndexManager()
	newIm := oldIm.ApplyPatch(patchs)

	plan.Diff = newIm.Diff(oldIm)

	plan.NoChanges = len(plan.SetField) == 0 &&
		len(plan.DelField) == 0 &&
		plan.Diff.ToAdd.Len() == 0 &&
		plan.Diff.ToDelete.Len() == 0 &&
		plan.Diff.ToExpire.Len() == 0

	return &plan
}

func NewUserIndexManager() *index.IndexManager {
	return index.NewIndexManager(IndexKey, FieldUserName, FieldEmail, FieldPhone)
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

func rollbackIndex(ctx context.Context, client *redis.Client, keys ...string) error {

	if len(keys) == 0 {
		return nil
	}

	err := client.Del(ctx, keys...).Err()
	if err != nil {
		return custerr.ErrFailedRollbackInedex.Clone()
	}

	return nil
}

func createIndexKey(field string, value string) string {
	return fmt.Sprintf("%s%s:%s", IndexKey, field, value)
}
