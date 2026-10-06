package reporedis

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"time"
	dm "user_service/domain"
	"user_service/pkg/repoerrors"
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

var (
	ErrUserAlredyExist      = repoerrors.NewError(RepoName, "user alredy exist", "001")
	ErrFailedRollbackInedex = repoerrors.NewFatalErr(RepoName, "failed rollback index", "002")
	ErrSetIndexInRedis      = repoerrors.NewError(RepoName, "failed set index", "003")
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

		indexs, ok := userCache.GetAllIndexs()
		if ok {
			err := setIndex(ctx, client, indexs, userCache.Id, key, us.ttl)
			if err != nil {
				errString := err.Error()

				event := dm.NewFailedEvent(dm.EventSendUserIntoCacheFailed, dm.EventPlaceRedis,
					&errString, user.Id.String())
				us.audit.Log(ctx, event)
				return err
			}
		}

		pipe := client.Pipeline()
		pipe.HSet(ctx, key, data)
		pipe.Expire(ctx, key, us.ttl)

		_, err := pipe.Exec(ctx)
		if err != nil {
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

	key := fmt.Sprintf("%s%s", UserKey, hex.EncodeToString(id[:]))

	err := us.repo.Do(ctx, func(ctx context.Context, client *redis.Client) error {

		indexManagerOpt := GetIndexManagerFromUserOpt(userOpt)
		if indexManagerOpt.Len() == 0 {
			event := dm.NewSuccessEvent(dm.EventSendUserIntoCacheSuccess,
				dm.EventPlaceRedis, id.String())
			us.audit.Log(ctx, event)
			return nil
		}

		data, err := client.HGetAll(ctx, key).Result()
		if err != nil {
			strerr := err.Error()
			event := dm.NewFailedEvent(dm.EventGetUserIntoCacheFailed, dm.EventPlaceRedis,
				&strerr, id.String())
			us.audit.Log(ctx, event)

			return err
		}

		oldUserCache := UserCacheFromMapString(data)

		var indexForAddOrUpdate []string
		var oldIndexForDelete []string
		// FIXME Не удаляются поля если они прилетели на удаление
		// FIXME не помечаются на удаление данные если прилетело поле только IsDeleted

		// check up
		fs2, _ := indexManagerOpt.GetFields()
		i1, ok := oldUserCache.Im.GetIndexsByFields(fs2...)
		if ok {
			indexForAddOrUpdate, _ = indexManagerOpt.GetIndexsNotIncludedIndexs(i1...)
			fieldsByForAddAndDelete, _ := indexManagerOpt.GetFieldsByIndexs(indexForAddOrUpdate...)
			oldIndexForDelete, _ = oldUserCache.GetIndexByFields(fieldsByForAddAndDelete...)

		} else {
			// don't have collision
			indexForAddOrUpdate, _ = indexManagerOpt.GetIndexs()
		}

		err = setIndex(ctx, client, indexForAddOrUpdate, hex.EncodeToString(id[:]), key, us.ttl)
		if err != nil {
			strerr := err.Error()
			event := dm.NewFailedEvent(dm.EventSendUserIntoCacheFailed, dm.EventPlaceRedis,
				&strerr, id.String())
			us.audit.Log(ctx, event)

			return err
		}

		pipe := client.Pipeline()
		dataForChange := GetDataMapFromUserOpt(userOpt)

		pipe.HSet(ctx, key, dataForChange)
		pipe.Expire(ctx, key, us.ttl)

		_, err = pipe.Exec(ctx)
		if err != nil {

			if rolErr := rollbackIndex(ctx, client, indexForAddOrUpdate...); rolErr != nil {
				strerr := rolErr.Error()
				event := dm.NewFailedEvent(dm.EventSendUserIntoCacheFailed, dm.EventPlaceRedis,
					&strerr, id.String())
				us.audit.Log(ctx, event)

				return rolErr
			}

			strerr := err.Error()
			event := dm.NewFailedEvent(dm.EventSendUserIntoCacheFailed, dm.EventPlaceRedis,
				&strerr, id.String())
			us.audit.Log(ctx, event)

			return err
		}

		if rolErr := rollbackIndex(ctx, client, oldIndexForDelete...); rolErr != nil {
			strerr := rolErr.Error()
			event := dm.NewFailedEvent(dm.EventSendUserIntoCacheFailed, dm.EventPlaceRedis,
				&strerr, id.String())
			us.audit.Log(ctx, event)

			return rolErr
		}

		event := dm.NewSuccessEvent(dm.EventSendUserIntoCacheSuccess, dm.EventPlaceRedis, id.String())
		us.audit.Log(ctx, event)

		return nil
	})

	return err
}

func updateIndex(ctx context.Context, audit dm.AuditService, client *redis.Client, id uuid.UUID, key string,
	userOpt *dm.UserOpt, ttl time.Duration) ([]string, []string, error) {

	indexManagerOpt := GetIndexManagerFromUserOpt(userOpt)
	if indexManagerOpt.Len() == 0 {
		event := dm.NewSuccessEvent(dm.EventSendUserIntoCacheSuccess,
			dm.EventPlaceRedis, id.String())
		audit.Log(ctx, event)
		return nil, nil, nil
	}

	data, err := client.HGetAll(ctx, key).Result()
	if err != nil {
		strerr := err.Error()
		event := dm.NewFailedEvent(dm.EventGetUserIntoCacheFailed, dm.EventPlaceRedis,
			&strerr, id.String())
		audit.Log(ctx, event)

		return nil, nil, err
	}

	oldUserCache := UserCacheFromMapString(data)

	var indexForAddOrUpdate []string
	var oldIndexForDelete []string
	// FIXME Не удаляются поля если они прилетели на удаление
	// FIXME не помечаются на удаление данные если прилетело поле только IsDeleted

	// check up
	fs2, _ := indexManagerOpt.GetFields()
	i1, ok := oldUserCache.Im.GetIndexsByFields(fs2...)
	if ok {
		indexForAddOrUpdate, _ = indexManagerOpt.GetIndexsNotIncludedIndexs(i1...)
		fieldsByForAddAndDelete, _ := indexManagerOpt.GetFieldsByIndexs(indexForAddOrUpdate...)
		oldIndexForDelete, _ = oldUserCache.GetIndexByFields(fieldsByForAddAndDelete...)

	} else {
		// don't have collision
		indexForAddOrUpdate, _ = indexManagerOpt.GetIndexs()
	}

	err = setIndex(ctx, client, indexForAddOrUpdate, hex.EncodeToString(id[:]), key, ttl)
	if err != nil {
		strerr := err.Error()
		event := dm.NewFailedEvent(dm.EventSendUserIntoCacheFailed, dm.EventPlaceRedis,
			&strerr, id.String())
		audit.Log(ctx, event)

		return nil, nil, err
	}
	return indexForAddOrUpdate, oldIndexForDelete, nil
}

type UserCache struct {
	Id        string // hex from uuid dm.User
	UserName  string
	Email     string
	Phone     string
	CreatedAt int64  // unix
	IsDeleted string // "1" or "0"
	Im        *IndexManager
}

func (uc *UserCache) GetAllIndexs() ([]string, bool) {
	return uc.Im.GetIndexs()
}

func (uc *UserCache) GetIndexByFields(fields ...string) ([]string, bool) {
	return uc.Im.GetIndexsByFields(fields...)
}

func (uc *UserCache) GetFieldForIndex() ([]string, bool) {
	return uc.Im.GetFields()
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

func UserCacheFromDomainUser(user *dm.User) *UserCache {

	im := NewIndexManager(IndexKey)
	im.SetIndex(FieldUserName, user.UserName)

	if user.Email != "" {
		im.SetIndex(FieldEmail, user.Email)
	}

	if user.Phone != "" {
		im.SetIndex(FieldPhone, user.Phone)
	}

	return &UserCache{
		Id:        hex.EncodeToString(user.Id[:]),
		UserName:  user.UserName,
		Email:     user.Email,
		Phone:     user.Phone,
		CreatedAt: user.CreatedAt.Unix(),
		IsDeleted: deleteStatusFromBool(user.IsDeleted),
		Im:        im,
	}
}

func UserCacheFromMapString(data map[string]string) *UserCache {

	createdAt, err := strconv.ParseInt(data[FieldCreatedAt], 10, 64)
	if err != nil {
		createdAt = 0
	}

	im := NewIndexManager(IndexKey)
	im.SetIndex(FieldUserName, data[FieldUserName])

	if data[FieldEmail] != "" {
		im.SetIndex(FieldEmail, data[FieldEmail])
	}

	if data[FieldPhone] != "" {
		im.SetIndex(FieldPhone, data[FieldPhone])
	}

	return &UserCache{
		Id:        data[FieldId],
		UserName:  data[FieldUserName],
		Email:     data[FieldEmail],
		Phone:     data[FieldPhone],
		CreatedAt: createdAt,
		IsDeleted: data[FieldIsDeleted],
		Im:        im,
	}
}

func GetIndexManagerFromUserOpt(user *dm.UserOpt) *IndexManager {

	im := NewIndexManager(IndexKey)

	if user.UserName.Define {
		if user.UserName.Valid {
			im.SetIndex(FieldUserName, user.UserName.Value)
		}
	}

	if user.Email.Define {
		if user.Email.Valid {
			im.SetIndex(FieldEmail, user.Email.Value)
		}
	}

	if user.Phone.Define {
		if user.Phone.Valid {
			im.SetIndex(FieldPhone, user.Phone.Value)
		}
	}

	return im
}

func GetIndexFromUserOpt(user *dm.UserOpt) []string {

	keys := make([]string, 0, 3)

	if user.UserName.Define {
		if user.UserName.Valid {
			keys = append(keys, createIndexKey(FieldUserName, user.UserName.Value))
		}
	}

	if user.Email.Define {
		if user.Email.Valid {
			keys = append(keys, createIndexKey(FieldEmail, user.Email.Value))
		}
	}

	if user.Phone.Define {
		if user.Phone.Valid {
			keys = append(keys, createIndexKey(FieldPhone, user.Phone.Value))
		}
	}

	return keys
}

func GetFieldsForIndexFromUserOpt(user *dm.UserOpt) []string {

	fields := make([]string, 0, 3)
	if user.UserName.Define && user.UserName.Valid {
		fields = append(fields, FieldUserName)
	}

	if user.Email.Define {
		fields = append(fields, FieldEmail)
	}

	if user.Phone.Define {
		fields = append(fields, FieldPhone)
	}

	return fields
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

func GetIndexFromFields(fieldsAndValues ...string) ([]string, error) {

	if len(fieldsAndValues)%2 != 0 {
		return nil, errors.New("an odd number of arguments were passed")
	}

	keys := make([]string, 0)

	for i := 0; i < len(fieldsAndValues)-1; i += 2 {
		index := createIndexKey(fieldsAndValues[i], fieldsAndValues[i+1])
		keys = append(keys, index)
	}

	return keys, nil
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

func setIndex(ctx context.Context, client *redis.Client, indexKeys []string, id, keyForUpdateTtl string, ttl time.Duration) error {

	keysForRollback := make([]string, 0, 3)

	for _, key := range indexKeys {

		ok, err := client.SetNX(ctx, key, id, ttl).Result()
		if err != nil {
			if rollErr := rollbackIndex(ctx, client, keysForRollback...); rollErr != nil {
				return rollErr
			}
			return ErrSetIndexInRedis
		}

		if !ok {
			if rollErr := rollbackIndex(ctx, client, keysForRollback...); rollErr != nil {
				return rollErr
			}

			errUserExist := ErrUserAlredyExist
			errUserExist.Fields = make([]string, 0, 1)
			errUserExist.Fields = append(errUserExist.Fields, key)
			return errUserExist
		}

		keysForRollback = append(keysForRollback, key)
		client.Expire(ctx, keyForUpdateTtl, ttl)
	}

	return nil
}

func rollbackIndex(ctx context.Context, client *redis.Client, keys ...string) error {

	if len(keys) == 0 {
		return nil
	}

	err := client.Del(ctx, keys...).Err()
	if err != nil {
		return ErrFailedRollbackInedex
	}

	return nil
}

func createIndexKey(field string, value string) string {
	return fmt.Sprintf("%s%s:%s", IndexKey, field, value)
}
