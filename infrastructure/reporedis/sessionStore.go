package reporedis

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
	dm "user_service/domain"
	"user_service/infrastructure/reporedis/custerr"
	"user_service/infrastructure/reporedis/scripts"
	"uuid"

	"github.com/redis/go-redis/v9"
)

const (
	SessionKey = "session:{%v}:user:"
	RefreshKey = "session:{%v}:refresh:"
)

type SessionStore struct {
	repo  *Repository
	audit dm.AuditService
	ttl   time.Duration
}

func NewSessionStore(repo *Repository, audit dm.AuditService, ttl time.Duration) *SessionStore {
	return &SessionStore{
		repo:  repo,
		audit: audit,
		ttl:   ttl,
	}
}

func (sst *SessionStore) Registration(ctx context.Context, session *dm.Session, refreshToken string) error {

	localSession := SessionFromDomainSession(session)
	err := sst.repo.Do(ctx, func(ctx context.Context, client *redis.Client) error {

		hashFromRefresh := hashSumFromRefreshToken(refreshToken)
		hexid := hex.EncodeToString(session.UserId[:])

		refreshKey := makeKey(RefreshKey, hexid, hashFromRefresh)
		ssKey := makeKey(SessionKey, hexid, hashFromRefresh)

		data := localSession.ToMap()

		pipe := client.TxPipeline()
		pipe.HSet(ctx, refreshKey, data)
		pipe.Expire(ctx, refreshKey, sst.ttl)
		pipe.Set(ctx, ssKey, hashFromRefresh, sst.ttl)

		_, err := pipe.Exec(ctx)
		if err != nil {
			strerr := err.Error()
			event := dm.NewFailedEvent(dm.EventRegistrationSessionUserFailed, dm.EventPlaceRedis,
				&strerr, session.UserId.String())
			sst.audit.Log(ctx, event)
			return err
		}

		event := dm.NewSuccessEvent(dm.EventRegistrationSessionUserSuccess, dm.EventPlaceRedis,
			session.UserId.String())
		sst.audit.Log(ctx, event)

		return nil
	})

	return err
}

func (sst *SessionStore) GetAllSession(ctx context.Context, userId uuid.UUID) ([]dm.Session, error) {

	hexId := hex.EncodeToString(userId[:])
	key := makeKey(SessionKey, hexId, "*")

	result := make([]dm.Session, 0)

	err := sst.repo.Do(ctx, func(ctx context.Context, client *redis.Client) error {

		userKeys := make([]string, 0)
		iter := client.Scan(ctx, 0, key, 0).Iterator()
		for iter.Next(ctx) {
			userKeys = append(userKeys, iter.Val())
		}

		if err := iter.Err(); err != nil {
			strerr := err.Error()
			event := dm.NewFailedEvent(dm.EventGetSessionUserFailed, dm.EventPlaceRedis,
				&strerr, userId.String())
			sst.audit.Log(ctx, event)
			return err
		}

		if len(userKeys) == 0 {
			return nil
		}

		for i := 0; i < len(userKeys); i++ {
			userKeys[i] = strings.Trim(userKeys[i], makeKey(SessionKey, hexId, ""))
		}

		data := make([]*redis.MapStringInterfaceCmd, 0)
		pipe := client.TxPipeline()

		for _, val := range userKeys {
			elem := pipe.HGetAll(ctx, val)
			data = append(data, elem)

			data, err := client.HGetAll(ctx, val).Result()
			if err != nil {
				strerr := err.Error()
				event := dm.NewFailedEvent(dm.EventGetSessionUserFailed, dm.EventPlaceRedis,
					&strerr, userId.String())
				sst.audit.Log(ctx, event)
				return err
			}

			if len(data) != 0 {
				session := SessionFromMapString(data).ToDomain()
				result = append(result, *session)
			}
		}

		event := dm.NewSuccessEvent(dm.EventGetSessionUserSuccess, dm.EventPlaceRedis,
			userId.String())
		sst.audit.Log(ctx, event)

		return nil
	})

	if err != nil {
		return nil, err
	}

	return result, nil
}

func (sst *SessionStore) GetSessionByRefresh(ctx context.Context, userId uuid.UUID, refreshToken string) (*dm.Session, error) {

	hexid := hex.EncodeToString(userId[:])
	tokenHash := hashSumFromRefreshToken(refreshToken)
	hashRefresh := makeKey(RefreshKey, hexid, tokenHash)

	var session *dm.Session
	err := sst.repo.Do(ctx, func(ctx context.Context, client *redis.Client) error {

		data, err := client.HGetAll(ctx, hashRefresh).Result()
		if err != nil {
			strerr := err.Error()
			event := dm.NewFailedEvent(dm.EventGetSessionUserFailed, dm.EventPlaceRedis,
				&strerr, hashRefresh)
			sst.audit.Log(ctx, event)
			return err
		}

		if len(data) == 0 {
			return custerr.ErrNotFound
		}
		session = SessionFromMapString(data).ToDomain()

		// XXX ?update
		return nil
	})

	if err != nil {
		return nil, err
	}

	return session, nil
}

func (sst *SessionStore) UpdateRefreshToken(ctx context.Context, id uuid.UUID, oldToken string, newToken string) error {

	err := sst.repo.Do(ctx, func(ctx context.Context, client *redis.Client) error {

		hashOld := hashSumFromRefreshToken(oldToken)
		hashNew := hashSumFromRefreshToken(newToken)
		hexid := hex.EncodeToString(id[:])

		refreshOldKey := makeKey(RefreshKey, hexid, hashOld)
		refreshNewKey := makeKey(RefreshKey, hexid, hashNew)

		sessionOldKey := makeKey(SessionKey, hexid, hashOld)
		sessionNewKey := makeKey(SessionKey, hexid, hashNew)

		res, err := scripts.UpdateRefreshToken.Run(ctx, client, []string{
			refreshOldKey,
			sessionOldKey,
			refreshNewKey,
			sessionNewKey,
		}, int(sst.ttl.Seconds()), hashNew).Int()

		if err != nil {
			strerr := err.Error()
			event := dm.NewFailedEvent(dm.EventUpdateRefreshTokenFailed, dm.EventPlaceRedis,
				&strerr, hexid)
			sst.audit.Log(ctx, event)
			return err
		}

		if res == 0 {
			return custerr.ErrNotFound
		}

		event := dm.NewSuccessEvent(dm.EventUpdateRefreshTokenSuccess, dm.EventPlaceRedis, hexid)
		sst.audit.Log(ctx, event)

		return nil
	})

	return err
}

func (sst *SessionStore) DeleteAll(ctx context.Context, id uuid.UUID) error {

	err := sst.repo.Do(ctx, func(ctx context.Context, client *redis.Client) error {

		hexId := hex.EncodeToString(id[:])
		pattern := makeKey(SessionKey, hexId, "*")

		keys := make([]string, 0)
		keysFromBd := client.Scan(ctx, 0, pattern, 0).Iterator()
		for keysFromBd.Next(ctx) {
			keys = append(keys, keysFromBd.Val())
		}

		if err := keysFromBd.Err(); err != nil {
			strerr := err.Error()
			event := dm.NewFailedEvent(dm.EventGetSessionUserFailed, dm.EventPlaceRedis,
				&strerr, id.String())
			sst.audit.Log(ctx, event)
			return err
		}

		if len(keys) == 0 {
			return nil
		}

		// FIXME change code
		// userKeys is string's slice "session:user:hex_user_id:hash_refresh_token"
		// add trim function for del "session:user:hex_user_id:"
		keysForDel, err := client.MGet(ctx, keys...).Result()
		if err != nil {
			strerr := err.Error()
			event := dm.NewFailedEvent(dm.EventGetSessionUserFailed, dm.EventPlaceRedis,
				&strerr, id.String())
			sst.audit.Log(ctx, event)
			return err
		}

		if len(keysForDel) == 0 {
			return nil
		}

		keysString := interfaceSliceToStringSlice(keysForDel)
		if len(keysString) == 0 {
			return nil
		}

		for i := 0; i < len(keysString); i++ {
			keysString[i] = makeKey(RefreshKey, hexId, keysString[i])
		}

		pipe := client.TxPipeline()
		pipe.Del(ctx, keysString...)
		pipe.Del(ctx, keys...)

		_, err = pipe.Exec(ctx)
		if err != nil {
			strerr := err.Error()
			event := dm.NewFailedEvent(dm.EventDeleteSessionFailed, dm.EventPlaceRedis,
				&strerr, id.String())
			sst.audit.Log(ctx, event)
			return err
		}

		event := dm.NewSuccessEvent(dm.EventDeleteSessionSuccess, dm.EventPlaceRedis, id.String())
		sst.audit.Log(ctx, event)

		return nil
	})

	return err
}

func (sst *SessionStore) DeletByRefresh(ctx context.Context, id uuid.UUID, refresh string) error {

	err := sst.repo.Do(ctx, func(ctx context.Context, client *redis.Client) error {

		hexid := hex.EncodeToString(id[:])
		hashRefresh := hashSumFromRefreshToken(refresh)
		hkey := makeKey(RefreshKey, hexid, hashRefresh)
		keyWithUser := makeKey(SessionKey, hexid, hashRefresh)

		_, err := client.Del(ctx, keyWithUser, hkey).Result()
		if err != nil {
			strerr := err.Error()
			event := dm.NewFailedEvent(dm.EventDeleteSessionFailed, dm.EventPlaceRedis, &strerr,
				hashRefresh)
			sst.audit.Log(ctx, event)
			return err
		}

		event := dm.NewSuccessEvent(dm.EventDeleteSessionSuccess, dm.EventPlaceRedis, hashRefresh)
		sst.audit.Log(ctx, event)

		return nil

	})

	return err
}

type Session struct {
	UserId    string // user_id hex string
	DeviceId  string
	Ip        string
	Agent     string
	CreatedAt int64
	ExpAt     int64
}

func (ss *Session) ToMap() map[string]interface{} {

	data := make(map[string]interface{})

	data[FieldUserId] = ss.UserId
	data[FieldDeviceId] = ss.DeviceId
	data[FieldIp] = ss.Ip
	data[FieldAgent] = ss.Agent
	data[FieldCreatedAt] = ss.CreatedAt
	data[FieldExpAt] = ss.ExpAt

	return data
}

func (ss *Session) ToDomain() *dm.Session {

	expAt := time.Unix(ss.ExpAt, 0)
	createdAt := time.Unix(ss.CreatedAt, 0)
	id, _ := hexToUuid(ss.UserId)

	return &dm.Session{
		UserId:    id,
		DeviceId:  ss.DeviceId,
		Ip:        ss.Ip,
		Agent:     ss.Agent,
		CreatedAt: createdAt,
		ExpAt:     expAt,
	}
}

func SessionFromDomainSession(ss *dm.Session) *Session {
	return &Session{
		UserId:    hex.EncodeToString(ss.UserId[:]),
		DeviceId:  ss.DeviceId,
		Ip:        ss.Ip,
		Agent:     ss.Agent,
		CreatedAt: ss.CreatedAt.Unix(),
		ExpAt:     ss.ExpAt.Unix(),
	}
}

func SessionFromMapString(data map[string]string) *Session {

	ss := Session{
		UserId:   data[FieldUserId],
		DeviceId: data[FieldDeviceId],
		Ip:       data[FieldIp],
		Agent:    data[FieldAgent],
	}

	intCreatedAt, err := strconv.ParseInt(data[FieldCreatedAt], 10, 64)
	if err != nil {
		intCreatedAt = 0
	}

	ss.CreatedAt = intCreatedAt

	intExpAt, err := strconv.ParseInt(data[FieldExpAt], 10, 64)
	if err != nil {
		intExpAt = 0
	}

	ss.ExpAt = intExpAt

	return &ss
}

func hashSumFromRefreshToken(token string) string {

	hsh := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hsh[:])
}

func interfaceSliceToStringSlice(input []interface{}) []string {

	output := make([]string, 0, len(input))
	for _, val := range input {
		if val != nil {
			output = append(output, val.(string))
		}
	}

	return output
}

func makeKey(typeKey string, hexid string, tokenHash string) string {
	incStr := fmt.Sprintf(typeKey, hexid)
	return fmt.Sprintf("%v%v", incStr, tokenHash)
}
