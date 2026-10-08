package reporedis

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"
	dm "user_service/domain"
	"uuid"

	"github.com/redis/go-redis/v9"
)

const (
	SessionKey = "session:user:"
	RefreshKey = "session:refresh:"
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
		refreshKey := fmt.Sprintf("%s%s", RefreshKey, hashFromRefresh)
		ssKey := fmt.Sprintf("%s%s:%s", SessionKey, localSession.UserId, hashFromRefresh)

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

		event := dm.NewSuccessEvent(dm.EventRegistrationSessionUserFailed, dm.EventPlaceRedis,
			session.UserId.String())
		sst.audit.Log(ctx, event)

		return nil
	})

	return err
}

// TEST write func test
func (sst *SessionStore) GetAllSession(ctx context.Context, userId uuid.UUID) ([]dm.Session, error) {

	hexId := hex.EncodeToString(userId[:])
	key := fmt.Sprintf("%s%s:*", SessionKey, hexId)

	result := make([]dm.Session, 0)

	err := sst.repo.Do(ctx, func(ctx context.Context, client *redis.Client) error {

		refreshKeys := make([]string, 0)
		iter := client.Scan(ctx, 0, key, 0).Iterator()
		for iter.Next(ctx) {
			refreshKeys = append(refreshKeys, iter.Val())
		}

		if err := iter.Err(); err != nil {
			strerr := err.Error()
			event := dm.NewFailedEvent(dm.EventGetSessionUserFailed, dm.EventPlaceRedis,
				&strerr, userId.String())
			sst.audit.Log(ctx, event)
			return err
		}

		if len(refreshKeys) != 0 {
			return nil
		}

		vals, err := client.MGet(ctx, refreshKeys...).Result()
		if err != nil {
			strerr := err.Error()
			event := dm.NewFailedEvent(dm.EventGetSessionUserFailed, dm.EventPlaceRedis,
				&strerr, userId.String())
			sst.audit.Log(ctx, event)
			return err
		}

		for _, val := range vals {
			if val != nil {
				session := SessionFromMapString(val.(map[string]string)).ToDomain()
				result = append(result, *session)
			}
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return result, nil
}

func (sst *SessionStore) GetSessionByRefresh(ctx context.Context, refreshToken string) (*dm.Session, error) {

	hashRefresh := fmt.Sprintf("%s%s", RefreshKey, hashSumFromRefreshToken(refreshToken))
	var session *dm.Session
	err := sst.repo.Do(ctx, func(ctx context.Context, client *redis.Client) error {

		data, err := client.HGetAll(ctx, hashRefresh).Result()
		if err != nil {
			strerr := err.Error()
			event := dm.NewFailedEvent(dm.EventGetSessionUserFailed, dm.EventPlaceRedis,
				&strerr, refreshToken)
			sst.audit.Log(ctx, event)
			return err
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

func (sst *SessionStore) UpdateRefreshToken(ctx context.Context, oldToken string, newToken string) error {

	err := sst.repo.Do(ctx, func(ctx context.Context, client *redis.Client) error {

		hashOld := hashSumFromRefreshToken(oldToken)
		hashNew := hashSumFromRefreshToken(newToken)

		keyOld := fmt.Sprintf("%s%s", RefreshKey, hashOld)
		keyNew := fmt.Sprintf("%s%s", RefreshKey, hashNew)

		hexUserId, err := client.HGet(ctx, keyOld, FieldUserId).Result()
		if err != nil {
			strerr := err.Error()
			event := dm.NewFailedEvent(dm.EventGetSessionUserFailed, dm.EventPlaceRedis,
				&strerr, oldToken)
			sst.audit.Log(ctx, event)
			return err
		}

		keyWithUserOld := fmt.Sprintf("%s%s:%s", SessionKey, hexUserId, hashOld)
		keyWithUserNew := fmt.Sprintf("%s%s:%s", SessionKey, hexUserId, hashNew)

		pipe := client.TxPipeline()

		pipe.Rename(ctx, keyOld, keyNew)
		pipe.Rename(ctx, keyWithUserOld, keyWithUserNew)
		_, err = pipe.Exec(ctx)

		if err != nil {
			strerr := err.Error()
			event := dm.NewFailedEvent(dm.EventGetSessionUserFailed, dm.EventPlaceRedis,
				&strerr, oldToken)
			sst.audit.Log(ctx, event)
			return err
		}

		return nil
	})

	return err
}

func (sst *SessionStore) DeleteAll(ctx context.Context, id uuid.UUID) error {

	sst.repo.Do(ctx, func(ctx context.Context, client *redis.Client) error {

		hexId := hex.EncodeToString(id[:])
		pattern := fmt.Sprintf("%s%s:*", SessionKey, hexId)

		keys := make([]string, 0)
		keysFromBd := client.Scan(ctx, 0, pattern, 0).Iterator()
		for keysFromBd.Next(ctx) {
			keys = append(keys, keysFromBd.Val())
		}

		//if err
		return nil
	})

	return nil
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
