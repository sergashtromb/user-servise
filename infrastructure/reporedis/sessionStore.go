package reporedis

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
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

	traceId, ok := ctx.Value(dm.TraceKey).(string)
	if !ok {
		traceId = ""
	}

	regerr := custerr.ErrBadArgs.Clone()
	if session == nil {
		regerr.Fields = append(regerr.Fields, "session")
		return regerr
	}

	if session.UserId == uuid.Nil() {
		regerr.Fields = append(regerr.Fields, FieldUserId)
	}

	if len(refreshToken) == 0 {
		regerr.Fields = append(regerr.Fields, "refresh_token")
	}

	if len(regerr.Fields) != 0 {
		return regerr
	}

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
				&strerr, session.UserId.String(), traceId)
			sst.audit.Log(ctx, event)
			return err
		}

		event := dm.NewSuccessEvent(dm.EventRegistrationSessionUserSuccess, dm.EventPlaceRedis,
			session.UserId.String(), traceId)
		sst.audit.Log(ctx, event)

		return nil
	})

	return err
}

// one break session - is error for all
// cache can't have break session
func (sst *SessionStore) GetAllSession(ctx context.Context, userId uuid.UUID) ([]dm.Session, error) {

	traceId, ok := ctx.Value(dm.TraceKey).(string)
	if !ok {
		traceId = ""
	}

	if userId == uuid.Nil() {
		geterr := custerr.ErrBadArgs.Clone()
		geterr.Fields = append(geterr.Fields, FieldUserId)
		return nil, geterr
	}

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
				&strerr, userId.String(), traceId)
			sst.audit.Log(ctx, event)
			return err
		}

		if len(userKeys) == 0 {
			return nil
		}

		for i := 0; i < len(userKeys); i++ {
			trimsToken := strings.TrimPrefix(userKeys[i], makeKey(SessionKey, hexId, ""))
			userKeys[i] = makeKey(RefreshKey, hexId, trimsToken)
		}

		data := make([]*redis.MapStringStringCmd, 0)
		pipe := client.Pipeline()

		for _, val := range userKeys {
			elem := pipe.HGetAll(ctx, val)
			data = append(data, elem)
		}

		_, err := pipe.Exec(ctx)
		if err != nil {
			strerr := err.Error()
			event := dm.NewFailedEvent(dm.EventGetSessionUserFailed, dm.EventPlaceRedis, &strerr,
				hexId, traceId)
			sst.audit.Log(ctx, event)
			return err

		}

		var getErr error
		for _, elem := range data {

			val, err := elem.Result()
			if err != nil {
				strerr := err.Error()
				event := dm.NewFailedEvent(dm.EventGetSessionUserFailed, dm.EventPlaceRedis,
					&strerr, hexId, traceId)
				sst.audit.Log(ctx, event)
				getErr = errors.Join(getErr, err)
			}

			if len(val) != 0 {

				localSession, err := SessionFromMapString(val)
				if err != nil {
					strerr := err.Error()
					event := dm.NewFailedEvent(dm.EventGetSessionUserFailed, dm.EventPlaceRedis,
						&strerr, hexId, traceId)
					sst.audit.Log(ctx, event)
					getErr = errors.Join(getErr, err)
					getErr = errors.Join(getErr, custerr.ErrBadData)
					continue
				}

				session, err := localSession.ToDomain()
				if err != nil {
					strerr := err.Error()
					event := dm.NewFailedEvent(dm.EventGetSessionUserFailed, dm.EventPlaceRedis,
						&strerr, hexId, traceId)
					sst.audit.Log(ctx, event)
					getErr = errors.Join(getErr, err)
					getErr = errors.Join(getErr, custerr.ErrBadData)
					continue
				}

				result = append(result, *session)
			}
		}

		if getErr != nil {
			return getErr
		}

		event := dm.NewSuccessEvent(dm.EventGetSessionUserSuccess, dm.EventPlaceRedis,
			userId.String(), traceId)
		sst.audit.Log(ctx, event)

		return nil
	})

	if err != nil {
		return nil, err
	}

	return result, nil
}

func (sst *SessionStore) GetSessionByRefresh(ctx context.Context, userId uuid.UUID, refreshToken string) (*dm.Session, error) {

	traceId, ok := ctx.Value(dm.TraceKey).(string)
	if !ok {
		traceId = ""
	}

	geterr := custerr.ErrBadArgs.Clone()
	if userId == uuid.Nil() {
		geterr.Fields = append(geterr.Fields, FieldUserId)
	}

	if len(refreshToken) == 0 {
		geterr.Fields = append(geterr.Fields, "refresh_token")
	}

	if len(geterr.Fields) != 0 {
		return nil, geterr
	}

	hexid := hex.EncodeToString(userId[:])
	tokenHash := hashSumFromRefreshToken(refreshToken)
	hashRefresh := makeKey(RefreshKey, hexid, tokenHash)

	var session *dm.Session
	err := sst.repo.Do(ctx, func(ctx context.Context, client *redis.Client) error {

		data, err := client.HGetAll(ctx, hashRefresh).Result()
		if err != nil {
			strerr := err.Error()
			event := dm.NewFailedEvent(dm.EventGetSessionUserFailed, dm.EventPlaceRedis,
				&strerr, hashRefresh, traceId)
			sst.audit.Log(ctx, event)
			return err
		}

		if len(data) == 0 {
			return custerr.ErrNotFound
		}
		localSession, err := SessionFromMapString(data)
		if err != nil {
			strerr := err.Error()
			event := dm.NewFailedEvent(dm.EventGetSessionUserFailed, dm.EventPlaceRedis,
				&strerr, hashRefresh, traceId)
			sst.audit.Log(ctx, event)
			return custerr.ErrBadData
		}

		session, err = localSession.ToDomain()
		if err != nil {
			strerr := err.Error()
			event := dm.NewFailedEvent(dm.EventGetSessionUserFailed, dm.EventPlaceRedis,
				&strerr, hashRefresh, traceId)
			sst.audit.Log(ctx, event)
			return custerr.ErrBadData
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return session, nil
}

func (sst *SessionStore) UpdateRefreshToken(ctx context.Context, id uuid.UUID, oldToken string, newToken string) error {

	traceId, ok := ctx.Value(dm.TraceKey).(string)
	if !ok {
		traceId = ""
	}

	geterr := custerr.ErrBadArgs.Clone()
	if id == uuid.Nil() {
		geterr.Fields = append(geterr.Fields, FieldUserId)
	}

	if len(oldToken) == 0 {
		geterr.Fields = append(geterr.Fields, "old_token")
	}

	if len(newToken) == 0 {
		geterr.Fields = append(geterr.Fields, "new_token")
	}

	if len(geterr.Fields) != 0 {
		return geterr
	}

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
				&strerr, hexid, traceId)
			sst.audit.Log(ctx, event)
			return err
		}

		if res == 0 {
			return custerr.ErrNotFound
		}

		event := dm.NewSuccessEvent(dm.EventUpdateRefreshTokenSuccess, dm.EventPlaceRedis, hexid, traceId)
		sst.audit.Log(ctx, event)

		return nil
	})

	return err
}

func (sst *SessionStore) DeleteAll(ctx context.Context, id uuid.UUID) error {

	traceId, ok := ctx.Value(dm.TraceKey).(string)
	if !ok {
		traceId = ""
	}

	if id == uuid.Nil() {
		geterr := custerr.ErrBadArgs.Clone()
		geterr.Fields = append(geterr.Fields, FieldUserId)
		return geterr
	}

	err := sst.repo.Do(ctx, func(ctx context.Context, client *redis.Client) error {

		hexId := hex.EncodeToString(id[:])
		pattern := makeKey(SessionKey, hexId, "*")

		sessionKeys := make([]string, 0)
		keysFromBd := client.Scan(ctx, 0, pattern, 0).Iterator()
		for keysFromBd.Next(ctx) {
			sessionKeys = append(sessionKeys, keysFromBd.Val())
		}

		if err := keysFromBd.Err(); err != nil {
			strerr := err.Error()
			event := dm.NewFailedEvent(dm.EventGetSessionUserFailed, dm.EventPlaceRedis,
				&strerr, id.String(), traceId)
			sst.audit.Log(ctx, event)
			return err
		}

		if len(sessionKeys) == 0 {
			return nil
		}

		refreshKeys := make([]string, len(sessionKeys))
		for i := 0; i < len(sessionKeys); i++ {
			trimsToken := strings.TrimPrefix(sessionKeys[i], makeKey(SessionKey, hexId, ""))
			refreshKeys[i] = makeKey(RefreshKey, hexId, trimsToken)
		}

		pipe := client.TxPipeline()
		pipe.Del(ctx, sessionKeys...)
		pipe.Del(ctx, refreshKeys...)

		_, err := pipe.Exec(ctx)
		if err != nil {
			strerr := err.Error()
			event := dm.NewFailedEvent(dm.EventDeleteSessionFailed, dm.EventPlaceRedis,
				&strerr, id.String(), traceId)
			sst.audit.Log(ctx, event)
			return err
		}

		event := dm.NewSuccessEvent(dm.EventDeleteSessionSuccess, dm.EventPlaceRedis, id.String(), traceId)
		sst.audit.Log(ctx, event)

		return nil
	})

	return err
}

func (sst *SessionStore) DeleteByRefresh(ctx context.Context, id uuid.UUID, refresh string) error {

	traceId, ok := ctx.Value(dm.TraceKey).(string)
	if !ok {
		traceId = ""
	}

	geterr := custerr.ErrBadArgs.Clone()
	if id == uuid.Nil() {
		geterr.Fields = append(geterr.Fields, FieldUserId)
	}

	if len(refresh) == 0 {
		geterr.Fields = append(geterr.Fields, "refresh_token")
	}

	if len(geterr.Fields) != 0 {
		return geterr
	}

	err := sst.repo.Do(ctx, func(ctx context.Context, client *redis.Client) error {

		hexid := hex.EncodeToString(id[:])
		hashRefresh := hashSumFromRefreshToken(refresh)
		hkey := makeKey(RefreshKey, hexid, hashRefresh)
		keyWithUser := makeKey(SessionKey, hexid, hashRefresh)

		qnty, err := client.Del(ctx, keyWithUser, hkey).Result()
		if err != nil {
			strerr := err.Error()
			event := dm.NewFailedEvent(dm.EventDeleteSessionFailed, dm.EventPlaceRedis, &strerr,
				hashRefresh, traceId)
			sst.audit.Log(ctx, event)
			return err
		}
		// we have a two keys: session and refresh
		// they should be removed at the same time
		if qnty != 2 {
			strerr := custerr.ErrNotFound.Error()
			event := dm.NewFailedEvent(dm.EventDeleteSessionFailed, dm.EventPlaceRedis, &strerr,
				hashRefresh, traceId)
			sst.audit.Log(ctx, event)
			return custerr.ErrNotFound
		}

		event := dm.NewSuccessEvent(dm.EventDeleteSessionSuccess, dm.EventPlaceRedis, hashRefresh, traceId)
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
	Version   string
}

func (ss *Session) ToMap() map[string]interface{} {

	data := make(map[string]interface{})

	data[FieldUserId] = ss.UserId
	data[FieldDeviceId] = ss.DeviceId
	data[FieldIp] = ss.Ip
	data[FieldAgent] = ss.Agent
	data[FieldCreatedAt] = ss.CreatedAt
	data[FieldVersion] = ss.Version

	return data
}

func (ss *Session) ToDomain() (*dm.Session, error) {

	createdAt := time.Unix(ss.CreatedAt, 0)
	id, err := hexToUuid(ss.UserId)
	if err != nil {
		return nil, err
	}

	return &dm.Session{
		UserId:    id,
		DeviceId:  ss.DeviceId,
		Ip:        ss.Ip,
		Agent:     ss.Agent,
		CreatedAt: createdAt,
		Version:   ss.Version,
	}, nil
}

func SessionFromDomainSession(ss *dm.Session) *Session {
	return &Session{
		UserId:    hex.EncodeToString(ss.UserId[:]),
		DeviceId:  ss.DeviceId,
		Ip:        ss.Ip,
		Agent:     ss.Agent,
		CreatedAt: ss.CreatedAt.Unix(),
		Version:   ss.Version,
	}
}

func SessionFromMapString(data map[string]string) (*Session, error) {

	ss := Session{
		UserId:   data[FieldUserId],
		DeviceId: data[FieldDeviceId],
		Ip:       data[FieldIp],
		Agent:    data[FieldAgent],
		Version:  data[FieldVersion],
	}

	intCreatedAt, err := strconv.ParseInt(data[FieldCreatedAt], 10, 64)
	if err != nil {
		return nil, err
	}

	ss.CreatedAt = intCreatedAt

	return &ss, nil
}

func hashSumFromRefreshToken(token string) string {

	hsh := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hsh[:])
}

func makeKey(typeKey string, hexid string, tokenHash string) string {
	incStr := fmt.Sprintf(typeKey, hexid)
	return fmt.Sprintf("%s%s", incStr, tokenHash)
}
