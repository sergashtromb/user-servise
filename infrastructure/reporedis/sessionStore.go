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
	"user_service/config"
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
	accessLifetime int64
	repo           *Repository
	audit          dm.AuditService
	ttl            time.Duration
}

func NewSessionStore(repo *Repository, audit dm.AuditService, ttl time.Duration, cm *config.ConfigManager) *SessionStore {
	return &SessionStore{
		accessLifetime: int64(cm.Get().TokenConf.AccessLifeTime),
		repo:           repo,
		audit:          audit,
		ttl:            ttl,
	}
}

func (sst *SessionStore) Registration(ctx context.Context, session *dm.Session, familyId uuid.UUID) error {

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

	if familyId == uuid.Nil() {
		regerr.Fields = append(regerr.Fields, "family_id")
	}

	if len(regerr.Fields) != 0 {
		return regerr
	}

	localSession := SessionFromDomainSession(session)
	err := sst.repo.Do(ctx, func(ctx context.Context, client *redis.Client) error {

		hexFamId := hex.EncodeToString(familyId[:])
		hexid := hex.EncodeToString(session.UserId[:])

		refreshKey := makeKey(RefreshKey, hexid, hexFamId)
		ssKey := makeKey(SessionKey, hexid, hexFamId)

		data := localSession.ToMap()

		pipe := client.TxPipeline()
		setCmd := pipe.SetNX(ctx, ssKey, hexFamId, sst.ttl)
		pipe.HSet(ctx, refreshKey, data)
		pipe.Expire(ctx, refreshKey, sst.ttl)

		_, err := pipe.Exec(ctx)
		if err != nil {
			strerr := err.Error()
			event := dm.NewFailedEvent(dm.EventRegistrationSessionUserFailed, dm.EventPlaceRedis,
				&strerr, session.UserId.String(), traceId)
			sst.audit.Log(ctx, event)
			return err
		}

		ok, err := setCmd.Result()
		if err != nil || !ok {
			if err != nil {

				strerr := err.Error()
				event := dm.NewFailedEvent(dm.EventRegistrationSessionUserFailed, dm.EventPlaceRedis,
					&strerr, session.UserId.String(), traceId)
				sst.audit.Log(ctx, event)
				return err

			} else {

				strerr := custerr.ErrSessionAlredyExist.Error()
				event := dm.NewFailedEvent(dm.EventRegistrationSessionUserFailed, dm.EventPlaceRedis,
					&strerr, session.UserId.String(), traceId)
				sst.audit.Log(ctx, event)

			}

			return custerr.ErrSessionAlredyExist
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

func (sst *SessionStore) GetSessionByFamilyId(ctx context.Context, userId uuid.UUID, familyId uuid.UUID) (*dm.Session, error) {

	traceId, ok := ctx.Value(dm.TraceKey).(string)
	if !ok {
		traceId = ""
	}

	geterr := custerr.ErrBadArgs.Clone()
	if userId == uuid.Nil() {
		geterr.Fields = append(geterr.Fields, FieldUserId)
	}

	if familyId == uuid.Nil() {
		geterr.Fields = append(geterr.Fields, "family_id")
	}

	if len(geterr.Fields) != 0 {
		return nil, geterr
	}

	hexid := hex.EncodeToString(userId[:])
	hexFamilyId := hex.EncodeToString(familyId[:])
	hashRefresh := makeKey(RefreshKey, hexid, hexFamilyId)

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

// FORDEL
func (sst *SessionStore) UpdateVersion(ctx context.Context, userId uuid.UUID, familyId uuid.UUID) (string, error) {

	errBadArgs := custerr.ErrBadArgs.Clone()
	if userId == uuid.Nil() {
		errBadArgs.Fields = append(errBadArgs.Fields, "user_id")
	}
	if familyId == uuid.Nil() {
		errBadArgs.Fields = append(errBadArgs.Fields, "family_id")
	}

	if len(errBadArgs.Fields) > 0 {
		return "", errBadArgs
	}

	var ver string

	traceId, ok := ctx.Value(dm.TraceKey).(string)
	if !ok {
		traceId = ""
	}

	err := sst.repo.Do(ctx, func(ctx context.Context, client *redis.Client) error {

		userHex := hex.EncodeToString(userId[:])
		familyHex := hex.EncodeToString(familyId[:])

		key := makeKey(RefreshKey, userHex, familyHex)
		timeNow := time.Now().Unix()

		data, err := scripts.UpdateVersion.Run(ctx, client, []string{key}, timeNow, sst.accessLifetime).Result()
		if err != nil {

			strerr := err.Error()
			event := dm.NewFailedEvent(dm.EventUpdateVersionTokenFailed, dm.EventPlaceRedis,
				&strerr, userHex, traceId)
			sst.audit.Log(ctx, event)

			if strings.Contains(err.Error(), ErrLuaBadArgs) {
				return custerr.ErrBadArgs
			} else if strings.Contains(err.Error(), ErrLuaSessionNotFound) {
				return custerr.ErrNotFound
			} else if strings.Contains(err.Error(), ErrLuaSuspiciousRefreshRate) {
				return custerr.ErrSuspiciousRefreshRate
			} else if strings.Contains(err.Error(), ErrLuaBadVersion) {
				return custerr.ErrBadData
			} else {
				return err
			}
		}

		version, ok := data.(string)
		if !ok {
			return custerr.ErrBadData
		}

		ver = version

		event := dm.NewSuccessEvent(dm.EventUpdateVersionTokenSuccess, dm.EventPlaceRedis, userHex, traceId)
		sst.audit.Log(ctx, event)

		return nil
	})

	if err != nil {
		return "", err
	}

	return ver, nil
}

// TODO
// add new function for make grace periodic on 30 sec ttl
func (sst *SessionStore) CreateGracePeriodic(ctx context.Context, userId uuid.UUID, familyId uuid.UUID, gracePeriodic dm.GracePeriodic) error {
	return nil
}

// TODO
// add new function for update ip adress

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

func (sst *SessionStore) DeleteByRefresh(ctx context.Context, id uuid.UUID, familyId uuid.UUID) error {

	traceId, ok := ctx.Value(dm.TraceKey).(string)
	if !ok {
		traceId = ""
	}

	geterr := custerr.ErrBadArgs.Clone()
	if id == uuid.Nil() {
		geterr.Fields = append(geterr.Fields, FieldUserId)
	}

	if familyId == uuid.Nil() {
		geterr.Fields = append(geterr.Fields, "refresh_token")
	}

	if len(geterr.Fields) != 0 {
		return geterr
	}

	err := sst.repo.Do(ctx, func(ctx context.Context, client *redis.Client) error {

		hexid := hex.EncodeToString(id[:])
		hexFamilyId := hex.EncodeToString(familyId[:])
		hkey := makeKey(RefreshKey, hexid, hexFamilyId)
		keyWithUser := makeKey(SessionKey, hexid, hexFamilyId)

		qnty, err := client.Del(ctx, keyWithUser, hkey).Result()
		if err != nil {
			strerr := err.Error()
			event := dm.NewFailedEvent(dm.EventDeleteSessionFailed, dm.EventPlaceRedis, &strerr,
				hexFamilyId, traceId)
			sst.audit.Log(ctx, event)
			return err
		}
		// we have a two keys: session and refresh
		// they should be removed at the same time
		if qnty != 2 {
			strerr := custerr.ErrNotFound.Error()
			event := dm.NewFailedEvent(dm.EventDeleteSessionFailed, dm.EventPlaceRedis, &strerr,
				hexFamilyId, traceId)
			sst.audit.Log(ctx, event)
			return custerr.ErrNotFound
		}

		event := dm.NewSuccessEvent(dm.EventDeleteSessionSuccess, dm.EventPlaceRedis, hexFamilyId, traceId)
		sst.audit.Log(ctx, event)

		return nil

	})

	return err
}

type Session struct {
	UserId     string // user_id hex string
	DeviceId   string
	Ip         string
	Agent      string
	CreatedAt  int64
	Version    string
	LastUpdate int64
}

func (ss *Session) ToMap() map[string]interface{} {

	data := make(map[string]interface{})

	data[FieldUserId] = ss.UserId
	data[FieldDeviceId] = ss.DeviceId
	data[FieldIp] = ss.Ip
	data[FieldAgent] = ss.Agent
	data[FieldCreatedAt] = ss.CreatedAt
	data[FieldVersion] = ss.Version
	data[FieldLastUpdate] = ss.LastUpdate

	return data
}

func (ss *Session) ToDomain() (*dm.Session, error) {

	createdAt := time.Unix(ss.CreatedAt, 0)
	lastUpdate := time.Unix(ss.LastUpdate, 0)
	id, err := hexToUuid(ss.UserId)
	if err != nil {
		return nil, err
	}

	return &dm.Session{
		UserId:     id,
		DeviceId:   ss.DeviceId,
		Ip:         ss.Ip,
		Agent:      ss.Agent,
		CreatedAt:  createdAt,
		Version:    ss.Version,
		LastUpdate: lastUpdate,
	}, nil
}

func SessionFromDomainSession(ss *dm.Session) *Session {
	return &Session{
		UserId:     hex.EncodeToString(ss.UserId[:]),
		DeviceId:   ss.DeviceId,
		Ip:         ss.Ip,
		Agent:      ss.Agent,
		CreatedAt:  ss.CreatedAt.Unix(),
		Version:    ss.Version,
		LastUpdate: ss.LastUpdate.Unix(),
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

	intLastUpdate, err := strconv.ParseInt(data[FieldLastUpdate], 10, 64)
	if err != nil {
		return nil, err
	}

	ss.LastUpdate = intLastUpdate

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
