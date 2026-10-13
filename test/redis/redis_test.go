package test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"
	"time"
	"user_service/config"
	"user_service/domain"
	"user_service/infrastructure/postgres"
	"user_service/infrastructure/reporedis"
	"user_service/infrastructure/reporedis/custerr"
	"user_service/util"
	"uuid"

	"github.com/redis/go-redis/v9"
)

func TestSetUserDataToRedis(t *testing.T) {

	userStore, err := loadAndGetUserStore()
	if err != nil {
		t.Errorf("failed load test err%v\n", err)
	}

	user := domain.User{
		Id:        uuid.MustParse("01a0e653-37d4-78d5-aac0-0b2ccfad1963"),
		UserName:  "newTestname",
		Password:  "111",
		Email:     "b@b.com",
		Phone:     "+71111111111",
		IsDeleted: false,
	}

	user2 := domain.User{
		Id:        uuid.MustParse("01a10a25-854b-7789-9602-c077421e6748"),
		UserName:  "newTestname22",
		Password:  "111",
		Email:     "b@b.com",
		Phone:     "+71111111211",
		IsDeleted: false,
	}

	err = userStore.Set(context.TODO(), &user)
	if err != nil {
		t.Errorf("failed to set in redis %v\n", err)
	}

	err = userStore.Set(context.TODO(), &user2)
	if err == nil {
		t.Errorf("failed to set err:two index")
	}

	time.Sleep(3 * time.Second)
}

func TestGetUserDataFromRedis(t *testing.T) {

	userStore, err := loadAndGetUserStore()
	if err != nil {
		t.Errorf("failed load test err %v", err)
	}

	user := domain.User{
		Id:        uuid.MustParse("01a0e653-37d4-78d5-aac0-0b2ccfad1963"),
		UserName:  "newTestname",
		Password:  "111",
		Email:     "b@b.com",
		Phone:     "+71111111111",
		IsDeleted: false,
	}

	err = userStore.Set(context.TODO(), &user)

	getingUser, err := userStore.Get(context.TODO(), uuid.MustParse("01a0e653-37d4-78d5-aac0-0b2ccfad1963"))
	if err != nil {
		t.Errorf("failed get from redis %v", err)
	}

	if user.Id != getingUser.Id {
		t.Error("Failed test id dont equal\n")
	}

	if user.UserName != getingUser.UserName {
		t.Error("Failed test usernamePassword dont equal\n")
	}

	if user.Email != getingUser.Email {
		t.Error("Failed test Email dont equal\n")
	}

	if user.Phone != getingUser.Phone {
		t.Error("Failed test Phone dont equal\n")
	}

	if user.IsDeleted != getingUser.IsDeleted {
		t.Error("Failed test IsDeleted dont equal\n")
	}

	time.Sleep(3 * time.Second)

}

func TestUpdateFuncInRedis(t *testing.T) {

	userStore, err := loadAndGetUserStore()
	if err != nil {
		t.Errorf("Failed load test err:%v", err)
	}

	user := domain.User{
		Id:        uuid.MustParse("01a0e653-37d4-78d5-aac0-0b2ccfad1963"),
		UserName:  "newTestname",
		Password:  "111",
		Email:     "b@b.com",
		Phone:     "+71111111111",
		IsDeleted: false,
	}

	user2 := domain.User{
		Id:        uuid.MustParse("01a0e715-e4fa-7985-9d2c-a41019053711"),
		UserName:  "A_name",
		Password:  "111",
		Email:     "",
		Phone:     "",
		IsDeleted: false,
	}

	err = userStore.Set(context.TODO(), &user)
	if err != nil {
		t.Errorf("failed set user1 err:%v", err)
	}

	err = userStore.Set(context.TODO(), &user2)
	if err != nil {
		t.Errorf("failed set user2 err:%v", err)
	}

	tests := []string{
		`{ "01a0e715-e4fa-7985-9d2c-a41019053711": { "username": "newTestname", "email": "b@b.com" } }`,
		`{ "01a0e715-e4fa-7985-9d2c-a41019053711": { "username": "B_name", "phone": "+79999999999" } }`,
		`{ "01a0e653-37d4-78d5-aac0-0b2ccfad1963": { "username": "B_name" } }`,
		`{ "01a0e715-e4fa-7985-9d2c-a41019053711": { "email": "a@a.com" } }`,
		`{ "01a0e653-37d4-78d5-aac0-0b2ccfad1963": { "phone": "+79999999999" } }`,
	}

	for i, jsonStr := range tests {

		jsmap := make(map[string]domain.UserOpt)

		err := json.Unmarshal([]byte(jsonStr), &jsmap)
		if err != nil {
			t.Errorf("failed parse json in user opt err:%v\n", err)
		}

		var id uuid.UUID
		var opt domain.UserOpt
		for k, v := range jsmap {
			id = uuid.MustParse(k)
			opt = v
			break
		}

		updateErr := userStore.Update(context.TODO(), id, &opt)

		switch i + 1 {
		case 1, 3, 5:
			if updateErr == nil {
				t.Errorf("failed test dont err")
			}
		case 2, 4:
			if updateErr != nil {
				t.Errorf("failed test err:%v", updateErr)
			}
		}
	}

}

func TestBuildUpgratePnaForUserStore(t *testing.T) {

	userStore, err := loadAndGetUserStore()
	if err != nil {
		t.Errorf("failed load user store err%v", err)
	}

	user := domain.User{
		Id:        uuid.MustParse("01a0e653-37d4-78d5-aac0-0b2ccfad1963"),
		UserName:  "newTestname",
		Password:  "111",
		Email:     "b@b.com",
		Phone:     "",
		IsDeleted: false,
	}

	userCache := reporedis.UserCacheFromDomainUser(&user)

	jsString := `{ "username": "newTestname", "phone": "+79999999999", "is_delete": true }`
	var opt domain.UserOpt
	if err := json.Unmarshal([]byte(jsString), &opt); err != nil {
		t.Errorf("failed test err %v", err)
	}

	userCacheOpt := reporedis.UserCacheOptFromDomainOpt(&opt)

	userStore.BuildUpgratePlan(userCache, userCacheOpt.Patches())
}

func TestRegistrationSessionUser(t *testing.T) {

	sessionStore, err := loadAndGetSessionStore()
	if err != nil {
		t.Errorf("failed load test err:%v\n", err)
	}

	session := domain.Session{
		UserId:    uuid.MustParse("01a0e653-37d4-78d5-aac0-0b2ccfad1963"),
		DeviceId:  "111",
		Ip:        "1.2.3.4",
		Agent:     "Chrome",
		CreatedAt: time.Now(),
	}

	err = sessionStore.Registration(context.TODO(), &session, "5555")
	if err != nil {
		t.Errorf("fail don't work registration %v", err)
	}
}

func TestGetAllSessionByUserId(t *testing.T) {

	sessionStore, err := loadAndGetSessionStore()
	if err != nil {
		t.Errorf("failed load test err:%v\n", err)
	}

	now := time.Now().Truncate(time.Second)

	session := domain.Session{
		UserId:    uuid.MustParse("01a0e653-37d4-78d5-aac0-0b2ccfad1963"),
		DeviceId:  "111",
		Ip:        "1.2.3.4",
		Agent:     "Chrome",
		CreatedAt: now,
	}

	session2 := domain.Session{
		UserId:    uuid.MustParse("01a0e653-37d4-78d5-aac0-0b2ccfad1963"),
		DeviceId:  "222",
		Ip:        "1.2.3.4",
		Agent:     "Mozzila",
		CreatedAt: now,
	}

	session3 := domain.Session{
		UserId:    uuid.MustParse("01a132fe-7f4f-7739-a8b5-68187bc90776"),
		DeviceId:  "333",
		Ip:        "4.5.6.7",
		Agent:     "Safari",
		CreatedAt: now,
	}

	err = sessionStore.Registration(context.TODO(), &session, "5555")
	if err != nil {
		t.Errorf("fail don't work registration %v", err)
	}

	err = sessionStore.Registration(context.TODO(), &session2, "6666")
	if err != nil {
		t.Errorf("fail don't work registration %v", err)
	}

	err = sessionStore.Registration(context.TODO(), &session3, "7777")
	if err != nil {
		t.Errorf("fail don't work registration %v", err)
	}

	ss, err := sessionStore.GetAllSession(context.TODO(), uuid.MustParse("01a0e653-37d4-78d5-aac0-0b2ccfad1963"))
	if err != nil {
		t.Errorf("fail get all session err:%v\n", err)
	}

	if len(ss) != 2 {
		t.Errorf("fail get all session small session")
	}

	trueArr := []*domain.Session{&session, &session2}
	coincidence := 0

	for _, val := range trueArr {
		for _, valFromRedis := range ss {

			if valFromRedis.UserId == val.UserId && valFromRedis.DeviceId == val.DeviceId &&
				valFromRedis.Agent == val.Agent && valFromRedis.CreatedAt.Equal(val.CreatedAt) &&
				valFromRedis.Ip == val.Ip {

				coincidence++

			}
		}

	}

	if coincidence != len(trueArr) {
		t.Errorf("fail test, don't work coincidence != len(trueArr)")
	}

}

func TestGetSessionByRefresh(t *testing.T) {

	sessionStore, err := loadAndGetSessionStore()
	if err != nil {
		t.Errorf("failed load test err:%v\n", err)
	}

	now := time.Now().Truncate(time.Second)

	session := domain.Session{
		UserId:    uuid.MustParse("01a0e653-37d4-78d5-aac0-0b2ccfad1963"),
		DeviceId:  "111",
		Ip:        "1.2.3.4",
		Agent:     "Chrome",
		CreatedAt: now,
	}

	err = sessionStore.Registration(context.TODO(), &session, "5555")
	if err != nil {
		t.Errorf("fail don't work registration %v", err)
	}

	ss, err := sessionStore.GetSessionByRefresh(context.TODO(), session.UserId, "5555")
	if err != nil {
		t.Errorf("fail get session from redis err:%v\n", err)
	}

	if ss.UserId != session.UserId || ss.DeviceId != session.DeviceId ||
		ss.Agent != session.Agent || ss.CreatedAt != session.CreatedAt ||
		ss.Ip != session.Ip {
		t.Errorf("first elem dont equal")
	}

}

func TestUpdateRefreshToken(t *testing.T) {

	sessionStore, err := loadAndGetSessionStore()
	if err != nil {
		t.Errorf("failed load test err:%v\n", err)
	}

	now := time.Now().Truncate(time.Second)

	session := domain.Session{
		UserId:    uuid.MustParse("01a0e653-37d4-78d5-aac0-0b2ccfad1963"),
		DeviceId:  "111",
		Ip:        "1.2.3.4",
		Agent:     "Chrome",
		CreatedAt: now,
	}

	err = sessionStore.Registration(context.TODO(), &session, "5555")
	if err != nil {
		t.Errorf("fail don't work registration %v", err)
	}

	err = sessionStore.UpdateRefreshToken(context.TODO(), session.UserId, "5555", "6666")
	if err != nil {
		t.Errorf("fail update token err:%v\n", err)
	}

	ss, err := sessionStore.GetSessionByRefresh(context.TODO(), session.UserId, "6666")
	if err != nil {
		t.Errorf("fail get session from redis err:%v\n", err)
	}

	if ss.UserId != session.UserId || ss.DeviceId != session.DeviceId ||
		ss.Agent != session.Agent || ss.CreatedAt != session.CreatedAt ||
		ss.Ip != session.Ip {
		t.Errorf("update token new val dont equal old val")
	}

}

func TestCheckTTLAfterRotationToken(t *testing.T) {

	checkTtl := 10 * time.Minute

	sessionStore, repo, err := loadAndGetSessionStoreAndRepo(checkTtl)

	now := time.Now().Truncate(time.Second)

	session := domain.Session{
		UserId:    uuid.MustParse("01a0e653-37d4-78d5-aac0-0b2ccfad1963"),
		DeviceId:  "111",
		Ip:        "1.2.3.4",
		Agent:     "Chrome",
		CreatedAt: now,
	}

	err = sessionStore.Registration(context.TODO(), &session, "5555")
	if err != nil {
		t.Errorf("fail don't work registration %v", err)
	}

	err = sessionStore.UpdateRefreshToken(context.TODO(), session.UserId, "5555", "6666")
	if err != nil {
		t.Errorf("fail update token err:%v\n", err)
	}

	repo.Do(context.TODO(), func(ctx context.Context, client *redis.Client) error {

		id := uuid.MustParse("01a0e653-37d4-78d5-aac0-0b2ccfad1963")
		bt := sha256.Sum256([]byte("6666"))
		hashToken := hex.EncodeToString(bt[:])
		hexId := hex.EncodeToString(id[:])

		sessionToken := fmt.Sprintf("%s%s", fmt.Sprintf(reporedis.SessionKey, hexId), hashToken)
		refreshToken := fmt.Sprintf("%s%s", fmt.Sprintf(reporedis.RefreshKey, hexId), hashToken)

		ttlSession, err := client.TTL(context.TODO(), sessionToken).Result()
		if err != nil {
			t.Errorf("fail get ttl session key err:%v", err)
		}

		ttlRefresh, err := client.TTL(context.TODO(), refreshToken).Result()
		if err != nil {
			t.Errorf("fail get ttl refresh key err:%v", err)
		}

		if ttlRefresh != checkTtl || ttlSession != checkTtl {
			t.Errorf("fail don't set ttl for new key")
		}

		return nil
	})

}

func TestCheckTryUpdateRefreshTokenWithMissingToken(t *testing.T) {

	sessionStore, err := loadAndGetSessionStore()
	if err != nil {
		t.Errorf("failed load test err:%v\n", err)
	}

	now := time.Now().Truncate(time.Second)

	session := domain.Session{
		UserId:    uuid.MustParse("01a0e653-37d4-78d5-aac0-0b2ccfad1963"),
		DeviceId:  "111",
		Ip:        "1.2.3.4",
		Agent:     "Chrome",
		CreatedAt: now,
	}

	err = sessionStore.Registration(context.TODO(), &session, "5555")
	if err != nil {
		t.Errorf("fail registration don't work err:%v\n", err)
	}

	err = sessionStore.UpdateRefreshToken(context.TODO(), uuid.MustParse("01a0e653-37d4-78d5-aac0-0b2ccfad1963"),
		"missing token", "6666")
	if !custerr.ErrNotFound.Is(err) {
		t.Errorf("fail don't return not found return err:%v\n", err)
	} else if err == nil {
		t.Errorf("fail don't return not found return nil")
	}

}

func TestDeleteAllSession(t *testing.T) {

	sessionStore, err := loadAndGetSessionStore()
	if err != nil {
		t.Errorf("failed load test err:%v\n", err)
	}

	now := time.Now().Truncate(time.Second)

	session := domain.Session{
		UserId:    uuid.MustParse("01a0e653-37d4-78d5-aac0-0b2ccfad1963"),
		DeviceId:  "111",
		Ip:        "1.2.3.4",
		Agent:     "Chrome",
		CreatedAt: now,
	}

	session2 := domain.Session{
		UserId:    uuid.MustParse("01a0e653-37d4-78d5-aac0-0b2ccfad1963"),
		DeviceId:  "222",
		Ip:        "1.2.3.4",
		Agent:     "Mozzila",
		CreatedAt: now,
	}

	err = sessionStore.Registration(context.TODO(), &session, "5555")
	if err != nil {
		t.Errorf("fail don't work registration %v", err)
	}

	err = sessionStore.Registration(context.TODO(), &session2, "6666")
	if err != nil {
		t.Errorf("fail don't work registration %v", err)
	}

	err = sessionStore.DeleteAll(context.TODO(), session.UserId)
	if err != nil {
		t.Errorf("fail delete all err:%v\n", err)
	}

	_, err = sessionStore.GetSessionByRefresh(context.TODO(), session.UserId, "5555")
	if err != custerr.ErrNotFound {
		t.Errorf("fail store has session 1")
	}

	_, err = sessionStore.GetSessionByRefresh(context.TODO(), session2.UserId, "6666")
	if err != custerr.ErrNotFound {
		t.Errorf("fail store has session 2")
	}

	data, err := sessionStore.GetAllSession(context.TODO(), session2.UserId)
	if err != nil {
		t.Errorf("fail error get all err:%v\n", err)
	}

	if len(data) > 0 {
		t.Errorf("fail test session store has data")
	}

}

func TestDeleteSessionByRefreshToken(t *testing.T) {

	sessionStore, err := loadAndGetSessionStore()
	if err != nil {
		t.Errorf("failed load test err:%v\n", err)
	}

	now := time.Now().Truncate(time.Second)

	session := domain.Session{
		UserId:    uuid.MustParse("01a0e653-37d4-78d5-aac0-0b2ccfad1963"),
		DeviceId:  "111",
		Ip:        "1.2.3.4",
		Agent:     "Chrome",
		CreatedAt: now,
	}

	session2 := domain.Session{
		UserId:    uuid.MustParse("01a0e653-37d4-78d5-aac0-0b2ccfad1963"),
		DeviceId:  "222",
		Ip:        "1.2.3.4",
		Agent:     "Mozzila",
		CreatedAt: now,
	}

	err = sessionStore.Registration(context.TODO(), &session, "5555")
	if err != nil {
		t.Errorf("fail don't work registration %v", err)
	}

	err = sessionStore.Registration(context.TODO(), &session2, "6666")
	if err != nil {
		t.Errorf("fail don't work registration %v", err)
	}

	err = sessionStore.DeleteByRefresh(context.TODO(), session.UserId, "5555")
	if err != nil {
		t.Errorf("fail delete by refresh token 5555 err:%v\n", err)
	}

	err = sessionStore.DeleteByRefresh(context.TODO(), session.UserId, "6666")
	if err != nil {
		t.Errorf("fail delete by refresh token 6666 err:%v\n", err)
	}

	err = sessionStore.DeleteAll(context.TODO(), session.UserId)

	_, err = sessionStore.GetSessionByRefresh(context.TODO(), session.UserId, "5555")
	if err != custerr.ErrNotFound {
		t.Errorf("fail store has session 1")
	}

	_, err = sessionStore.GetSessionByRefresh(context.TODO(), session2.UserId, "6666")
	if err != custerr.ErrNotFound {
		t.Errorf("fail store has session 2")
	}

	data, err := sessionStore.GetAllSession(context.TODO(), session2.UserId)
	if err != nil {
		t.Errorf("fail error get all err:%v\n", err)
	}

	if len(data) > 0 {
		t.Errorf("fail test session store has data")
	}

}

func TestDeleteSessionByMissRefreshToken(t *testing.T) {

	sessionStore, err := loadAndGetSessionStore()
	if err != nil {
		t.Errorf("fail load test err:%v\n", err)
	}

	now := time.Now().Truncate(time.Second)

	session := domain.Session{
		UserId:    uuid.MustParse("01a0e653-37d4-78d5-aac0-0b2ccfad1963"),
		DeviceId:  "111",
		Ip:        "1.2.3.4",
		Agent:     "Chrome",
		CreatedAt: now,
	}

	err = sessionStore.Registration(context.TODO(), &session, "5555")
	if err != nil {
		t.Errorf("fail registration session err:%v\n", err)
	}

	err = sessionStore.DeleteByRefresh(context.TODO(), uuid.MustParse("01a0e653-37d4-78d5-aac0-0b2ccfad1963"), "6666")
	if !custerr.ErrNotFound.Is(err) {
		t.Errorf("fail delete by missing refresh dont retur ErrNotFound return err:%v\n", err)
	}

}

func loadAndGetUserStore() (*reporedis.UserStore, error) {
	ctx := context.Background()
	util.LoadEnvFile()

	cm := config.NewConfigManager()

	cm.Init(ctx, "")

	repo, err := reporedis.NewRepository(ctx, cm)
	if err != nil {
		return nil, fmt.Errorf("Failed connect in redis %v\n", err)
	}

	db, err := postgres.NewDataBase(ctx, cm)
	if err != nil {
		return nil, fmt.Errorf("Failed connect to database %v\n", err)
	}

	au := postgres.NewAuditService(db, 1, 1*time.Millisecond, 5*time.Minute)
	au.Init()
	us := reporedis.NewUserStore(repo, au, 60*time.Minute)

	return us, nil
}

func loadAndGetSessionStore() (*reporedis.SessionStore, error) {
	ctx := context.Background()
	util.LoadEnvFile()

	cm := config.NewConfigManager()

	cm.Init(ctx, "")

	repo, err := reporedis.NewRepository(ctx, cm)
	if err != nil {
		return nil, fmt.Errorf("Failed connect in redis %v\n", err)
	}

	db, err := postgres.NewDataBase(ctx, cm)
	if err != nil {
		return nil, fmt.Errorf("Failed connect to database %v\n", err)
	}

	au := postgres.NewAuditService(db, 1, 1*time.Millisecond, 5*time.Minute)
	au.Init()
	ss := reporedis.NewSessionStore(repo, au, 60*time.Minute)

	return ss, nil
}

func loadAndGetSessionStoreAndRepo(ttl time.Duration) (*reporedis.SessionStore, *reporedis.Repository, error) {
	ctx := context.Background()
	util.LoadEnvFile()

	cm := config.NewConfigManager()

	cm.Init(ctx, "")

	repo, err := reporedis.NewRepository(ctx, cm)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed connect in redis %v\n", err)
	}

	db, err := postgres.NewDataBase(ctx, cm)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed connect to database %v\n", err)
	}

	au := postgres.NewAuditService(db, 1, 1*time.Millisecond, 5*time.Minute)
	au.Init()
	ss := reporedis.NewSessionStore(repo, au, ttl)

	return ss, repo, nil
}
