package test

import (
	"context"
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
		ExpAt:     time.Now().Add(60 * time.Minute),
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
		ExpAt:     now.Add(60 * time.Minute),
	}

	session2 := domain.Session{
		UserId:    uuid.MustParse("01a0e653-37d4-78d5-aac0-0b2ccfad1963"),
		DeviceId:  "222",
		Ip:        "1.2.3.4",
		Agent:     "Mozzila",
		CreatedAt: now,
		ExpAt:     now.Add(60 * time.Minute),
	}

	err = sessionStore.Registration(context.TODO(), &session, "5555")
	if err != nil {
		t.Errorf("fail don't work registration %v", err)
	}

	err = sessionStore.Registration(context.TODO(), &session2, "6666")
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

	if ss[0].UserId != session.UserId || ss[0].DeviceId != session.DeviceId ||
		ss[0].Agent != session.Agent || ss[0].CreatedAt != session.CreatedAt ||
		ss[0].ExpAt != session.ExpAt || ss[0].Ip != session.Ip {
		t.Errorf("first elem dont equal")
	}

	if ss[1].UserId != session2.UserId || ss[1].DeviceId != session2.DeviceId ||
		ss[1].Agent != session2.Agent || ss[1].CreatedAt != session2.CreatedAt ||
		ss[1].ExpAt != session2.ExpAt || ss[1].Ip != session2.Ip {
		t.Errorf("second elem dont equal")
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
		ExpAt:     now.Add(60 * time.Minute),
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
		ss.ExpAt != session.ExpAt || ss.Ip != session.Ip {
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
		ExpAt:     now.Add(60 * time.Minute),
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
		ss.ExpAt != session.ExpAt || ss.Ip != session.Ip {
		t.Errorf("update token new val dont equal old val")
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
		ExpAt:     now.Add(60 * time.Minute),
	}

	session2 := domain.Session{
		UserId:    uuid.MustParse("01a0e653-37d4-78d5-aac0-0b2ccfad1963"),
		DeviceId:  "222",
		Ip:        "1.2.3.4",
		Agent:     "Mozzila",
		CreatedAt: now,
		ExpAt:     now.Add(60 * time.Minute),
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

	_, err = sessionStore.GetAllSession(context.TODO(), session2.UserId)
	if err != custerr.ErrNotFound && err == nil {
		t.Errorf("fail store has sessions")
	} else if err != nil && err != custerr.ErrNotFound {
		t.Errorf("fail error get all err:%v\n", err)
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
		ExpAt:     now.Add(60 * time.Minute),
	}

	session2 := domain.Session{
		UserId:    uuid.MustParse("01a0e653-37d4-78d5-aac0-0b2ccfad1963"),
		DeviceId:  "222",
		Ip:        "1.2.3.4",
		Agent:     "Mozzila",
		CreatedAt: now,
		ExpAt:     now.Add(60 * time.Minute),
	}

	err = sessionStore.Registration(context.TODO(), &session, "5555")
	if err != nil {
		t.Errorf("fail don't work registration %v", err)
	}

	err = sessionStore.Registration(context.TODO(), &session2, "6666")
	if err != nil {
		t.Errorf("fail don't work registration %v", err)
	}

	err = sessionStore.DeletByRefresh(context.TODO(), session.UserId, "5555")
	if err != nil {
		t.Errorf("fail delete by refresh token 5555 err:%v\n", err)
	}

	err = sessionStore.DeletByRefresh(context.TODO(), session.UserId, "6666")
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

	_, err = sessionStore.GetAllSession(context.TODO(), session2.UserId)
	if err != custerr.ErrNotFound && err == nil {
		t.Errorf("fail store has sessions")
	} else if err != nil && err != custerr.ErrNotFound {
		t.Errorf("fail error get all err:%v\n", err)
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
