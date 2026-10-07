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
