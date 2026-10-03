package test

import (
	"context"
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

	err = userStore.Set(context.TODO(), &user)
	if err != nil {
		t.Errorf("failed to set in redis %v\n", err)
	}
	time.Sleep(3 * time.Second)
}

// TEST write test for get from redis

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
