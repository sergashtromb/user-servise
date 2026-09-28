package test

import (
	"context"
	"fmt"
	"testing"
	"user_service/config"
	"user_service/domain"
	"user_service/infrastructure/postgres"
	"user_service/util"
	"uuid"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestAddTestData(t *testing.T) {
	
	pool, err := loadAndGetPool()
	if err != nil {
		t.Errorf("%v\n", err)
	}

	_, err = pool.Exec(context.TODO(), `INSERT INTO users (username, pass, email, phone) 
							 VALUES ($1, $2, $3, $4);`, 
							 "username_test", "111", "a@a.com", "+79999999999")
	if err != nil {
		t.Errorf("Failed make insert query %v\n", err)
	}
}

func TestGetUserByID(t *testing.T) {

	userStore, err := loadAndGetUserStore()
	if err != nil {
		t.Errorf("%v\n", err)
	}

	origUser := domain.User {
		Id: uuid.MustParse("01a0e653-37d4-78d5-aac0-0b2ccfad1963"),
		UserName: "username_test",
		Password: "111",
		Email: "a@a.com",
		Phone: "+79999999999",
		IsDeleted: false,
	}

	user, err := userStore.GetByID(context.TODO(), uuid.MustParse("01a0e653-37d4-78d5-aac0-0b2ccfad1963"))
	if err != nil {
		t.Errorf("%v\n", err)
	}

	if user.Id != origUser.Id {
		t.Errorf("fatal id dont equal")
	}

	if user.UserName != origUser.UserName {
		t.Errorf("fatal username dont equal")
	}

	if user.Email != origUser.Email {
		t.Errorf("fatal email dont equal")
	}

	if user.Password != origUser.Password {
		t.Errorf("fatal pass dont equal")
	}

	if user.Phone != origUser.Phone {
		t.Errorf("fatal phone dont equal")
	}

	if user.IsDeleted != origUser.IsDeleted {
		t.Errorf("fatal phone dont equal")
	}
}

func TestCreateUserStore(t *testing.T) {

	userStore, err := loadAndGetUserStore()
	if err != nil {
		t.Errorf("%v\n", err)
	}

	newUser := domain.User {
		UserName: "A_user",
		Password: "222",
	}

	err = userStore.Create(context.TODO(), &newUser)
	if err != nil {
		t.Errorf("%v\n", err)
	}

	err = userStore.Create(context.TODO(), &newUser)
	if err == nil {
		t.Error("Possible make duble")
	}

	oldUser := domain.User {
		UserName: "username_test",
		Password: "111",
		Email: "a@a.com",
		Phone: "+79999999999",
	}

	err = userStore.Create(context.TODO(), &oldUser)
	if err == nil {
		t.Error("Possible make duble")
	}
}

//01a0e653-37d4-78d5-aac0-0b2ccfad1963 test user

func loadAndGetUserStore() (*postgres.UserStore, error) {
	ctx := context.Background()
	util.LoadEnvFile()

	cm := config.NewConfigManager()

	cm.Init(ctx, "")

	db, err := postgres.NewDataBase(ctx, cm)
	if err != nil {
		return nil, fmt.Errorf("Failed connect in data base %v\n", err)
	}

	userStore := postgres.NewUserStore(db)

	return userStore, nil
}

func loadAndGetPool() (*pgxpool.Pool, error) {
	ctx := context.Background()
	util.LoadEnvFile()

	cm := config.NewConfigManager()

	cm.Init(ctx, "")

	db, err := postgres.NewDataBase(ctx, cm)
	if err != nil {
		return nil, fmt.Errorf("Failed connect in data base %v\n", err)
	}

	pool := db.GetPool()

	return pool, nil
}