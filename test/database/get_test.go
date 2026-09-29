package test

import (
	"context"
	"encoding/json"
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

func TestUpdateUserStore(t *testing.T) {

	userStore, err := loadAndGetUserStore()
	if err != nil {
		t.Errorf("%v\n", err)
	}

	// 1 pass
	// 2 pass
	// 3 error
	// 4 pass
	// 5 error
	tests := []string{
		`{ "01a0e653-37d4-78d5-aac0-0b2ccfad1963": { "username": "newTestname", "email": "b@b.com" } }`,   
		`{ "01a0e715-e4fa-7985-9d2c-a41019053711": { "username": "B_name", "phone": "+79999999999" } }`, 
		`{ "01a0e653-37d4-78d5-aac0-0b2ccfad1963": { "username": "B_name" } }`,                         
		`{ "01a0e715-e4fa-7985-9d2c-a41019053711": { "email": "a@a.com" } }`,                           
		`{ "01a0e653-37d4-78d5-aac0-0b2ccfad1963": { "phone": "+79999999999" } }`,                   
	}

	for i, jsonStr := range tests {
		jsonMap := make(map[string]domain.UserOpt)

		if err := json.Unmarshal([]byte(jsonStr), &jsonMap); err != nil {
			t.Fatalf("Ошибка десериализации в тесте №%d: %v", i+1, err)
		}

		var key string
		var value domain.UserOpt
		for k, v := range jsonMap {
			key = k
			value = v
			break 
		}

		err := userStore.Update(context.TODO(), uuid.MustParse(key), &value)

		testNum := i + 1

		switch testNum {
		case 1, 2, 4: // pass
			if err != nil {
				t.Errorf("Failed test №%d: expected no error, got %v", testNum, err)
			}
		case 3, 5: // error
			if err == nil {
				t.Errorf("Failed test №%d: expected error, but got nil", testNum)
			}
		}
	}
}


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