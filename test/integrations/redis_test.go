package test

import (
	"context"
	"fmt"
	"testing"
	"time"
	"user_service/config"
	"user_service/domain"
	"user_service/util"
	"uuid"

	"github.com/redis/go-redis/v9"
)

// SPEC
// 	Спецификация для тестов SessionStore
//	Тесты табличые, формируется мапа ключ - имя теста значение структура с параметрами
//	Обязательно функция подготовки теста, функция очистки, а также функции подготовки моков если необходимо
//  Обязательно функция выполняемая перед подготовкой для загрузки и подключения реальных хранилищ

// SPEC
//	SessionStore:
//		Registration - метод формирует регистрацию сессию в кеше
//			Args - ctx - контекст выполнения, session - *domain.Session подготовленная сейссия,
// 					family_id айдишник семейства refresh токенов
//			Return - Ошибка при падении редис, Ошибка дублирования если сейссия существует,
// 					ошибка при некорретно заполнененых параметрах, nil если все нормально
//			Tests:
//					correct_request - корректный запрос, должен вернуть nil, данные в redis должны совпадать с тем что мы отправили в функцию
//										ключи также должны совпадать
//					double_session - попытка создать дубликат сейссии, вернуть ошибку, должен быть единичный экземпляр сейссии заданый изначально
//					invalid_args - попытка зарегистрировать сейссию с незаполненными полями, не должно быть некоректных данных в кеше
//
//

func TestRegistrationSessionInRedis(t *testing.T) {

	client, err := loadRedisClient()
	if err != nil {
		t.Fatalf("dont load redis err:%v", err)
	}

	fullSession := domain.Session{
		UserId:    uuid.NewV7(),
		DeviceId:  "12345",
		Ip:        "1.1.1.1",
		Agent:     "chrome win 10",
		CreatedAt: time.Now(),
		Version:   "jtw-1",
	}

	emptySession := domain.Session{
		UserId:    uuid.Nil(),
		DeviceId:  "",
		Ip:        "",
		Agent:     "",
		CreatedAt: time.Now(),
		Version:   "jtw-1",
	}

	table := map[string]struct {
		IsError              bool
		fnReady              func()
		fnCleanUp            func()
		fnCheckStoreAfterReg func()
		Err                  error
	}{
		"correct_request": {},
	}

}

func loadRedisClient() (*redis.Client, error) {

	util.LoadEnvFile()

	cm := config.NewConfigManager()
	cm.Init(context.TODO(), "")

	redisConfig := cm.Get().RedisConf

	client := redis.NewClient(&redis.Options{
		Addr: fmt.Sprintf("%s:%s", redisConfig.Host, redisConfig.Port),
		DB:   redisConfig.DbNum,

		Password: redisConfig.Password,

		PoolSize:        redisConfig.PoolSize,
		MinIdleConns:    redisConfig.MinIdleConn,
		MaxIdleConns:    redisConfig.MaxIdleConn,
		ConnMaxIdleTime: time.Duration(redisConfig.ConnMaxIdleTime) * time.Minute,
		ConnMaxLifetime: time.Duration(redisConfig.ConnMaxLifetime) * time.Minute,

		DialTimeout:  time.Duration(redisConfig.DialTimeout) * time.Second,
		ReadTimeout:  time.Duration(redisConfig.ReadTimeout) * time.Second,
		WriteTimeout: time.Duration(redisConfig.WriteTimeout) * time.Second,
		PoolTimeout:  time.Duration(redisConfig.PoolTimeout) * time.Second,
	})

	if _, err := client.Ping(context.TODO()).Result(); err != nil {
		return nil, err
	}

	return client, nil
}
