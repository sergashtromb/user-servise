package test

import (
	"context"
	"encoding/hex"
	"fmt"
	"strconv"
	"testing"
	"time"
	"user_service/config"
	"user_service/domain"
	"user_service/infrastructure/reporedis"
	"user_service/infrastructure/reporedis/custerr"
	"user_service/pkg/repoerrors"
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

	cm := config.NewConfigManager()
	cm.Init(context.TODO(), "")

	sessionStore, err := loadAndGetSessionStore()
	if err != nil {
		t.Fatalf("fail load session store, err:%v", err)
	}

	client, err := loadRedisClient()
	if err != nil {
		t.Fatalf("dont load redis err:%v", err)
	}

	fullSession := domain.Session{
		UserId:     uuid.NewV7(),
		DeviceId:   "12345",
		Ip:         "1.1.1.1",
		Agent:      "chrome win 10",
		CreatedAt:  time.Now(),
		Version:    "jtw-1",
		LastUpdate: time.Now(),
	}

	emptySession := domain.Session{
		UserId:     uuid.Nil(),
		DeviceId:   "",
		Ip:         "",
		Agent:      "",
		CreatedAt:  time.Now(),
		Version:    "jtw-1",
		LastUpdate: time.Now(),
	}

	familyId1 := uuid.NewV7()

	table := map[string]struct {
		IsError              bool
		SessionForReg        domain.Session
		FamilyId             uuid.UUID
		fnReady              func()
		fnCleanUp            func()
		fnCheckStoreAfterReg func()
		Err                  *repoerrors.RepoError
	}{
		"correct_request": {
			IsError: false,
			fnReady: func() {},
			fnCleanUp: func() {
				_, err := client.FlushDB(context.TODO()).Result()
				if err != nil {
					t.Fatalf("fail clear data base err:%v", err)
				}
			},
			fnCheckStoreAfterReg: func() {
				// should be:
				//	session:{hex_user_id}:user:hex_family_id - Hmap session
				//	session:{hex_user_id}:refresh:hex_family_id - hex_family_id - for check uniq

				hexFamilyId := hex.EncodeToString(familyId1[:])

				refreshKey := fmt.Sprintf("session:{%v}:user:%v", hex.EncodeToString(fullSession.UserId[:]), hexFamilyId)
				sessionKey := fmt.Sprintf("session:{%v}:refresh:%v", hex.EncodeToString(fullSession.UserId[:]),
					hexFamilyId)

				data, err := client.HGetAll(context.TODO(), sessionKey).Result()
				if err != nil {
					t.Fatalf("fail get data for check err:%v", err)
				}

				if len(data) == 0 {
					t.Errorf("fail dont save all field")
				}

				if len(data) != 0 {
					var dataSession domain.Session
					idstr, ok := data["user_id"]
					if !ok {
						t.Errorf("fail get user id")
					} else {

						userId, err := hex.DecodeString(idstr)
						if err != nil {
							t.Errorf("fail conver hex string to user id uuid err:%v", err)
						}
						dataSession.UserId = uuid.UUID(userId)

					}

					deviceIdstr, ok := data["device_id"]
					if !ok {
						t.Errorf("fail get device id")
					} else {
						dataSession.DeviceId = deviceIdstr
					}

					agentstr, ok := data["agent"]
					if !ok {
						t.Errorf("fail get agent")
					} else {
						dataSession.Agent = agentstr
					}

					ipstr, ok := data["ip"]
					if !ok {
						t.Errorf("fail get ip")
					} else {
						dataSession.Ip = ipstr
					}

					versionstr, ok := data["version"]
					if !ok {
						t.Errorf("fail get version")
					} else {
						dataSession.Version = versionstr
					}

					createdatstr, ok := data["created_at"]
					if !ok {
						t.Errorf("fail get created_at")
					} else {
						createdAtInt, err := strconv.ParseInt(createdatstr, 10, 64)
						if err != nil {
							t.Errorf("fail convert string to int64 err:%v", err)
							createdAtInt = 0
						}

						dataSession.CreatedAt = time.Unix(createdAtInt, 0)
					}

					lastUpdateStr, ok := data["last_update"]
					if !ok {
						t.Errorf("fail get last_update")
					} else {
						lastUpdateInt, err := strconv.ParseInt(lastUpdateStr, 10, 64)
						if err != nil {
							t.Errorf("fail convert last_update string to int64 err:%v", err)
						} else {
							dataSession.LastUpdate = time.Unix(lastUpdateInt, 0)
						}
					}

					if fullSession.UserId != dataSession.UserId || fullSession.DeviceId != dataSession.DeviceId ||
						fullSession.Agent != dataSession.Agent || fullSession.Ip != dataSession.Ip ||
						!fullSession.CreatedAt.Truncate(time.Second).Equal(dataSession.CreatedAt) {
						t.Errorf("fail field full session dont equal data session")
					}
				}

				refKey, err := client.Get(context.TODO(), refreshKey).Result()
				if err != nil {
					t.Errorf("fail get ref key err:%v", err)
				}

				if hexFamilyId != refKey {
					t.Errorf("fail hex family id dont equal want %v have %v", hexFamilyId, refKey)
				}

				ttl, err := client.TTL(context.TODO(), sessionKey).Result()
				if err != nil || ttl < 0 {
					t.Errorf("fail session key dont exist ot dont have ttl")
				}

				refreshTtl, err := client.TTL(context.TODO(), refreshKey).Result()
				if err != nil || refreshTtl < 0 {
					t.Errorf("fail refresh key dont exist ot dont have ttl")
				}

			},
			SessionForReg: fullSession,
			FamilyId:      familyId1,
		},
		"double_session": {
			IsError:       true,
			SessionForReg: fullSession,
			FamilyId:      familyId1,
			fnCleanUp: func() {
				_, err := client.FlushDB(context.TODO()).Result()
				if err != nil {
					t.Fatalf("fail clear data base err:%v", err)
				}
			},
			fnReady: func() {

				// should be:
				//	session:{hex_user_id}:user:hex_family_id - Hmap session
				//	session:{hex_user_id}:refresh:hex_family_id - hex_family_id - for check uniq

				hexFamilyId := hex.EncodeToString(familyId1[:])

				refreshKey := fmt.Sprintf("session:{%v}:user:%v", hex.EncodeToString(fullSession.UserId[:]), hexFamilyId)
				sessionKey := fmt.Sprintf("session:{%v}:refresh:%v", hex.EncodeToString(fullSession.UserId[:]),
					hexFamilyId)

				data := map[string]interface{}{
					"user_id":     hex.EncodeToString(fullSession.UserId[:]),
					"device_id":   fullSession.DeviceId,
					"agent":       fullSession.Agent,
					"ip":          fullSession.Ip,
					"created_at":  fullSession.CreatedAt.Unix(),
					"version":     fullSession.Version,
					"last_update": fullSession.LastUpdate.Unix(),
				}

				_, err := client.HSet(context.TODO(), sessionKey, data).Result()
				if err != nil {
					t.Errorf("fail ready test err:%v", err)
				}
				_, err = client.Expire(context.TODO(), sessionKey, 10*time.Hour).Result()
				if err != nil {
					t.Errorf("fail ready test err:%v", err)
				}

				_, err = client.Set(context.TODO(), refreshKey, hexFamilyId, 10*time.Hour).Result()
				if err != nil {
					t.Errorf("fail ready test err:%v", err)
				}

			},
			fnCheckStoreAfterReg: func() {
				// should be:
				//	session:{hex_user_id}:user:hex_family_id - Hmap session
				//	session:{hex_user_id}:refresh:hex_family_id - hex_family_id - for check uniq

				hexFamilyId := hex.EncodeToString(familyId1[:])

				refreshKey := fmt.Sprintf("session:{%v}:user:%v", hex.EncodeToString(fullSession.UserId[:]), hexFamilyId)
				sessionKey := fmt.Sprintf("session:{%v}:refresh:%v", hex.EncodeToString(fullSession.UserId[:]),
					hexFamilyId)

				data, err := client.HGetAll(context.TODO(), sessionKey).Result()
				if err != nil {
					t.Fatalf("fail get data for check err:%v", err)
				}

				if len(data) == 0 {
					t.Errorf("fail dont save all field")
				}

				if len(data) != 0 {
					var dataSession domain.Session
					idstr, ok := data["user_id"]
					if !ok {
						t.Errorf("fail get user id")
					} else {

						userId, err := hex.DecodeString(idstr)
						if err != nil {
							t.Errorf("fail conver hex string to user id uuid err:%v", err)
						}
						dataSession.UserId = uuid.UUID(userId)

					}

					deviceIdstr, ok := data["device_id"]
					if !ok {
						t.Errorf("fail get device id")
					} else {
						dataSession.DeviceId = deviceIdstr
					}

					agentstr, ok := data["agent"]
					if !ok {
						t.Errorf("fail get agent")
					} else {
						dataSession.Agent = agentstr
					}

					ipstr, ok := data["ip"]
					if !ok {
						t.Errorf("fail get ip")
					} else {
						dataSession.Ip = ipstr
					}

					versionstr, ok := data["version"]
					if !ok {
						t.Errorf("fail get version")
					} else {
						dataSession.Version = versionstr
					}

					createdatstr, ok := data["created_at"]
					if !ok {
						t.Errorf("fail get created_at")
					} else {
						createdAtInt, err := strconv.ParseInt(createdatstr, 10, 64)
						if err != nil {
							t.Errorf("fail convert string to int64 err:%v", err)
							createdAtInt = 0
						}

						dataSession.CreatedAt = time.Unix(createdAtInt, 0)
					}

					lastUpdateStr, ok := data["last_update"]
					if !ok {
						t.Errorf("fail get last_update")
					} else {
						lastUpdateInt, err := strconv.ParseInt(lastUpdateStr, 10, 64)
						if err != nil {
							t.Errorf("fail convert last_update string to int64 err:%v", err)
						} else {
							dataSession.LastUpdate = time.Unix(lastUpdateInt, 0)
						}
					}

					if fullSession.UserId != dataSession.UserId || fullSession.DeviceId != dataSession.DeviceId ||
						fullSession.Agent != dataSession.Agent || fullSession.Ip != dataSession.Ip ||
						!fullSession.CreatedAt.Truncate(time.Second).Equal(dataSession.CreatedAt) {
						t.Errorf("fail field full session dont equal data session")
					}
				}

				refKey, err := client.Get(context.TODO(), refreshKey).Result()
				if err != nil {
					t.Errorf("fail get ref key err:%v", err)
				}

				if hexFamilyId != refKey {
					t.Errorf("fail hex family id dont equal want %v have %v", hexFamilyId, refKey)
				}
			},
			Err: custerr.ErrSessionAlredyExist,
		},
		"invalid_args": {
			IsError:       true,
			SessionForReg: emptySession,
			FamilyId:      uuid.Nil(),
			Err:           custerr.ErrBadArgs,
			fnReady: func() {
				_, err := client.FlushDB(context.TODO()).Result()
				if err != nil {
					t.Errorf("fail flush db in ready err:%v", err)
				}
			},
			fnCleanUp: func() {},
			fnCheckStoreAfterReg: func() {
				count, err := client.DBSize(context.TODO()).Result()
				if err != nil {
					t.Errorf("fail check test invalid_args err:%v", err)
				}

				if count > 0 {
					t.Errorf("fail repo has data")
				}
			},
		},
	}

	for name, val := range table {

		t.Run(name, func(t *testing.T) {

			val.fnReady()

			err := sessionStore.Registration(context.Background(), &val.SessionForReg, val.FamilyId)
			if val.IsError {
				if !val.Err.Is(err) {
					t.Errorf("fail error miss want %v have %v", val.Err, err)
				}
			} else {
				if err != nil {
					t.Errorf("fail registration err:%v", err)
				}
			}

			val.fnCheckStoreAfterReg()

			val.fnCleanUp()

		})
	}

}

// SPEC
//	SessionStore:
//		GetSessionByFamilyId - метод получает сейссию
//			Args - 	ctx - контекст выполнения
// 					userId - uuid.UUID адишник пользователя,
// 					familyId айдишник семейства refresh токенов
//			Return - (*session.Domain, error)
// 					(Существующая сессия, nil),
// 					(nil, Ошибка сессии не существует)
// 					(nil, Ошибка не корректно заполнены аргументы)
// 					(nil, Ошибка если упал редис (не проверяется, использующий должен обрабатывать  такой момент сам))
//			Tests:
//					correct_request - корректный запрос, должен вернуть сессию, данные в redis должны совпадать с тем что мы подготовили
//					no_exist_session - попытка получить несуществующую сессию, должен вернуть nil без ошибки
//					invalid_args - попытка получить сейссию с незаполненными полями, не должно быть некоректных данных в кеше
//

func TestGetSessionByFamilyId(t *testing.T) {
	cm := config.NewConfigManager()
	cm.Init(context.TODO(), "")

	sessionStore, err := loadAndGetSessionStore()
	if err != nil {
		t.Fatalf("fail load session store, err:%v", err)
	}

	client, err := loadRedisClient()
	if err != nil {
		t.Fatalf("dont load redis err:%v", err)
	}

	fullSession := domain.Session{
		UserId:     uuid.NewV7(),
		DeviceId:   "12345",
		Ip:         "1.1.1.1",
		Agent:      "chrome win 10",
		CreatedAt:  time.Now(),
		Version:    "jtw-1",
		LastUpdate: time.Now(),
	}

	existfamilyId := uuid.NewV7()
	noExistfamilyId := uuid.NewV7()

	table := map[string]struct {
		IsError         bool
		Err             *repoerrors.RepoError
		ReturnedSession *domain.Session
		FamilyId        uuid.UUID
		UserId          uuid.UUID
		fnReady         func()
		fnCleanUp       func()
	}{
		"correct_request": {
			IsError:         false,
			Err:             nil,
			ReturnedSession: &fullSession,
			FamilyId:        existfamilyId,
			UserId:          fullSession.UserId,
			fnReady: func() {

				// should be:
				//	session:{hex_user_id}:user:hex_family_id - Hmap session
				//	session:{hex_user_id}:refresh:hex_family_id - hex_family_id - for check uniq

				hexFamilyId := hex.EncodeToString(existfamilyId[:])

				refreshKey := fmt.Sprintf("session:{%v}:user:%v", hex.EncodeToString(fullSession.UserId[:]), hexFamilyId)
				sessionKey := fmt.Sprintf("session:{%v}:refresh:%v", hex.EncodeToString(fullSession.UserId[:]),
					hexFamilyId)

				data := map[string]interface{}{
					"user_id":     hex.EncodeToString(fullSession.UserId[:]),
					"device_id":   fullSession.DeviceId,
					"agent":       fullSession.Agent,
					"ip":          fullSession.Ip,
					"created_at":  fullSession.CreatedAt.Unix(),
					"version":     fullSession.Version,
					"last_update": fullSession.LastUpdate.Unix(),
				}

				_, err := client.HSet(context.TODO(), sessionKey, data).Result()
				if err != nil {
					t.Errorf("fail ready test err:%v", err)
				}
				_, err = client.Expire(context.TODO(), sessionKey, 10*time.Hour).Result()
				if err != nil {
					t.Errorf("fail ready test err:%v", err)
				}

				_, err = client.Set(context.TODO(), refreshKey, hexFamilyId, 10*time.Hour).Result()
				if err != nil {
					t.Errorf("fail ready test err:%v", err)
				}

			},
			fnCleanUp: func() {
				_, err := client.FlushDB(context.TODO()).Result()
				if err != nil {
					t.Fatalf("fail clear data base err:%v", err)
				}
			},
		},
		"no_exist_session": {
			IsError:         true,
			Err:             custerr.ErrNotFound,
			ReturnedSession: nil,
			FamilyId:        noExistfamilyId,
			UserId:          fullSession.UserId,
			fnReady: func() {

				// should be:
				//	session:{hex_user_id}:user:hex_family_id - Hmap session
				//	session:{hex_user_id}:refresh:hex_family_id - hex_family_id - for check uniq

				hexFamilyId := hex.EncodeToString(existfamilyId[:])

				refreshKey := fmt.Sprintf("session:{%v}:user:%v", hex.EncodeToString(fullSession.UserId[:]), hexFamilyId)
				sessionKey := fmt.Sprintf("session:{%v}:refresh:%v", hex.EncodeToString(fullSession.UserId[:]),
					hexFamilyId)

				data := map[string]interface{}{
					"user_id":     hex.EncodeToString(fullSession.UserId[:]),
					"device_id":   fullSession.DeviceId,
					"agent":       fullSession.Agent,
					"ip":          fullSession.Ip,
					"created_at":  fullSession.CreatedAt.Unix(),
					"version":     fullSession.Version,
					"last_update": fullSession.LastUpdate.Unix(),
				}

				_, err := client.HSet(context.TODO(), sessionKey, data).Result()
				if err != nil {
					t.Errorf("fail ready test err:%v", err)
				}
				_, err = client.Expire(context.TODO(), sessionKey, 10*time.Hour).Result()
				if err != nil {
					t.Errorf("fail ready test err:%v", err)
				}

				_, err = client.Set(context.TODO(), refreshKey, hexFamilyId, 10*time.Hour).Result()
				if err != nil {
					t.Errorf("fail ready test err:%v", err)
				}

			},
			fnCleanUp: func() {
				_, err := client.FlushDB(context.TODO()).Result()
				if err != nil {
					t.Fatalf("fail clear data base err:%v", err)
				}
			},
		},
		"invalid_args": {
			IsError:         true,
			Err:             custerr.ErrBadArgs,
			ReturnedSession: nil,
			FamilyId:        uuid.Nil(),
			UserId:          uuid.Nil(),
			fnReady:         func() {},
			fnCleanUp: func() {
				_, err := client.FlushDB(context.TODO()).Result()
				if err != nil {
					t.Fatalf("fail clear data base err:%v", err)
				}
			},
		},
	}

	for name, val := range table {

		t.Run(name, func(t *testing.T) {

			val.fnReady()

			res, err := sessionStore.GetSessionByFamilyId(context.TODO(), val.UserId, val.FamilyId)
			if val.IsError {
				if !val.Err.Is(err) {
					t.Errorf("fail return error want:%v have:%v", val.Err, err)
				}
			} else {
				if err != nil {
					t.Errorf("fail return error should return nil err:%v", err)
				}

				if res != nil {

					if res.UserId != val.ReturnedSession.UserId || res.DeviceId != val.ReturnedSession.DeviceId ||
						res.Agent != val.ReturnedSession.Agent || res.Ip != val.ReturnedSession.Ip ||
						res.Version != val.ReturnedSession.Version ||
						!val.ReturnedSession.CreatedAt.Truncate(time.Second).Equal(res.CreatedAt) {
						t.Errorf("fail field dont equal")
					}

				} else {
					t.Errorf("fail return nil want *domain.Session have nil")
				}
			}

			val.fnCleanUp()
		})
	}
}

// SPEC
//	SessionStore:
//		GetAllSession - метод получает все сессии пользователя
//			Args - 	ctx - контекст выполнения
// 					userId - uuid.UUID айдишник пользователя
//			Return - ([]Session, error)
// 					(Список сессий, nil),
// 					(nil, Ошибка не корректно заполнены аргументы)
// 					([], nil) - если сессий нет
//			Tests:
//					correct_request - корректный запрос с несколькими сессиями, должны вернуться все сессии
//					no_sessions - пользователь без сессий, должен вернуться пустой список
//					invalid_args - попытка получить сессии с незаполненным userId, должна вернуться ошибка
//

func TestGetAllSession(t *testing.T) {
	cm := config.NewConfigManager()
	cm.Init(context.TODO(), "")

	sessionStore, err := loadAndGetSessionStore()
	if err != nil {
		t.Fatalf("fail load session store, err:%v", err)
	}

	client, err := loadRedisClient()
	if err != nil {
		t.Fatalf("dont load redis err:%v", err)
	}

	userId1 := uuid.NewV7()
	//userId2 := uuid.NewV7()
	familyId1 := uuid.NewV7()
	familyId2 := uuid.NewV7()

	session1 := domain.Session{
		UserId:     userId1,
		DeviceId:   "device-1",
		Ip:         "192.168.1.1",
		Agent:      "chrome win 10",
		CreatedAt:  time.Now().Truncate(time.Second),
		Version:    "jwt-1",
		LastUpdate: time.Now().Truncate(time.Second),
	}

	session2 := domain.Session{
		UserId:     userId1,
		DeviceId:   "device-2",
		Ip:         "192.168.1.2",
		Agent:      "firefox macos",
		CreatedAt:  time.Now().Truncate(time.Second).Add(-1 * time.Hour),
		Version:    "jwt-2",
		LastUpdate: time.Now().Truncate(time.Second).Add(-1 * time.Hour),
	}

	//session3 := domain.Session{
	//	UserId:    userId2,
	//	DeviceId:  "device-3",
	//	Ip:        "10.0.0.1",
	//	Agent:     "safari ios",
	//	CreatedAt: time.Now().Truncate(time.Second).Add(-2 * time.Hour),
	//	Version:   "jwt-3",
	//}

	table := map[string]struct {
		IsError         bool
		Err             *repoerrors.RepoError
		ExpectedCount   int
		UserId          uuid.UUID
		SessionsToSetup []domain.Session
		FamilyIds       []uuid.UUID
		fnReady         func()
		fnCleanUp       func()
		fnCheckResult   func(result []domain.Session)
	}{
		"correct_request": {
			IsError:         false,
			Err:             nil,
			ExpectedCount:   2,
			UserId:          userId1,
			SessionsToSetup: []domain.Session{session1, session2},
			FamilyIds:       []uuid.UUID{familyId1, familyId2},
			fnReady: func() {
				hexUserId := hex.EncodeToString(userId1[:])

				// Setup session 1
				hexFamId1 := hex.EncodeToString(familyId1[:])
				// refreshKey (Hash) - содержит данные сессии
				refreshKey1 := fmt.Sprintf("session:{%v}:refresh:%v", hexUserId, hexFamId1)
				// sessionKey (String) - содержит familyId
				sessionKey1 := fmt.Sprintf("session:{%v}:user:%v", hexUserId, hexFamId1)

				data1 := map[string]interface{}{
					"user_id":     hex.EncodeToString(session1.UserId[:]),
					"device_id":   session1.DeviceId,
					"agent":       session1.Agent,
					"ip":          session1.Ip,
					"created_at":  session1.CreatedAt.Unix(),
					"version":     session1.Version,
					"last_update": session1.LastUpdate.Unix(),
				}

				_, err := client.HSet(context.TODO(), refreshKey1, data1).Result()
				if err != nil {
					t.Errorf("fail ready test session1 err:%v", err)
				}
				_, err = client.Expire(context.TODO(), refreshKey1, 10*time.Hour).Result()
				if err != nil {
					t.Errorf("fail ready test session1 ttl err:%v", err)
				}

				_, err = client.Set(context.TODO(), sessionKey1, hexFamId1, 10*time.Hour).Result()
				if err != nil {
					t.Errorf("fail ready test session1 sessionKey err:%v", err)
				}

				// Setup session 2
				hexFamId2 := hex.EncodeToString(familyId2[:])
				// refreshKey (Hash) - содержит данные сессии
				refreshKey2 := fmt.Sprintf("session:{%v}:refresh:%v", hexUserId, hexFamId2)
				// sessionKey (String) - содержит familyId
				sessionKey2 := fmt.Sprintf("session:{%v}:user:%v", hexUserId, hexFamId2)

				data2 := map[string]interface{}{
					"user_id":     hex.EncodeToString(session2.UserId[:]),
					"device_id":   session2.DeviceId,
					"agent":       session2.Agent,
					"ip":          session2.Ip,
					"created_at":  session2.CreatedAt.Unix(),
					"version":     session2.Version,
					"last_update": session2.LastUpdate.Unix(),
				}

				_, err = client.HSet(context.TODO(), refreshKey2, data2).Result()
				if err != nil {
					t.Errorf("fail ready test session2 err:%v", err)
				}
				_, err = client.Expire(context.TODO(), refreshKey2, 10*time.Hour).Result()
				if err != nil {
					t.Errorf("fail ready test session2 ttl err:%v", err)
				}

				_, err = client.Set(context.TODO(), sessionKey2, hexFamId2, 10*time.Hour).Result()
				if err != nil {
					t.Errorf("fail ready test session2 sessionKey err:%v", err)
				}
			},
			fnCleanUp: func() {
				_, err := client.FlushDB(context.TODO()).Result()
				if err != nil {
					t.Fatalf("fail clear data base err:%v", err)
				}
			},
			fnCheckResult: func(result []domain.Session) {
				if len(result) != 2 {
					t.Errorf("fail expected 2 sessions, got %d", len(result))
					return
				}

				// Check that both sessions are present
				foundSession1 := false
				foundSession2 := false

				for _, sess := range result {
					if sess.DeviceId == session1.DeviceId && sess.Ip == session1.Ip && sess.Agent == session1.Agent {
						foundSession1 = true
						if sess.UserId != session1.UserId {
							t.Errorf("fail session1 userId mismatch")
						}
						if sess.Version != session1.Version {
							t.Errorf("fail session1 version mismatch")
						}
						if !sess.CreatedAt.Truncate(time.Second).Equal(session1.CreatedAt) {
							t.Errorf("fail session1 created_at mismatch")
						}
					}
					if sess.DeviceId == session2.DeviceId && sess.Ip == session2.Ip && sess.Agent == session2.Agent {
						foundSession2 = true
						if sess.UserId != session2.UserId {
							t.Errorf("fail session2 userId mismatch")
						}
						if sess.Version != session2.Version {
							t.Errorf("fail session2 version mismatch")
						}
						if !sess.CreatedAt.Truncate(time.Second).Equal(session2.CreatedAt) {
							t.Errorf("fail session2 created_at mismatch")
						}
					}
				}

				if !foundSession1 {
					t.Errorf("fail session1 not found in result")
				}
				if !foundSession2 {
					t.Errorf("fail session2 not found in result")
				}
			},
		},
		"no_sessions": {
			IsError:         false,
			Err:             nil,
			ExpectedCount:   0,
			UserId:          userId1,
			SessionsToSetup: []domain.Session{},
			FamilyIds:       []uuid.UUID{},
			fnReady: func() {
				// No sessions setup - empty state
			},
			fnCleanUp: func() {
				_, err := client.FlushDB(context.TODO()).Result()
				if err != nil {
					t.Fatalf("fail clear data base err:%v", err)
				}
			},
			fnCheckResult: func(result []domain.Session) {
				if len(result) != 0 {
					t.Errorf("fail expected 0 sessions, got %d", len(result))
				}
			},
		},
		"invalid_args": {
			IsError:         true,
			Err:             custerr.ErrBadArgs,
			ExpectedCount:   0,
			UserId:          uuid.Nil(),
			SessionsToSetup: []domain.Session{},
			FamilyIds:       []uuid.UUID{},
			fnReady: func() {
				_, err := client.FlushDB(context.TODO()).Result()
				if err != nil {
					t.Errorf("fail flush db in ready err:%v", err)
				}
			},
			fnCleanUp: func() {},
			fnCheckResult: func(result []domain.Session) {
				if len(result) != 0 {
					t.Errorf("fail expected 0 sessions for invalid args, got %d", len(result))
				}
			},
		},
	}

	for name, val := range table {

		t.Run(name, func(t *testing.T) {

			val.fnReady()

			result, err := sessionStore.GetAllSession(context.Background(), val.UserId)
			if val.IsError {
				if !val.Err.Is(err) {
					t.Errorf("fail return error want:%v have:%v", val.Err, err)
				}
			} else {
				if err != nil {
					t.Errorf("fail return error should return nil err:%v", err)
				}

				if val.fnCheckResult != nil {
					val.fnCheckResult(result)
				}
			}

			val.fnCleanUp()
		})
	}
}

// SPEC
//	SessionStore:
//		DeleteAll - метод удаляет все сессии пользователя
//			Args - 	ctx - контекст выполнения
// 					id - uuid.UUID айдишник пользователя
//			Return - (error)
// 					(nil) - если сессии успешно удалены
// 					(nil) - если сессий не было (успешно, без ошибки)
// 					(error) - если не корректно заполнены аргументы (uuid.Nil)
//					(error) - если упал редис
//			Tests:
//					correct_request - корректный запрос с несколькими сессиями, все сессии должны быть удалены
//					no_sessions - удаление для пользователя без сессий, ошибка не должна вернуться
//					invalid_args - попытка удалить сессии с uuid.Nil, должна вернуться ошибка
//

func TestDeleteAll(t *testing.T) {
	cm := config.NewConfigManager()
	cm.Init(context.TODO(), "")

	sessionStore, err := loadAndGetSessionStore()
	if err != nil {
		t.Fatalf("fail load session store, err:%v", err)
	}

	client, err := loadRedisClient()
	if err != nil {
		t.Fatalf("dont load redis err:%v", err)
	}

	userId1 := uuid.NewV7()
	familyId1 := uuid.NewV7()
	familyId2 := uuid.NewV7()

	session1 := domain.Session{
		UserId:     userId1,
		DeviceId:   "device-1",
		Ip:         "192.168.1.1",
		Agent:      "chrome win 10",
		CreatedAt:  time.Now().Truncate(time.Second),
		Version:    "jwt-1",
		LastUpdate: time.Now().Truncate(time.Second),
	}

	session2 := domain.Session{
		UserId:     userId1,
		DeviceId:   "device-2",
		Ip:         "192.168.1.2",
		Agent:      "firefox macos",
		CreatedAt:  time.Now().Truncate(time.Second).Add(-1 * time.Hour),
		Version:    "jwt-2",
		LastUpdate: time.Now().Truncate(time.Second).Add(-1 * time.Hour),
	}

	table := map[string]struct {
		IsError         bool
		Err             *repoerrors.RepoError
		UserId          uuid.UUID
		SessionsToSetup []domain.Session
		FamilyIds       []uuid.UUID
		fnReady         func()
		fnCleanUp       func()
		fnCheckAfter    func()
	}{
		"correct_request": {
			IsError:         false,
			Err:             nil,
			UserId:          userId1,
			SessionsToSetup: []domain.Session{session1, session2},
			FamilyIds:       []uuid.UUID{familyId1, familyId2},
			fnReady: func() {
				hexUserId := hex.EncodeToString(userId1[:])

				// Setup session 1
				hexFamId1 := hex.EncodeToString(familyId1[:])
				// refreshKey (Hash) - содержит данные сессии
				refreshKey1 := fmt.Sprintf("session:{%v}:refresh:%v", hexUserId, hexFamId1)
				// sessionKey (String) - содержит familyId
				sessionKey1 := fmt.Sprintf("session:{%v}:user:%v", hexUserId, hexFamId1)

				data1 := map[string]interface{}{
					"user_id":     hex.EncodeToString(session1.UserId[:]),
					"device_id":   session1.DeviceId,
					"agent":       session1.Agent,
					"ip":          session1.Ip,
					"created_at":  session1.CreatedAt.Unix(),
					"version":     session1.Version,
					"last_update": session1.LastUpdate.Unix(),
				}

				_, err := client.HSet(context.TODO(), refreshKey1, data1).Result()
				if err != nil {
					t.Errorf("fail ready test session1 err:%v", err)
				}
				_, err = client.Expire(context.TODO(), refreshKey1, 10*time.Hour).Result()
				if err != nil {
					t.Errorf("fail ready test session1 ttl err:%v", err)
				}

				_, err = client.Set(context.TODO(), sessionKey1, hexFamId1, 10*time.Hour).Result()
				if err != nil {
					t.Errorf("fail ready test session1 sessionKey err:%v", err)
				}

				// Setup session 2
				hexFamId2 := hex.EncodeToString(familyId2[:])
				// refreshKey (Hash) - содержит данные сессии
				refreshKey2 := fmt.Sprintf("session:{%v}:refresh:%v", hexUserId, hexFamId2)
				// sessionKey (String) - содержит familyId
				sessionKey2 := fmt.Sprintf("session:{%v}:user:%v", hexUserId, hexFamId2)

				data2 := map[string]interface{}{
					"user_id":     hex.EncodeToString(session2.UserId[:]),
					"device_id":   session2.DeviceId,
					"agent":       session2.Agent,
					"ip":          session2.Ip,
					"created_at":  session2.CreatedAt.Unix(),
					"version":     session2.Version,
					"last_update": session2.LastUpdate.Unix(),
				}

				_, err = client.HSet(context.TODO(), refreshKey2, data2).Result()
				if err != nil {
					t.Errorf("fail ready test session2 err:%v", err)
				}
				_, err = client.Expire(context.TODO(), refreshKey2, 10*time.Hour).Result()
				if err != nil {
					t.Errorf("fail ready test session2 ttl err:%v", err)
				}

				_, err = client.Set(context.TODO(), sessionKey2, hexFamId2, 10*time.Hour).Result()
				if err != nil {
					t.Errorf("fail ready test session2 sessionKey err:%v", err)
				}
			},
			fnCleanUp: func() {
				_, err := client.FlushDB(context.TODO()).Result()
				if err != nil {
					t.Fatalf("fail clear data base err:%v", err)
				}
			},
			fnCheckAfter: func() {
				hexUserId := hex.EncodeToString(userId1[:])

				// Проверяем что refreshKey (Hash) удалены
				refreshKey1 := fmt.Sprintf("session:{%v}:refresh:%v", hexUserId, hex.EncodeToString(familyId1[:]))
				refreshKey2 := fmt.Sprintf("session:{%v}:refresh:%v", hexUserId, hex.EncodeToString(familyId2[:]))

				count1, err := client.Exists(context.TODO(), refreshKey1).Result()
				if err != nil {
					t.Errorf("fail check refreshKey1 err:%v", err)
				}
				if count1 > 0 {
					t.Errorf("fail refreshKey1 should be deleted, but exists")
				}

				count2, err := client.Exists(context.TODO(), refreshKey2).Result()
				if err != nil {
					t.Errorf("fail check refreshKey2 err:%v", err)
				}
				if count2 > 0 {
					t.Errorf("fail refreshKey2 should be deleted, but exists")
				}

				// Проверяем что sessionKey (String) удалены
				sessionKey1 := fmt.Sprintf("session:{%v}:user:%v", hexUserId, hex.EncodeToString(familyId1[:]))
				sessionKey2 := fmt.Sprintf("session:{%v}:user:%v", hexUserId, hex.EncodeToString(familyId2[:]))

				sessionCount1, err := client.Exists(context.TODO(), sessionKey1).Result()
				if err != nil {
					t.Errorf("fail check sessionKey1 err:%v", err)
				}
				if sessionCount1 > 0 {
					t.Errorf("fail sessionKey1 should be deleted, but exists")
				}

				sessionCount2, err := client.Exists(context.TODO(), sessionKey2).Result()
				if err != nil {
					t.Errorf("fail check sessionKey2 err:%v", err)
				}
				if sessionCount2 > 0 {
					t.Errorf("fail sessionKey2 should be deleted, but exists")
				}

				// Проверяем что GetAllSession возвращает пустой список
				sessions, err := sessionStore.GetAllSession(context.Background(), userId1)
				if err != nil {
					t.Errorf("fail GetAllSession after delete err:%v", err)
				}
				if len(sessions) != 0 {
					t.Errorf("fail expected 0 sessions after delete, got %d", len(sessions))
				}
			},
		},
		"no_sessions": {
			IsError:         false,
			Err:             nil,
			UserId:          userId1,
			SessionsToSetup: []domain.Session{},
			FamilyIds:       []uuid.UUID{},
			fnReady: func() {
				// No sessions setup - empty state
			},
			fnCleanUp: func() {
				_, err := client.FlushDB(context.TODO()).Result()
				if err != nil {
					t.Fatalf("fail clear data base err:%v", err)
				}
			},
			fnCheckAfter: func() {
				// No error expected, nothing to check
			},
		},
		"invalid_args": {
			IsError:         true,
			Err:             custerr.ErrBadArgs,
			UserId:          uuid.Nil(),
			SessionsToSetup: []domain.Session{},
			FamilyIds:       []uuid.UUID{},
			fnReady: func() {
				_, err := client.FlushDB(context.TODO()).Result()
				if err != nil {
					t.Errorf("fail flush db in ready err:%v", err)
				}
			},
			fnCleanUp: func() {},
			fnCheckAfter: func() {
				// Nothing to check
			},
		},
	}

	for name, val := range table {

		t.Run(name, func(t *testing.T) {

			val.fnReady()

			err := sessionStore.DeleteAll(context.Background(), val.UserId)
			if val.IsError {
				if !val.Err.Is(err) {
					t.Errorf("fail return error want:%v have:%v", val.Err, err)
				}
			} else {
				if err != nil {
					t.Errorf("fail delete all err:%v", err)
				}

				if val.fnCheckAfter != nil {
					val.fnCheckAfter()
				}
			}

			val.fnCleanUp()
		})
	}
}

// SPEC
//	SessionStore:
//		DeleteByRefresh - метод удаляет одну сессию по familyId
//			Args - 	ctx - контекст выполнения
// 					id - uuid.UUID айдишник пользователя
// 					familyId - uuid.UUID айдишник семейства refresh токенов
//			Return - (error)
// 					(nil) - если сессия успешно удалена
// 					(error) - если сессия не найдена (ErrNotFound)
// 					(error) - если не корректно заполнены аргументы (uuid.Nil)
//					(error) - если упал редис
//			Tests:
//					correct_request - корректный запрос с существующей сессией, сессия должна быть удалена
//					session_not_found - попытка удалить несуществующую сессию, должна вернуться ошибка ErrNotFound
//					invalid_args - попытка удалить сессию с uuid.Nil, должна вернуться ошибка ErrBadArgs
//

func TestDeleteByRefresh(t *testing.T) {
	cm := config.NewConfigManager()
	cm.Init(context.TODO(), "")

	sessionStore, err := loadAndGetSessionStore()
	if err != nil {
		t.Fatalf("fail load session store, err:%v", err)
	}

	client, err := loadRedisClient()
	if err != nil {
		t.Fatalf("dont load redis err:%v", err)
	}

	userId1 := uuid.NewV7()
	familyId1 := uuid.NewV7()
	familyId2 := uuid.NewV7()

	session1 := domain.Session{
		UserId:    userId1,
		DeviceId:  "device-1",
		Ip:        "192.168.1.1",
		Agent:     "chrome win 10",
		CreatedAt: time.Now().Truncate(time.Second),
		Version:   "jwt-1",
	}

	table := map[string]struct {
		IsError         bool
		Err             *repoerrors.RepoError
		UserId          uuid.UUID
		FamilyId        uuid.UUID
		SessionsToSetup []domain.Session
		FamilyIds       []uuid.UUID
		fnReady         func()
		fnCleanUp       func()
		fnCheckAfter    func()
	}{
		"correct_request": {
			IsError:         false,
			Err:             nil,
			UserId:          userId1,
			FamilyId:        familyId1,
			SessionsToSetup: []domain.Session{session1},
			FamilyIds:       []uuid.UUID{familyId1, familyId2},
			fnReady: func() {
				hexUserId := hex.EncodeToString(userId1[:])

				// Setup session 1 (будет удалена)
				hexFamId1 := hex.EncodeToString(familyId1[:])
				// refreshKey (Hash) - содержит данные сессии
				refreshKey1 := fmt.Sprintf("session:{%v}:refresh:%v", hexUserId, hexFamId1)
				// sessionKey (String) - содержит familyId
				sessionKey1 := fmt.Sprintf("session:{%v}:user:%v", hexUserId, hexFamId1)

				data1 := map[string]interface{}{
					"user_id":     hex.EncodeToString(session1.UserId[:]),
					"device_id":   session1.DeviceId,
					"agent":       session1.Agent,
					"ip":          session1.Ip,
					"created_at":  session1.CreatedAt.Unix(),
					"version":     session1.Version,
					"last_update": session1.LastUpdate.Unix(),
				}

				_, err := client.HSet(context.TODO(), refreshKey1, data1).Result()
				if err != nil {
					t.Errorf("fail ready test session1 err:%v", err)
				}
				_, err = client.Expire(context.TODO(), refreshKey1, 10*time.Hour).Result()
				if err != nil {
					t.Errorf("fail ready test session1 ttl err:%v", err)
				}

				_, err = client.Set(context.TODO(), sessionKey1, hexFamId1, 10*time.Hour).Result()
				if err != nil {
					t.Errorf("fail ready test session1 sessionKey err:%v", err)
				}

				// Setup session 2 (НЕ будет удалена, должна остаться)
				hexFamId2 := hex.EncodeToString(familyId2[:])
				// refreshKey (Hash) - содержит данные сессии
				refreshKey2 := fmt.Sprintf("session:{%v}:refresh:%v", hexUserId, hexFamId2)
				// sessionKey (String) - содержит familyId
				sessionKey2 := fmt.Sprintf("session:{%v}:user:%v", hexUserId, hexFamId2)

				data2 := map[string]interface{}{
					"user_id":     hex.EncodeToString(session1.UserId[:]),
					"device_id":   "device-2",
					"agent":       "firefox macos",
					"ip":          "192.168.1.2",
					"created_at":  session1.CreatedAt.Unix(),
					"version":     "jwt-2",
					"last_update": session1.LastUpdate.Unix(),
				}

				_, err = client.HSet(context.TODO(), refreshKey2, data2).Result()
				if err != nil {
					t.Errorf("fail ready test session2 err:%v", err)
				}
				_, err = client.Expire(context.TODO(), refreshKey2, 10*time.Hour).Result()
				if err != nil {
					t.Errorf("fail ready test session2 ttl err:%v", err)
				}

				_, err = client.Set(context.TODO(), sessionKey2, hexFamId2, 10*time.Hour).Result()
				if err != nil {
					t.Errorf("fail ready test session2 sessionKey err:%v", err)
				}
			},
			fnCleanUp: func() {
				_, err := client.FlushDB(context.TODO()).Result()
				if err != nil {
					t.Fatalf("fail clear data base err:%v", err)
				}
			},
			fnCheckAfter: func() {
				hexUserId := hex.EncodeToString(userId1[:])

				// Проверяем что session1 (которую удаляли) удалена
				refreshKey1 := fmt.Sprintf("session:{%v}:refresh:%v", hexUserId, hex.EncodeToString(familyId1[:]))
				sessionKey1 := fmt.Sprintf("session:{%v}:user:%v", hexUserId, hex.EncodeToString(familyId1[:]))

				refreshCount1, err := client.Exists(context.TODO(), refreshKey1).Result()
				if err != nil {
					t.Errorf("fail check refreshKey1 err:%v", err)
				}
				if refreshCount1 > 0 {
					t.Errorf("fail refreshKey1 should be deleted, but exists")
				}

				sessionCount1, err := client.Exists(context.TODO(), sessionKey1).Result()
				if err != nil {
					t.Errorf("fail check sessionKey1 err:%v", err)
				}
				if sessionCount1 > 0 {
					t.Errorf("fail sessionKey1 should be deleted, but exists")
				}

				// Проверяем что session2 (которую НЕ удаляли) осталась
				refreshKey2 := fmt.Sprintf("session:{%v}:refresh:%v", hexUserId, hex.EncodeToString(familyId2[:]))
				sessionKey2 := fmt.Sprintf("session:{%v}:user:%v", hexUserId, hex.EncodeToString(familyId2[:]))

				refreshCount2, err := client.Exists(context.TODO(), refreshKey2).Result()
				if err != nil {
					t.Errorf("fail check refreshKey2 err:%v", err)
				}
				if refreshCount2 == 0 {
					t.Errorf("fail refreshKey2 should exist, but was deleted")
				}

				sessionCount2, err := client.Exists(context.TODO(), sessionKey2).Result()
				if err != nil {
					t.Errorf("fail check sessionKey2 err:%v", err)
				}
				if sessionCount2 == 0 {
					t.Errorf("fail sessionKey2 should exist, but was deleted")
				}

				// Проверяем что GetAllSession возвращает только одну сессию (session2)
				sessions, err := sessionStore.GetAllSession(context.Background(), userId1)
				if err != nil {
					t.Errorf("fail GetAllSession after delete err:%v", err)
				}
				if len(sessions) != 1 {
					t.Errorf("fail expected 1 session after delete, got %d", len(sessions))
				}
				if len(sessions) == 1 && sessions[0].DeviceId != "device-2" {
					t.Errorf("fail wrong session returned, expected device-2")
				}
			},
		},
		"session_not_found": {
			IsError:         true,
			Err:             custerr.ErrNotFound,
			UserId:          userId1,
			FamilyId:        familyId1,
			SessionsToSetup: []domain.Session{},
			FamilyIds:       []uuid.UUID{},
			fnReady: func() {
				// No sessions setup - session doesn't exist
			},
			fnCleanUp: func() {
				_, err := client.FlushDB(context.TODO()).Result()
				if err != nil {
					t.Fatalf("fail clear data base err:%v", err)
				}
			},
			fnCheckAfter: func() {
				// Nothing to check - session was never there
			},
		},
		"invalid_args": {
			IsError:         true,
			Err:             custerr.ErrBadArgs,
			UserId:          uuid.Nil(),
			FamilyId:        uuid.Nil(),
			SessionsToSetup: []domain.Session{},
			FamilyIds:       []uuid.UUID{},
			fnReady: func() {
				_, err := client.FlushDB(context.TODO()).Result()
				if err != nil {
					t.Errorf("fail flush db in ready err:%v", err)
				}
			},
			fnCleanUp: func() {},
			fnCheckAfter: func() {
				// Nothing to check
			},
		},
	}

	for name, val := range table {

		t.Run(name, func(t *testing.T) {

			val.fnReady()

			err := sessionStore.DeleteByRefresh(context.Background(), val.UserId, val.FamilyId)
			if val.IsError {
				if !val.Err.Is(err) {
					t.Errorf("fail return error want:%v have:%v", val.Err, err)
				}
			} else {
				if err != nil {
					t.Errorf("fail delete by refresh err:%v", err)
				}

				if val.fnCheckAfter != nil {
					val.fnCheckAfter()
				}
			}

			val.fnCleanUp()
		})
	}
}

// SPEC
//	SessionStore:
//		UpdateVersion - метод поднимает версию сессии и возвращает ее
//			Args - 	ctx - контекст выполнения
// 					userId - uuid.UUID айдишник пользователя
// 					familyId - uuid.UUID айдишник семейства refresh токенов
//			Return - (string, error)
// 					(string, nil) - если версия успешно поднята, вернет новую сессию
// 					("", error) - если сессия не найдена (ErrNotFound)
// 					("", error) - если между текущим временем и временем последнего обновления меньше времени
// 									 чем время жизни access токена (ErrSuspiciousRefreshRate)
// 					("", error) - если не корректно заполнены аргументы (uuid.Nil)
//					("", error) - если упал редис
//			Tests:
//					correct_request - корректный запрос с существующей сессией, у сессии должна быть обновлена версия
//					session_not_found - попытка обновить версию несуществующую сессии, должна вернуться ошибка ErrNotFound
//					suspicious_refresh_rate - попытка обновить только что обновленную сессию ErrSuspiciousRefreshRate
//					invalid_args - попытка удалить сессию с uuid.Nil, должна вернуться ошибка ErrBadArgs
//

func TestUpdateVersion(t *testing.T) {

	cm := config.NewConfigManager()
	cm.Init(context.TODO(), "")

	sessionStore, err := loadAndGetSessionStore()
	if err != nil {
		t.Fatalf("fail load session store, err:%v", err)
	}

	client, err := loadRedisClient()
	if err != nil {
		t.Fatalf("dont load redis err:%v", err)
	}

	userId1 := uuid.NewV7()
	familyId1 := uuid.NewV7()
	familyId2 := uuid.NewV7()

	session1 := domain.Session{
		UserId:     userId1,
		DeviceId:   "device-1",
		Ip:         "192.168.1.1",
		Agent:      "chrome win 10",
		CreatedAt:  time.Now().Add(-32 * time.Minute),
		Version:    "jwt-2",
		LastUpdate: time.Now().Add(-16 * time.Minute),
	}

	session2 := domain.Session{
		UserId:     uuid.NewV7(),
		DeviceId:   "device-34",
		Ip:         "192.155.1.1",
		Agent:      "safari ios",
		CreatedAt:  time.Now().Add(-48 * time.Minute),
		Version:    "jwt-3",
		LastUpdate: time.Now().Add(-16 * time.Minute),
	}

	table := map[string]struct {
		IsError   bool
		Err       *repoerrors.RepoError
		UserId    uuid.UUID
		FamilyId  uuid.UUID
		fnCleanUp func()
		fnReady   func()
		fnCheck   func()
	}{
		"correct_request": {
			IsError:  false,
			Err:      nil,
			UserId:   userId1,
			FamilyId: familyId1,
			fnCleanUp: func() {
				_, err := client.FlushDB(context.TODO()).Result()
				if err != nil {
					t.Fatalf("fail clear data base err:%v", err)
				}
			},
			fnReady: func() {

				hexUserId1 := hex.EncodeToString(userId1[:])
				hexFamilyId1 := hex.EncodeToString(familyId1[:])
				refreshKey1 := fmt.Sprintf("session:{%v}:refresh:%v", hexUserId1, hexFamilyId1)
				sessionKey1 := fmt.Sprintf("session:{%v}:user:%v", hexUserId1, hexFamilyId1)

				_, err := client.HSet(context.TODO(), refreshKey1,
					map[string]interface{}{
						"user_id":     hexUserId1,
						"device_id":   session1.DeviceId,
						"ip":          session1.Ip,
						"agent":       session1.Agent,
						"created_at":  session1.CreatedAt.Unix(),
						"version":     session1.Version,
						"last_update": session1.LastUpdate.Unix(),
					}).Result()
				if err != nil {
					t.Errorf("fail ready session err:%v", err)
					return
				}

				_, err = client.Expire(context.TODO(), refreshKey1, 72*time.Hour).Result()
				if err != nil {
					t.Errorf("fail ready exp session err:%v", err)
					return
				}

				_, err = client.Set(context.TODO(), sessionKey1, hexFamilyId1, 72*time.Hour).Result()
				if err != nil {
					t.Errorf("fail ready session uniq key err:%v", err)
					return
				}

				hexUserId2 := hex.EncodeToString(session2.UserId[:])
				hexFamilyId2 := hex.EncodeToString(familyId2[:])
				refreshKey2 := fmt.Sprintf("session:{%v}:refresh:%v", hexUserId2, hexFamilyId2)
				sessionKey2 := fmt.Sprintf("session:{%v}:user:%v", hexUserId2, hexFamilyId2)

				_, err = client.HSet(context.TODO(), refreshKey2,
					map[string]interface{}{
						"user_id":     hexUserId2,
						"device_id":   session2.DeviceId,
						"ip":          session2.Ip,
						"agent":       session2.Agent,
						"created_at":  session2.CreatedAt.Unix(),
						"version":     session2.Version,
						"last_update": session2.LastUpdate.Unix(),
					}).Result()
				if err != nil {
					t.Errorf("fail ready session err:%v", err)
					return
				}

				_, err = client.Expire(context.TODO(), refreshKey2, 72*time.Hour).Result()
				if err != nil {
					t.Errorf("fail ready exp session err:%v", err)
					return
				}

				_, err = client.Set(context.TODO(), sessionKey2, hexFamilyId2, 72*time.Hour).Result()
				if err != nil {
					t.Errorf("fail ready session uniq key err:%v", err)
					return
				}

			},
			fnCheck: func() {

			},
		},
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

func loadAndGetSessionStore() (*reporedis.SessionStore, error) {
	ctx := context.Background()
	util.LoadEnvFile()

	cm := config.NewConfigManager()

	cm.Init(ctx, "")

	repo, err := reporedis.NewRepository(ctx, cm)
	if err != nil {
		return nil, fmt.Errorf("Failed connect in redis %v\n", err)
	}

	au := domain.GetMockAuditService()
	ss := reporedis.NewSessionStore(repo, au, 60*time.Minute)

	return ss, nil
}
