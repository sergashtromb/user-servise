package upgrateplan

import (
	"context"
	"time"
	"user_service/infrastructure/reporedis/custerr"
	"user_service/infrastructure/reporedis/index"
	"user_service/infrastructure/reporedis/patch"

	"github.com/redis/go-redis/v9"
)

type UpdatePlan struct {
	SetField  map[string]interface{}
	Diff      *index.IndexDiff
	DelField  []string
	NoChanges bool
}

type Builder[T any, S any] interface {
	BuildUpgratePlan(old T, patch S) *UpdatePlan
}

func (up *UpdatePlan) Apply(ctx context.Context, client *redis.Client, key string, hexid string, ttl time.Duration) error {

	toAdd, hasToAdd := up.Diff.ToAdd.GetIndexs()
	if hasToAdd {
		if err := ReservedIndex(ctx, client, toAdd, hexid, ttl); err != nil {
			return err
		}
	}

	toDel, hasToDel := up.Diff.ToDelete.GetIndexs()
	toExpire, hasToExpire := up.Diff.ToExpire.GetIndexs()

	pipe := client.TxPipeline()

	if len(up.SetField) > 0 {
		pipe.HSet(ctx, key, up.SetField)
	}

	if len(up.DelField) > 0 {
		pipe.HDel(ctx, key, up.DelField...)
	}

	if hasToAdd {
		for _, index := range toAdd {
			pipe.Expire(ctx, index, ttl)
		}
	}

	if hasToDel {
		pipe.Del(ctx, toDel...)
	}

	if hasToExpire {
		for _, index := range toExpire {
			pipe.Expire(ctx, index, ttl)
		}
	}

	_, err := pipe.Exec(ctx)
	if err != nil {
		if hasToAdd {
			if rolerr := RollbackIndex(ctx, client, toAdd); rolerr != nil {
				return rolerr
			}
			return err
		}
		return err
	}

	return nil
}

func ReservedIndex(ctx context.Context, client *redis.Client, indexs []string, id string, ttl time.Duration) error {

	var addedIndex []string

	for _, index := range indexs {
		ok, err := client.SetNX(ctx, index, id, ttl).Result()
		if err != nil {
			if rolerr := RollbackIndex(ctx, client, addedIndex); rolerr != nil {
				return rolerr
			}
			return err
		}

		if !ok {

			idOwner, err := client.Get(ctx, index).Result()
			if err != nil {
				if rolerr := RollbackIndex(ctx, client, addedIndex); rolerr != nil {
					return rolerr
				}
				return err
			}

			if idOwner == id {
				client.Expire(ctx, index, ttl)
				continue
			}

			if rolerr := RollbackIndex(ctx, client, addedIndex); rolerr != nil {
				return rolerr
			}
			errUserAlredyExist := custerr.ErrUserAlredyExist.Clone()
			errUserAlredyExist.Fields = append(errUserAlredyExist.Fields, index)
			return errUserAlredyExist
		}

		addedIndex = append(addedIndex, index)
	}

	return nil
}

func RollbackIndex(ctx context.Context, client *redis.Client, indexs []string) error {

	if len(indexs) == 0 {
		return nil
	}

	if _, err := client.Del(ctx, indexs...).Result(); err != nil {
		return err
	}

	return nil
}

func DataOption(patchs []patch.FieldPatch) (map[string]interface{}, []string) {

	toAdd := make(map[string]interface{})
	toDel := make([]string, 0)

	for _, field := range patchs {
		switch field.Action {
		case patch.FPSetField:
			toAdd[field.Name] = field.Value
		case patch.FPClearField:
			toDel = append(toDel, field.Name)
		}
	}

	return toAdd, toDel
}
