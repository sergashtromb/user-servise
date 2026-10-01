package reporedis

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
	"user_service/config"

	"github.com/redis/go-redis/v9"
)

var (
	ErrRepositoryClosed = errors.New("repository closed")
	ErrCloseTimeout 	= errors.New("close timeout")
)

type Repository struct {
	clientPoint 	*clientInstance
	rm 				sync.RWMutex
	closed 			bool
	timeForClose 	time.Duration
}

type clientInstance struct {
	rClient 		*redis.Client
	wg 				sync.WaitGroup
	so 				sync.Once
	err 			error
	activeGor 		atomic.Int64
}

func NewRepository(ctx context.Context, cm *config.ConfigManager) (*Repository, error) {

	rc := cm.Get().RedisConf
	
	clInst, err := createClientInstance(ctx, &rc)
	if err != nil {
		return nil, err
	}

	rep := &Repository{
		clientPoint: clInst,
		closed: false,
		timeForClose: 5*time.Minute,
	}

	return rep, nil
}

func (rep *Repository) Do(ctx context.Context, fn func(ctx context.Context, client *redis.Client) error) error {

	rep.rm.RLock()

	if rep.closed {
		rep.rm.RUnlock()
		return ErrRepositoryClosed	
	}

	inst := rep.clientPoint
	inst.wg.Add(1)
	inst.activeGor.Add(1)
	rep.rm.RUnlock()

	defer func() {
		inst.activeGor.Add(-1)
	 	inst.wg.Done()
	}()

	return fn(ctx, inst.rClient)
}

func (rep *Repository) ChangeClient(ctx context.Context, rc *config.RedisConfig) error {

	newInstans, err := createClientInstance(ctx, rc)
	if err != nil {
		return err
	}

	rep.rm.Lock()

	if rep.closed {
		rep.rm.Unlock()
		newInstans.Close(1*time.Minute)
		return ErrRepositoryClosed
	}

	var oldInst *clientInstance

	oldInst = rep.clientPoint
	rep.clientPoint = newInstans

	rep.rm.Unlock()

	oldInst.Close(rep.timeForClose)
	return nil
}

func (rep *Repository) Shutdown() {

	var inst *clientInstance

	rep.rm.Lock()
	inst = rep.clientPoint
	rep.closed = true
	rep.rm.Unlock()

	inst.Close(rep.timeForClose)
}

func (ci *clientInstance) Close(timeForClose time.Duration) error {
	ci.so.Do(func() {

		done := make(chan struct{}, 1)

		go func() {
			ci.wg.Wait()
			close(done)
		}()

		timer := time.NewTimer(timeForClose)
		defer timer.Stop()

		select {
		case <-done:
			ci.err = ci.rClient.Close()
		case <-timer.C:
			ci.err = errors.Join(ErrCloseTimeout, ci.rClient.Close())
		}

		select {
		case <-done:
		case <-time.After(1*time.Second):
			// TODO add log message
		}			
		
	})

	return ci.err
}

func createClientInstance(ctx context.Context, redisConfig *config.RedisConfig) (*clientInstance, error) {

	client := redis.NewClient(&redis.Options{
		Addr: fmt.Sprintf("%s:%s", redisConfig.Host, redisConfig.Port),
		DB: redisConfig.DbNum,

		Password: redisConfig.Password,

		PoolSize: redisConfig.PoolSize,
		MinIdleConns: redisConfig.MinIdleConn,
		MaxIdleConns: redisConfig.MaxIdleConn,
		ConnMaxIdleTime: time.Duration(redisConfig.ConnMaxIdleTime) * time.Minute,
		ConnMaxLifetime: time.Duration(redisConfig.ConnMaxLifetime) * time.Minute,

		DialTimeout: time.Duration(redisConfig.DialTimeout) * time.Second,
		ReadTimeout: time.Duration(redisConfig.ReadTimeout) * time.Second,
		WriteTimeout: time.Duration(redisConfig.WriteTimeout) * time.Second,
		PoolTimeout: time.Duration(redisConfig.PoolTimeout) * time.Second,

	})

	if err := client.Ping(ctx).Err(); err != nil {
		slog.Error("Failed connect to redis", "err", err)
		return nil, err
	}

	return &clientInstance{
		rClient: client,
	}, nil
}

