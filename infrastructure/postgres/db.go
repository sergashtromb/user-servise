package postgres

import (
	"context"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"
	"user_service/config"

	"github.com/jackc/pgx/v5/pgxpool"
)

type DataBase struct {
	pool atomic.Pointer[pgxpool.Pool]
}

func NewDataBase(ctx context.Context, cm *config.ConfigManager) (*DataBase, error) {

	cnf := cm.Get()

	pool, err := createPool(ctx, &cnf.DataBaseConf)
	if err != nil {
		return nil, fmt.Errorf("Failed create config conn database :%s", err)
	}

	db := &DataBase{}
	db.pool.Store(pool)

	return db, nil
}

func (db *DataBase) ChangePool(ctx context.Context, baseCnf *config.DataBaseConfig) {

	newPool, err := createPool(ctx, baseCnf)
	if err != nil {
		fmt.Errorf("Failed change pool err:%w", err)
		return
	}

	oldPool := db.pool.Swap(newPool)

	go closePoolWithTimeout(oldPool, 30*time.Second)
}

func (db *DataBase) GetPool() *pgxpool.Pool {
	return db.pool.Load()
}

func closePoolWithTimeout(pool *pgxpool.Pool, timeout time.Duration) {

	done := make(chan struct{})

	go func() {
		pool.Close()
		close(done)
	}()

	select {
	case <-done:
		slog.Info("The rotation was successful")
	case <-time.After(timeout):
		slog.Warn("Not all active connections managed to close due to the timeout during the rotation")
	}

}

func createPool(ctx context.Context, dbc *config.DataBaseConfig) (*pgxpool.Pool, error) {

	pgxConf, err := pgxpool.ParseConfig(dbc.ToString())
	if err != nil {
		slog.Error("Failed create config conn database", "err", err)
		return nil, fmt.Errorf("Failed create config conn database :%s", err)
	}

	pool, err := pgxpool.NewWithConfig(ctx, pgxConf)
	if err != nil {
		slog.Error("Failed create pool pgx", "err", err)
		return nil, fmt.Errorf("Failed create pool pgx :%s", err)
	}

	err = pool.Ping(ctx)
	if err != nil {
		slog.Error("Unable to connect to the database", "err", err)
		return nil, fmt.Errorf("Unable to connect to the database", "err", err)
	}

	return pool, nil
}
