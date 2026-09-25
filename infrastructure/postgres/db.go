package postgres

import (
	"context"
	"fmt"
	"log/slog"
	"sync/atomic"
	"user_service/config"

	"github.com/jackc/pgx/v5/pgxpool"
)

type DataBase struct {
	IsChangeConnActive 	atomic.Bool
	pool 				*pgxpool.Pool
	newPool 			*pgxpool.Pool
}

func NewDataBase(ctx context.Context, cm *config.ConfigManager) (*DataBase, error) {

	cnf := cm.Get()
	
	pool, err := createPool(ctx, &cnf.DataBaseConf)
	if err != nil {
		return nil, fmt.Errorf("Failed create config conn database :%s", err)
	}

	db := &DataBase{
		pool: pool,
	}
	db.IsChangeConnActive.Store(false)

	return db, nil
}

func (db *DataBase) ChangePool(ctx context.Context, baseCnf *config.DataBaseConfig) {

	newPool, err := createPool(ctx, baseCnf)
	if err != nil {
		return nil, fmt.Errorf("Failed change pool err:%w", err)
	}

}

func (db *DataBase) GetPool() *pgxpool.Pool {

	if db.IsChangeConnActive.Load() {
		return db.newPool
	} else {
		return db.pool
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