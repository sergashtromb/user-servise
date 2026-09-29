package main

import (
	"context"
	"embed"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"user_service/config"
	"user_service/infrastructure/postgres"
	"user_service/util"

	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

//go:embed migrations/*.sql
var embedMigrations embed.FS

func main() {

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	util.LoadEnvFile()

	slog.Info("Migrate start...")
	confFile := os.Getenv("CONFIG_FILE")

	goose.SetBaseFS(embedMigrations)

	if err := goose.SetDialect(string(goose.DialectPostgres)); err != nil {
		slog.Error("Failed set dialect postgres in goose", "err", err)
		log.Fatal("Migration error")
	}

	configManager := config.NewConfigManager()
	configManager.Init(ctx, confFile)

	dbManager, err := postgres.NewDataBase(ctx, configManager)
	if err != nil {
		slog.Error("Failed create db manager", "err", err)
		log.Fatal("Migration error")
	}
	defer dbManager.Shutdown()

	db := stdlib.OpenDBFromPool(dbManager.GetPool())
	defer db.Close()

	if err := goose.UpContext(ctx, db, "migrations"); err != nil {
		slog.Error("Failed up context", "err", err)
		log.Fatal("Migration error")
	}
}