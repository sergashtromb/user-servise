package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"user_service/config"
	"user_service/infrastructure/postgres"
)

func main(){

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	slog.Info("Start app")
	
	confFile := os.Getenv("CONFIG_FILE")

	configManager := config.NewConfigManager()
	configServer := config.NewConfigServer(8081, configManager)

	configServer.Start(ctx, confFile)

	db, err := postgres.NewDataBase(ctx, configManager)
	if err != nil {
		fmt.Printf("FAIL: dont-conn in database %s\n", err)
		return
	} else {
		fmt.Println("PASS: success conn")
	}

	fmt.Printf("db %v\n", db)
}