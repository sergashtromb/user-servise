package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
	"user_service/config"
)

func main() {

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	slog.Info("Start app")
	
	confFile := os.Getenv("CONFIG_FILE")

	configManager := config.NewConfigManager()
	configServer := config.NewConfigServer(8081, configManager)

	configServer.Start(ctx, confFile)

	<- ctx.Done()

	ctxTimeout, cancelTimeout := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelTimeout()

	var wg sync.WaitGroup

	wg.Go(func() {
		configServer.Shutdown(ctxTimeout)
	})

	wg.Wait()
}