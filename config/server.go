package config

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
)

type ConfigServer struct {
	port 	int // for change config from http
	server 	*http.Server
	cm 		*ConfigManager
}

func NewConfigServer(port int, cm *ConfigManager) *ConfigServer {

	Handler := ChangeSettingsHandler {
		cm: cm,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST admin/config", Handler.CheckChangeSettings)

	return &ConfigServer {
		port: port,
		server: &http.Server{
			Addr: fmt.Sprintf("127.0.0.1:%d", port),
			Handler: mux,
		},
		cm: cm,
	}
}

func (cs *ConfigServer) Start(ctx context.Context, configFile string) {

	cs.cm.Init(configFile)

	go func() {
		slog.Info("Start config server...")
		if err := cs.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("Failed server config", "err", err)
		}
	}()
}

func (cs *ConfigServer) Shutdown(ctx context.Context) {
	
	slog.Info("Close config server...")
	if err := cs.server.Shutdown(ctx); err != nil {
		slog.Error("Failed shutdown config server", "err", err)
	}
}