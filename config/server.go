package config

import (
	"context"
	"log/slog"
	"net/http"
)

type ConfigServer struct {
	port 	int // for change config from http
	server 	*http.Server
	cm 		*ConfigManager
}

func NewConfigServer(port int, cm *ConfigManager) *ConfigServer {
	return &ConfigServer {
		port: port,
		server: &http.Server{
			Addr: "127.0.0.1:"+string(port),
		},
		cm: cm,
	}
}

func (cs *ConfigServer) Start(ctx context.Context, configFile string) {

	cs.cm.Init(configFile)

	go func() {
		if err := cs.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("Failed server config", "err", err)
		}
	}()

	go func() {
		select {
		case <- ctx.Done():
			if err := cs.server.Shutdown(ctx); err != nil {
				slog.Error("Failed shutdown config server", "err", err)
			}
		}
	}()
}
