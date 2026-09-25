package config

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"

	"github.com/caarlos0/env/v11"
	_ "github.com/joho/godotenv/autoload"
	"github.com/knadh/koanf"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/file"
)

type ConfigManager struct {
	rm 			sync.RWMutex
	currSet 	*os.File
	cnf 		atomic.Pointer[Config] 
	kn 			*koanf.Koanf
	listener 	map[string][]func(ctx context.Context, option any)
}

type Config struct {
	Port 			int 			`yaml:"port" env:"PORT" koanf:"port" hot:"false"`
	LogLevel 		string 			`yaml:"log_level" env:"LOG_LEVEL" koanf:"log.level" hot:"true"`
	DataBaseConf 	DataBaseConfig 	`yaml:"data_base_config" envPrefix:"DB_"`
}

type DataBaseConfig struct {
	User 		string 	`yaml:"user" env:"USER" koanf:"data_base_config.user" hot:"false"`
	Password 	string 	`yaml:"password" env:"PASS" koanf:"data_base_config.pass" hot:"false"`
	DataBase 	string 	`yaml:"name" env:"NAME" koanf:"data_base_config.name" hot:"false"`
	Host 		string 	`yaml:"host" env:"HOST" koanf:"data_base_config.host" hot:"false"`
	Port 		string 	`yaml:"port" env:"PORT" koanf:"data_base_config.port" hot:"false"`
	MaxConn 	int 	`yaml:"max_conn" env:"MAX_CONN" koanf:"data_base_config.max_conn" hot:"true"`
	MinConn 	int 	`yaml:"min_conn" env:"MIN_CONN" koanf:"data_base_config.min_conn" hot:"true"`
}

func NewConfigManager() *ConfigManager {
	return &ConfigManager{
		kn: koanf.New("."),
		listener: make(map[string][]func(ctx context.Context, option any)),
	}
}

func (cm *ConfigManager) Init(ctx context.Context, configFile string) {

	cnf := setDefault()
	hasConfFile := false
	
	f := file.Provider(configFile)

	if err := cm.kn.Load(f, yaml.Parser()); err != nil {
		fmt.Printf("Dont load config file err=%v\n", err)
	} else {
		hasConfFile = true
	}

	if hasConfFile {
		f.Watch(func(event interface{}, err error){

			if err != nil {
				slog.Error("Watch config file error", "err", err)
				return
			}
			
			cm.kn = koanf.New(".")
			if err := cm.kn.Load(f, yaml.Parser()); err != nil {
				slog.Error("Error load config file", "err", err)
				return
			}

			cm.mergeChangesFromFile(ctx)
		})
	}
	slog.Info("yaml", "cnf", cnf)
	if err := env.Parse(cnf); err != nil {
		slog.Error("Error parse env", "err", err)
	}

	slog.Info("env", "cnf", cnf)
	cm.cnf.Store(cnf)
}

func (cm *ConfigManager) Get() *Config {
	return cm.cnf.Load()
}

func (cm *ConfigManager) Update(ctx context.Context, newCnf *Config) {

	oldCnf := cm.cnf.Swap(newCnf)

	if oldCnf.LogLevel != newCnf.LogLevel {
		cm.notify("log.level", ctx, newCnf.LogLevel)
	}

	if oldCnf.DataBaseConf.MaxConn != newCnf.DataBaseConf.MaxConn || 
		oldCnf.DataBaseConf.MinConn != newCnf.DataBaseConf.MinConn {
		cm.notify("data_base_config", ctx, newCnf.DataBaseConf)
	}
}

func (cm *ConfigManager) OnChange(key string, fn func(ctx context.Context, opt any)) {

	cm.rm.Lock()
	defer cm.rm.Unlock()

	_, ok := cm.listener[key]
	if !ok {
		cm.listener[key] = make([]func(ctx context.Context, option any), 0)
	}

	cm.listener[key] = append(cm.listener[key], fn)
}

func (cm *ConfigManager) notify(key string, ctx context.Context, newValue any) {
	cm.rm.RLock()
	listeners, ok := cm.listener[key]
	cm.rm.RUnlock()

	if !ok {
		return
	}

	for _, fn := range listeners {
		go fn(ctx, newValue)
	}
}

func (cm *ConfigManager) mergeChangesFromFile(ctx context.Context) {

	currCnf := cm.cnf.Load()
	cnf := *currCnf
	cnf.LogLevel = cm.kn.String("log.level")
	cnf.DataBaseConf.MaxConn = cm.kn.Int("data_base_config.max_conn")
	cnf.DataBaseConf.MinConn = cm.kn.Int("data_base_config.min_conn")
	
	cm.Update(ctx, &cnf)
}

func (dbc *DataBaseConfig) ToString() string {

	return fmt.Sprintf("user=%s password=%s host=%s port=%s dbname=%s pool_max_conns=%d pool_min_conns=%d",
		dbc.User, dbc.Password, dbc.Host, dbc.Port, dbc.DataBase, dbc.MaxConn, dbc.MinConn)
}

func setDefault() *Config {
	return &Config{
		Port: 8080,
		LogLevel: "info",
		DataBaseConf: DataBaseConfig {
			User: "",
			Password: "",
			DataBase: "",
			Host: "",
			Port: "",
			MaxConn: 15,
			MinConn: 3,
		},
	}
}