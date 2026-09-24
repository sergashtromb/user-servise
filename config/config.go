package config

import (
	"fmt"
	"log/slog"
	"os"
	"sync"

	"github.com/knadh/koanf"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/file"
	"github.com/caarlos0/env/v11"
)

type ConfigManager struct {
	rm 			sync.RWMutex
	currSet 	*os.File
	cnf 		*Config
	kn 			*koanf.Koanf
	listener 	map[string][]func(option any)
}

type Config struct {
	Port 		int 	`yaml:"port" env:"PORT" knoaf:"port" hot:"false"`
	LogLevel 	string 	`yaml:"log_level" env:"LOG_LEVEL" knoaf:"log.level" hot:"true"`
}


func NewConfigManager() *ConfigManager {
	return &ConfigManager{
		kn: koanf.New("."),
		listener: make(map[string][]func(option any)),
	}
}

func (cm *ConfigManager) Init(configFile string) {

	cm.cnf = setDefault()
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

			cm.mergeChangesFromFile()
		})
	}

	if err := env.Parse(cm.cnf); err != nil {
		slog.Error("Error parse env", "err", err)
	}
}

func (cm *ConfigManager) OnChange(key string, fn func(opt any)) {

	cm.rm.Lock()
	defer cm.rm.Unlock()

	_, ok := cm.listener[key]
	if !ok {
		cm.listener[key] = make([]func(option any), 0)
	}

	cm.listener[key] = append(cm.listener[key], fn)
}

func (cm *ConfigManager) notify(key string, newValue any) {
	cm.rm.RLock()
	listeners, ok := cm.listener[key]
	cm.rm.RUnlock()

	if !ok {
		return
	}

	for _, fn := range listeners {
		go fn(newValue)
	}
}

func (cm *ConfigManager) mergeChangesFromFile() {

	cm.rm.Lock()
	defer cm.rm.Unlock()

	cm.cnf.LogLevel = cm.kn.String("log.level")
}

func setDefault() *Config {
	return &Config{
		Port: 8080,
		LogLevel: "info",
	}
}