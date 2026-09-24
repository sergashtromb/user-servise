package config

import (
	"fmt"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"

	"github.com/caarlos0/env/v11"
	"github.com/knadh/koanf"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/file"
)

type ConfigManager struct {
	rm 			sync.RWMutex
	currSet 	*os.File
	cnf 		atomic.Pointer[Config] 
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

			cm.mergeChangesFromFile()
		})
	}

	if err := env.Parse(cnf); err != nil {
		slog.Error("Error parse env", "err", err)
	}

	cm.cnf.Store(cnf)
}

func (cm *ConfigManager) Get() *Config {
	return cm.cnf.Load()
}

func (cm *ConfigManager) Update(newCnf *Config) {

	oldCnf := cm.cnf.Swap(newCnf)

	if oldCnf.LogLevel != newCnf.LogLevel {
		cm.notify("log.level", newCnf.LogLevel)
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

	cnf := cm.cnf.Load()
	cnf.LogLevel = cm.kn.String("log.level")
	
	cm.Update(cnf)
}

func setDefault() *Config {
	return &Config{
		Port: 8080,
		LogLevel: "info",
	}
}