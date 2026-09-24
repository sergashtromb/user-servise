package config

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
)

type ChangeSettingsHandler struct {
	cm *ConfigManager
}

// POST admin/config json body {"key":"data"}
func (csh *ChangeSettingsHandler) CheckChangeSettings(w http.ResponseWriter, r *http.Request) {

	set := make(map[string]any)
	if err := json.NewDecoder(r.Body).Decode(&set); err != nil {
		slog.Warn("Failed change config in server", "err", err)
		http.Error(w, "failed convert body to json", http.StatusBadRequest)
		return
	}

	cnf := csh.cm.Get()

	for key, value := range set {
		switch key {
		case "log.level":
			cnf.LogLevel = value.(string)
		default:
			slog.Warn("Error changing settings via HTTP: unknown key", "key", key)
			http.Error(w, fmt.Sprintf("Error changing settings via HTTP: unknown key key=%v", key), http.StatusBadRequest)
			return
		}
	}

	csh.cm.Update(cnf)
}