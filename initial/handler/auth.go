package handler

import (
	"net/http"
	"user_service/config"
	"user_service/domain"
)

type AuthHandler struct {
	cm    *config.ConfigManager
	audit domain.AuditService
}

func (ah *AuthHandler) UpdateRefreshToken(w http.ResponseWriter, r *http.Request) {

}
