package domain

import (
	"context"
	"time"
)

type EventType string

const (
	EventCreatedUser 	EventType = "user_created"
	EventDeletedUser 	EventType = "user_deleted"
	EventUpdateUser 	EventType = "user_update"
	EventGetUser 		EventType = "user_getted"

	EventLoginSucces 	EventType = "login_succes"
	EventLoginFailed 	EventType = "login_failed"
)

type EventPlace string

const (
	EventPlaceStore 	EventPlace = "STORE"
	EventPlaceHandler 	EventPlace = "HANDLER"
	EventPlaceSystem 	EventPlace = "SYSTEM"
)

type AuditEvent struct {
	// general params
	Type 		EventType
	Place 		EventPlace
	Success 	bool
	Error 		string
	EntityId 	string
	Timestamp 	time.Time

	// for store
	OldData 	any
	NewData 	any

	Metadata map[string]any
}

type AuditService interface {
	Log(ctx context.Context, event *AuditEvent)
}

func NewAuditEvent(tp EventType, place EventPlace, succ bool, err string, entId string) *AuditEvent {
	return &AuditEvent{
		Type: tp, 
		Place: place,
		Success: succ,
		Error: err,
		EntityId: entId,
	}
}