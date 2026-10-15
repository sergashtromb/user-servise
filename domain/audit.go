package domain

import (
	"context"
	"time"
)

type EventType string

const (
	EventCreatedUser EventType = "user_created"
	EventDeletedUser EventType = "user_deleted"
	EventUpdateUser  EventType = "user_update"
	EventGetUser     EventType = "user_getted"

	EventSendUserIntoCacheFailed  EventType = "user_send_into_cache_failed"
	EventSendUserIntoCacheSuccess EventType = "user_send_into_cache_success"
	EventGetUserIntoCacheFailed   EventType = "user_get_into_cache_failed"
	EventGetUserIntoCacheSuccess  EventType = "user_get_into_cache_success"

	EventRegistrationSessionUserSuccess EventType = "registration_user_session_success"
	EventRegistrationSessionUserFailed  EventType = "registration_user_session_failed"
	EventGetSessionUserSuccess          EventType = "get_user_session_success"
	EventGetSessionUserFailed           EventType = "get_user_session_failed"
	EventDeleteSessionSuccess           EventType = "del_session_success"
	EventDeleteSessionFailed            EventType = "del_session_failed"
	EventUpdateRefreshTokenSuccess      EventType = "update_refresh_token_success"
	EventUpdateRefreshTokenFailed       EventType = "update_refresh_token_failed"

	EventLoginSucces EventType = "login_succes"
	EventLoginFailed EventType = "login_failed"

	EventInboxRequestStart EventType = "inbox_request_start"
	EventInboxRequestEnd   EventType = "inbox_request_end"
)

type EventPlace string

const (
	EventPlaceStore      EventPlace = "STORE"
	EventPlaceHandler    EventPlace = "HANDLER"
	EventPlaceMiddleware EventPlace = "MIDDLEWARE"
	EventPlaceSystem     EventPlace = "SYSTEM"
	EventPlaceRedis      EventPlace = "REDIS"
)

type AuditEvent struct {
	// general params
	Type      EventType
	Place     EventPlace
	Success   bool
	Error     *string
	EntityId  string
	Timestamp time.Time
	TraceId   string

	// for store
	OldData any
	NewData any

	Metadata map[string]any
}

type AuditService interface {
	Log(ctx context.Context, event *AuditEvent) error
}

func NewAuditEvent(tp EventType, place EventPlace, succ bool, err *string, entId string, traceId string) *AuditEvent {
	return &AuditEvent{
		Type:      tp,
		Place:     place,
		Success:   succ,
		Error:     err,
		EntityId:  entId,
		Timestamp: time.Now(),
		TraceId:   traceId,
	}
}

func NewSuccessEvent(tp EventType, place EventPlace, entId string, traceId string) *AuditEvent {
	return NewAuditEvent(tp, place, true, nil, entId, traceId)
}

func NewFailedEvent(tp EventType, place EventPlace, err *string, entId string, traceId string) *AuditEvent {
	return NewAuditEvent(tp, place, false, err, entId, traceId)
}
