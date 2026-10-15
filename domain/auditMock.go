package domain

import (
	"context"
)

type MockAuditService struct {
	TableResult map[string][]AuditEvent
}

func (mas *MockAuditService) Log(ctx context.Context, event *AuditEvent) error {

	_, ok := mas.TableResult[event.TraceId]
	if !ok {
		mas.TableResult[event.TraceId] = make([]AuditEvent, 0)
	}

	mas.TableResult[event.TraceId] = append(mas.TableResult[event.TraceId], *event)
	return nil
}
func GetMockAuditService() AuditService {
	mock := MockAuditService{
		TableResult: make(map[string][]AuditEvent),
	}
	var au AuditService
	au = &mock
	return au
}
