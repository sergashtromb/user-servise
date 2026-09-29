package postgres

import (
	"context"
	"log/slog"
	"sync"
	"time"
	"user_service/domain"
)

type AuditService struct {
	queue 		chan *domain.AuditEvent
	batch 		[]*domain.AuditEvent
	maxSize 	int
	timeToSend 	time.Duration
	db 			*DataBase
	on 			sync.Once
}

func NewAuditService(db *DataBase, ms int, tts time.Duration) *AuditService {
	return &AuditService{
		queue: make(chan *domain.AuditEvent),
		batch: make([]*domain.AuditEvent, 0, ms),
		maxSize: ms,
		timeToSend: tts,
		db: db,
	}
}

func (as *AuditService) Log(ctx context.Context, event *domain.AuditEvent) {
	go func() {
		select {
		case <- ctx.Done():
			as.closeChanel()
			return
		case as.queue <- event:
			return
		}
	}()
}

func (as *AuditService) closeChanel() {
	as.on.Do(func() {
		close(as.queue)
	})
}

func (as *AuditService) logWorker(ctx context.Context) {

	ticker := time.NewTicker(as.timeToSend)
	defer ticker.Stop()

	for {
		select {
		case val, ok := <- as.queue:

			if !ok {
				if err := as.writeBatch(); err != nil {
					slog.Error("Failed butching logs in db", "err", err)
				}	
				return
			}

			as.batch = append(as.batch, val)

			if len(as.batch) == as.maxSize {

				if err := as.writeBatch(); err != nil {
					slog.Error("Failed butching logs in db", "err", err)
				}	

				as.batch = as.batch[:0]

				ticker.Reset(as.timeToSend)
			}

		case <- ticker.C:
			if err := as.writeBatch(); err != nil {
				slog.Error("Failed butching logs in db", "err", err)
			}
		case <-ctx.Done():
			if err := as.writeBatch(); err != nil {
				slog.Error("Failed butching logs in db", "err", err)
			}
			return
		}
	}
}

func (as *AuditService) writeBatch() error {
	return nil
}