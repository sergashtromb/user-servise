package postgres

import (
	"context"
	"errors"
	"log/slog"
	"sync"

	"time"
	"user_service/domain"

	"github.com/jackc/pgx/v5"
)

var (
	ErrAuditStopped = errors.New("Audit is stopped!")
)

type AuditService struct {
	queue 			chan *domain.AuditEvent
	batch 			[]*domain.AuditEvent
	maxSize 		int
	db 				*DataBase
	wgForProd 		sync.WaitGroup
	wg 				sync.WaitGroup
	rm 				sync.RWMutex
	closed 			bool
	timeToSend 		time.Duration
	timeToFinish 	time.Duration
	shutTrigger 	chan struct{}
}

func NewAuditService(db *DataBase, ms int, tts time.Duration, ttf time.Duration) *AuditService {
	return &AuditService{
		queue: 			make(chan *domain.AuditEvent, ms*2),
		batch: 			make([]*domain.AuditEvent, 0, ms*2),
		maxSize: 		ms,
		timeToSend: 	tts,
		timeToFinish: 	ttf,
		db: 			db,
		shutTrigger: 	make(chan struct{}, 1),
		closed: 		false,	
	}
}

func (as *AuditService) Init() {
	as.wg.Add(1)
	go func() {
		defer as.wg.Done()
		as.logWorker()
	}()
}

func (as *AuditService) Log(ctx context.Context, event *domain.AuditEvent) error {

	as.rm.RLock()
	if as.closed {
		as.rm.RUnlock()
		return ErrAuditStopped
	}
	as.wgForProd.Add(1)
	as.rm.RUnlock()

	select {
	case <- as.shutTrigger:
		as.wgForProd.Done()
		return ErrAuditStopped
	case <- ctx.Done():
		as.wgForProd.Done()
		return ctx.Err()
	case as.queue <- event:
		as.wgForProd.Done()
		return nil
	}
}

func (as *AuditService) Shutdown() {

	as.rm.Lock()
	as.closed = true
	as.rm.Unlock()

	close(as.shutTrigger)

	go func() {
		as.wgForProd.Wait()
		close(as.queue)
	}()

	as.wg.Wait()
}

func (as *AuditService) logWorker() {

	ticker := time.NewTicker(as.timeToSend)
	defer ticker.Stop()

	for {
		select {
		case val, ok := <- as.queue:

			if !ok {
				as.flush()	
				return
			}

			as.batch = append(as.batch, val)

			if len(as.batch) >= as.maxSize {

				as.flush()
				ticker.Reset(as.timeToSend)
			}

		case <- ticker.C:
			as.flush()
		}
	}
}

func (as *AuditService) flush() {

	if len(as.batch) == 0 {
		return
	}

	timeout, timeoutCl := context.WithTimeout(context.Background(), as.timeToFinish)
	defer timeoutCl()

	if err := as.writeBatch(timeout, as.batch); err != nil {
		slog.Error("Failed butching logs in db", "err", err, "lost", len(as.batch))
	}

	clear(as.batch)
	as.batch = as.batch[:0]
}

func (as *AuditService) writeBatch(ctx context.Context, batch []*domain.AuditEvent) error {

	pool := as.db.GetPool()

	_, err := pool.CopyFrom(ctx, 
		[]string{"audit"}, 
		[]string{"event_time", "type", "place", "entity_id",
			"success", "error", "old_data", "new_data", "metadata"},
			pgx.CopyFromSlice(len(batch), func(i int) ([]any, error) {
				return []any {
					batch[i].Timestamp,
					batch[i].Type,
					batch[i].Place,
					batch[i].EntityId,
					batch[i].Success,
					batch[i].Error,
					batch[i].OldData,
					batch[i].NewData,
					batch[i].Metadata,
				}, nil
			}))
			
	if err != nil {
		return err
	}
	return nil
}