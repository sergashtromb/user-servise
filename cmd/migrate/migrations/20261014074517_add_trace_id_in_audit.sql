-- +goose Up
ALTER TABLE audit
ADD trace_id TEXT;

-- +goose NO TRANSACTION
CREATE INDEX CONCURRENTLY trace_id_idx ON audit(trace_id) WHERE trace_id IS NOT NULL;


-- +goose Down

-- +goose NO TRANSACTION
DROP INDEX trace_id_idx;

ALTER TABLE audit
DROP COLUMN trace_id