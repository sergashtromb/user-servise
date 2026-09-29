-- +goose Up
CREATE TABLE audit (
	id UUID PRIMARY KEY DEFAULT uuidv7(),
	event_time TIMESTAMP NOT NULL DEFAULT NOW(),
	type TEXT NOT NULL,
	place TEXT NOT NULL,
	entity_id TEXT,
	success BOOL NOT NULL,
	error TEXT,
	old_data JSONB,
	new_data JSONB,
	metadata JSONB
);

-- +goose NO TRANSACTION
CREATE INDEX CONCURRENTLY audit_timestap_idx ON audit(event_time DESC);

-- +goose NO TRANSACTION
CREATE INDEX CONCURRENTLY audit_type_idx ON audit(type);

-- +goose NO TRANSACTION
CREATE INDEX CONCURRENTLY audit_place_idx ON audit(place);

-- +goose NO TRANSACTION
CREATE INDEX CONCURRENTLY audit_entity_id_idx ON audit(entity_id);

-- +goose Down

-- +goose NO TRANSACTION
DROP INDEX CONCURRENTLY audit_timestap_idx;
-- +goose NO TRANSACTION
DROP INDEX CONCURRENTLY audit_type_idx;
-- +goose NO TRANSACTION
DROP INDEX CONCURRENTLY audit_place_idx;
-- +goose NO TRANSACTION
DROP INDEX CONCURRENTLY audit_entity_id_idx;

DROP TABLE audit;
