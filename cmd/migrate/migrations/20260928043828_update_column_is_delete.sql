-- +goose Up
ALTER TABLE users
ALTER COLUMN is_deleted SET DEFAULT FALSE;

-- +goose Down
SELECT 'down SQL query';
