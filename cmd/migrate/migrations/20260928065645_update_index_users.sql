-- +goose Up
DROP INDEX CONCURRENTLY users_username_idx;
DROP INDEX CONCURRENTLY users_email_idx;
DROP INDEX CONCURRENTLY users_phone_idx;

-- +goose NO TRANSACTION
CREATE UNIQUE INDEX CONCURRENTLY users_username_idx ON users (username)
	WHERE is_deleted = false;

-- +goose NO TRANSACTION
CREATE UNIQUE INDEX CONCURRENTLY users_email_idx ON users (email)
	WHERE email IS NOT NULL AND is_deleted = false;

-- +goose NO TRANSACTION
CREATE UNIQUE INDEX CONCURRENTLY users_phone_idx ON users (phone)
	WHERE phone IS NOT NULL AND is_deleted = false;

-- +goose Down
DROP INDEX CONCURRENTLY users_username_idx;
DROP INDEX CONCURRENTLY users_email_idx;
DROP INDEX CONCURRENTLY users_phone_idx;

-- +goose NO TRANSACTION
CREATE UNIQUE INDEX CONCURRENTLY users_username_idx ON users (username);

-- +goose NO TRANSACTION
CREATE UNIQUE INDEX CONCURRENTLY users_email_idx ON users (email)
	WHERE email IS NOT NULL;

-- +goose NO TRANSACTION
CREATE UNIQUE INDEX CONCURRENTLY users_phone_idx ON users (phone)
	WHERE phone IS NOT NULL;
