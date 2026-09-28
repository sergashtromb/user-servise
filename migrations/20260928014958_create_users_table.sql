-- +goose Up
CREATE TABLE users (
	id 			UUID PRIMARY KEY DEFAULT uuidv7(),
	username 	TEXT NOT NULL,
	pass 		TEXT NOT NULL,
	email 		TEXT,
	phone 		TEXT,
	created_at 	TIMESTAMPZ DEFAULT NOW(),
	is_deleted 	BOOL NOT NULL
);

CREATE UNIQUE INDEX CONCURRENTLY users_username_idx ON users (username);

CREATE UNIQUE INDEX CONCURRENTLY users_email_idx ON users (email)
	WHERE email IS NOT NULL;

CREATE UNIQUE INDEX CONCURRENTLY users_phone_idx ON users (phone)
	WHERE phone IS NOT NULL;

-- +goose Down
DROP TABLE IF EXISTS users;
