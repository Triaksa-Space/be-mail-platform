-- +goose Up
ALTER TABLE users ADD COLUMN token_version BIGINT NOT NULL DEFAULT 0;

-- +goose Down
ALTER TABLE users DROP COLUMN token_version;
