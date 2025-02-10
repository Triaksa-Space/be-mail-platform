-- +goose Up
-- +goose StatementBegin
ALTER TABLE users
ADD COLUMN failed_attempts INT DEFAULT 0,
ADD COLUMN last_failed_at TIMESTAMP NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE users
    DROP COLUMN failed_attempts,
    DROP COLUMN last_failed_at;
-- +goose StatementEnd
