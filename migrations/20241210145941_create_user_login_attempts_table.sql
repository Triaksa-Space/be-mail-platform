-- +goose Up
-- +goose StatementBegin
CREATE TABLE user_login_attempts (
    username VARCHAR(255) PRIMARY KEY,
    failed_attempts INT DEFAULT 0,
    last_attempt_time TIMESTAMP,
    blocked_until TIMESTAMP NULL
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS user_login_attempts;
-- +goose StatementEnd
