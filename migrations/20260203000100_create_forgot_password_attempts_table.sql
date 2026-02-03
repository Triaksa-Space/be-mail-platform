-- +goose Up
-- +goose StatementBegin
CREATE TABLE forgot_password_attempts (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    failed_attempts INT NOT NULL DEFAULT 0,
    blocked_until DATETIME NULL,
    last_attempt_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    UNIQUE INDEX uq_fpa_email (email),
    INDEX idx_fpa_blocked_until (blocked_until)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS forgot_password_attempts;
-- +goose StatementEnd
