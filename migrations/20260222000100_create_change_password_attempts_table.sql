-- +goose Up
-- +goose StatementBegin
CREATE TABLE change_password_attempts (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT NOT NULL,
    failed_attempts INT NOT NULL DEFAULT 0,
    blocked_until DATETIME NULL,
    last_attempt_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    UNIQUE INDEX uq_cpa_user_id (user_id),
    INDEX idx_cpa_blocked_until (blocked_until),
    CONSTRAINT fk_cpa_user FOREIGN KEY (user_id)
        REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS change_password_attempts;
-- +goose StatementEnd
