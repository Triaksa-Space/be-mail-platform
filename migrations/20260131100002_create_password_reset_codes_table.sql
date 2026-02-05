-- +goose Up
-- +goose StatementBegin
CREATE TABLE password_reset_codes (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT NOT NULL,
    code_hash VARCHAR(64) NOT NULL,
    binding_email VARCHAR(255) NOT NULL,
    expires_at DATETIME NOT NULL,
    failed_attempts INT NOT NULL DEFAULT 0,
    blocked_until DATETIME NULL,
    verified_at DATETIME NULL,
    used_at DATETIME NULL,
    reset_token VARCHAR(64) NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    INDEX idx_prc_user_id (user_id),
    INDEX idx_prc_expires (expires_at),
    INDEX idx_prc_reset_token (reset_token),
    CONSTRAINT fk_prc_user FOREIGN KEY (user_id)
        REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE users ADD COLUMN binding_email VARCHAR(255) NULL AFTER email;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE users DROP COLUMN binding_email;
-- +goose StatementEnd

-- +goose StatementBegin
DROP TABLE IF EXISTS password_reset_codes;
-- +goose StatementEnd
