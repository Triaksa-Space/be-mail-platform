-- +goose Up
-- +goose StatementBegin
CREATE TABLE incoming_emails (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    email_date DATETIME NOT NULL,
    message_id VARCHAR(255) NOT NULL UNIQUE,
    email_send_to VARCHAR(255) NOT NULL,
    email_data LONGBLOB NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    processed BOOLEAN NOT NULL DEFAULT FALSE,
    processed_at DATETIME NULL
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS incoming_emails;
-- +goose StatementEnd