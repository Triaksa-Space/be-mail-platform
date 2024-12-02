-- +goose Up
-- +goose StatementBegin
CREATE TABLE emails (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT NOT NULL,
    sender_email VARCHAR(255) NOT NULL,
    sender_name VARCHAR(255) NOT NULL,
    subject VARCHAR(255),
    preview VARCHAR(255),
    body LONGBLOB,
    body_eml LONGBLOB,
    attachments VARCHAR(255) NULL,
    timestamp DATETIME NOT NULL,
    email_type VARCHAR(255) NOT NULL,
    message_id VARCHAR(255) NULL,
    created_by BIGINT NOT NULL DEFAULT 0,
    updated_by BIGINT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS emails;
-- +goose StatementEnd
