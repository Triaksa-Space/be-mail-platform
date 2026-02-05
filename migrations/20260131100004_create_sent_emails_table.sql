-- +goose Up
-- +goose StatementBegin
CREATE TABLE sent_emails (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT NOT NULL,
    from_email VARCHAR(255) NOT NULL,
    to_email VARCHAR(255) NOT NULL,
    subject VARCHAR(500) NOT NULL,
    body_preview VARCHAR(500) NULL,
    body LONGTEXT NOT NULL,
    attachments LONGTEXT NULL,
    provider VARCHAR(50) NULL,
    provider_message_id VARCHAR(255) NULL,
    status ENUM('queued', 'sent', 'delivered', 'failed', 'bounced') DEFAULT 'queued',
    error_message TEXT NULL,
    sent_at DATETIME NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    INDEX idx_sent_emails_user_id (user_id),
    INDEX idx_sent_emails_from (from_email),
    INDEX idx_sent_emails_to (to_email),
    INDEX idx_sent_emails_sent_at (sent_at),
    INDEX idx_sent_emails_status (status),
    INDEX idx_sent_emails_admin (sent_at, user_id, status),
    FULLTEXT INDEX ft_sent_subject (subject),

    CONSTRAINT fk_sent_emails_user FOREIGN KEY (user_id)
        REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS sent_emails;
-- +goose StatementEnd
