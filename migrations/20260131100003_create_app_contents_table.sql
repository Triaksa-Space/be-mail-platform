-- +goose Up
-- +goose StatementBegin
CREATE TABLE app_contents (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    content_key VARCHAR(50) NOT NULL UNIQUE,
    content_html LONGTEXT NOT NULL,
    version INT NOT NULL DEFAULT 1,
    updated_by BIGINT NULL,
    updated_by_name VARCHAR(255) NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    INDEX idx_app_contents_key (content_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
-- +goose StatementEnd

-- +goose StatementBegin
INSERT INTO app_contents (content_key, content_html, version) VALUES
('terms', '<h1>Terms of Service</h1><p>Content here...</p>', 1),
('privacy', '<h1>Privacy Policy</h1><p>Content here...</p>', 1);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS app_contents;
-- +goose StatementEnd
