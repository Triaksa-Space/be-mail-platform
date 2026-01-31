-- +goose Up
-- +goose StatementBegin
CREATE TABLE system_settings (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    setting_key VARCHAR(100) NOT NULL UNIQUE,
    setting_value TEXT NOT NULL,
    setting_type ENUM('string', 'int', 'bool', 'json') DEFAULT 'string',
    description VARCHAR(500) NULL,
    updated_by BIGINT NULL,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    INDEX idx_settings_key (setting_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
-- +goose StatementEnd

-- +goose StatementBegin
INSERT INTO system_settings (setting_key, setting_value, setting_type, description) VALUES
('password_min_length', '8', 'int', 'Minimum password length for bulk creation'),
('password_max_length', '32', 'int', 'Maximum password length for bulk creation'),
('password_require_special', 'false', 'bool', 'Require special characters in generated passwords');
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS system_settings;
-- +goose StatementEnd
