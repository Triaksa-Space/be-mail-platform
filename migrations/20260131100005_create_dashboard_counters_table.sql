-- +goose Up
-- +goose StatementBegin
CREATE TABLE dashboard_counters (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    counter_key VARCHAR(100) NOT NULL UNIQUE,
    counter_value BIGINT NOT NULL DEFAULT 0,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    INDEX idx_counters_key (counter_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
-- +goose StatementEnd

-- +goose StatementBegin
INSERT INTO dashboard_counters (counter_key, counter_value) VALUES
('total_users', 0),
('total_inbox', 0),
('total_sent', 0);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS dashboard_counters;
-- +goose StatementEnd
