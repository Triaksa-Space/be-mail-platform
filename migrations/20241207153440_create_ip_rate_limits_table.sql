-- +goose Up
-- +goose StatementBegin
CREATE TABLE ip_rate_limits (
    ip_address VARCHAR(45) PRIMARY KEY, -- Supports IPv6
    request_count INT NOT NULL DEFAULT 0,
    first_request_time DATETIME NOT NULL,
    blocked_until DATETIME NULL,
    last_request_time DATETIME NOT NULL,
    INDEX (blocked_until)
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS ip_rate_limits;
-- +goose StatementEnd
