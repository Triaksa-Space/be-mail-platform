-- +goose Up
-- +goose StatementBegin
CREATE TABLE domains (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    domain VARCHAR(255) NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS domains;
-- +goose StatementEnd
