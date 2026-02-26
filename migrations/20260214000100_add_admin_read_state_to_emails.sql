-- +goose Up
-- +goose StatementBegin
ALTER TABLE emails
ADD COLUMN is_read_admin BOOLEAN NOT NULL DEFAULT FALSE;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE INDEX idx_emails_admin_read_timestamp ON emails (is_read_admin, timestamp DESC);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX idx_emails_admin_read_timestamp ON emails;
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE emails
DROP COLUMN is_read_admin;
-- +goose StatementEnd
