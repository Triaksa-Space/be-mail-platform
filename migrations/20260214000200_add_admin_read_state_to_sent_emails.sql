-- +goose Up
-- +goose StatementBegin
ALTER TABLE sent_emails
ADD COLUMN is_read_admin BOOLEAN NOT NULL DEFAULT FALSE;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE INDEX idx_sent_emails_admin_read_timestamp ON sent_emails (is_read_admin, sent_at);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX idx_sent_emails_admin_read_timestamp ON sent_emails;
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE sent_emails
DROP COLUMN is_read_admin;
-- +goose StatementEnd
