-- +goose Up
-- +goose StatementBegin
CREATE INDEX idx_emails_created_at ON emails (created_at);
-- +goose StatementEnd
-- +goose StatementBegin
CREATE INDEX idx_sent_emails_created_at ON sent_emails (created_at);
-- +goose StatementEnd
-- +goose StatementBegin
CREATE INDEX idx_incoming_emails_created_at ON incoming_emails (created_at);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX idx_emails_created_at ON emails;
-- +goose StatementEnd
-- +goose StatementBegin
DROP INDEX idx_sent_emails_created_at ON sent_emails;
-- +goose StatementEnd
-- +goose StatementBegin
DROP INDEX idx_incoming_emails_created_at ON incoming_emails;
-- +goose StatementEnd
