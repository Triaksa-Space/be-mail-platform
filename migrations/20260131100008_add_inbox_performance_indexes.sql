-- +goose Up
-- +goose StatementBegin
CREATE INDEX idx_emails_inbox_query ON emails (timestamp DESC, user_id, is_read);
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE emails ADD FULLTEXT INDEX ft_emails_search (sender_email, sender_name, subject);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE INDEX idx_emails_user_timestamp ON emails (user_id, timestamp DESC);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX idx_emails_inbox_query ON emails;
-- +goose StatementEnd

-- +goose StatementBegin
ALTER TABLE emails DROP INDEX ft_emails_search;
-- +goose StatementEnd

-- +goose StatementBegin
DROP INDEX idx_emails_user_timestamp ON emails;
-- +goose StatementEnd
