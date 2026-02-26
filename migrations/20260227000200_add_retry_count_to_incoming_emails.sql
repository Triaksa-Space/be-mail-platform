-- +goose Up
-- +goose StatementBegin
ALTER TABLE incoming_emails ADD COLUMN retry_count INT NOT NULL DEFAULT 0 AFTER processed;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE incoming_emails DROP COLUMN retry_count;
-- +goose StatementEnd
