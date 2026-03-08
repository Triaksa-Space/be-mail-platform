-- +goose Up
-- +goose StatementBegin
ALTER TABLE refresh_tokens ADD COLUMN grace_until TIMESTAMP NULL DEFAULT NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE refresh_tokens DROP COLUMN grace_until;
-- +goose StatementEnd
