-- +goose Up
-- +goose StatementBegin
ALTER TABLE users ADD COLUMN encrypted_password TEXT NULL AFTER password;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE users DROP COLUMN encrypted_password;
-- +goose StatementEnd
