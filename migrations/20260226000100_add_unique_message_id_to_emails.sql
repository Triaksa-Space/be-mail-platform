-- +goose Up
-- +goose StatementBegin
-- Remove any existing duplicate (user_id, message_id) pairs before adding the constraint.
-- Keep the oldest row (lowest id) for each duplicate group.
DELETE e1
FROM emails e1
INNER JOIN emails e2
    ON e1.user_id = e2.user_id
    AND e1.message_id = e2.message_id
    AND e1.message_id IS NOT NULL
    AND e1.id > e2.id;

ALTER TABLE emails
    ADD UNIQUE KEY uq_emails_user_message (user_id, message_id);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE emails
    DROP INDEX uq_emails_user_message;
-- +goose StatementEnd
