-- +goose Up
-- Step 1: Insert all 9 permissions for role_id=0 users (skip if already exists)
-- +goose StatementBegin
INSERT INTO admin_permissions (user_id, permission_key, created_at)
SELECT u.id, p.permission_key, NOW()
FROM users u
CROSS JOIN (
    SELECT 'overview'          AS permission_key
    UNION SELECT 'user_list'
    UNION SELECT 'create_single'
    UNION SELECT 'create_bulk'
    UNION SELECT 'all_inbox'
    UNION SELECT 'all_sent'
    UNION SELECT 'terms_of_services'
    UNION SELECT 'privacy_policy'
    UNION SELECT 'roles_permissions'
) p
WHERE u.role_id = 0
  AND NOT EXISTS (
    SELECT 1 FROM admin_permissions ap
    WHERE ap.user_id = u.id AND ap.permission_key = p.permission_key
  );
-- +goose StatementEnd

-- Step 2: Convert role_id=0 users to role_id=2
-- +goose StatementBegin
UPDATE users SET role_id = 2 WHERE role_id = 0;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
SELECT 1;
-- +goose StatementEnd
