-- +goose Up
-- +goose StatementBegin
CREATE TABLE admin_permissions (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT NOT NULL,
    permission_key VARCHAR(50) NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    UNIQUE KEY uk_user_permission (user_id, permission_key),
    INDEX idx_admin_perm_user (user_id),
    CONSTRAINT fk_admin_perm_user FOREIGN KEY (user_id)
        REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
-- +goose StatementEnd

-- Seed default permissions for existing admins (role_id = 2)
-- +goose StatementBegin
INSERT INTO admin_permissions (user_id, permission_key)
SELECT u.id, p.permission_key
FROM users u
CROSS JOIN (
    SELECT 'overview' AS permission_key
    UNION SELECT 'user_list'
    UNION SELECT 'create_single'
    UNION SELECT 'create_bulk'
    UNION SELECT 'all_inbox'
    UNION SELECT 'all_sent'
    UNION SELECT 'terms_of_services'
    UNION SELECT 'privacy_policy'
) p
WHERE u.role_id = 2;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS admin_permissions;
-- +goose StatementEnd
