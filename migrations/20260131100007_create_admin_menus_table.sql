-- +goose Up
-- +goose StatementBegin
CREATE TABLE admin_menus (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    menu_key VARCHAR(50) NOT NULL UNIQUE,
    menu_name VARCHAR(100) NOT NULL,
    parent_id BIGINT NULL,
    sort_order INT NOT NULL DEFAULT 0,
    icon VARCHAR(50) NULL,
    route VARCHAR(100) NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    INDEX idx_admin_menus_parent (parent_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE menu_api_permissions (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    menu_id BIGINT NOT NULL,
    http_method VARCHAR(10) NOT NULL,
    api_pattern VARCHAR(200) NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    INDEX idx_map_menu (menu_id),
    INDEX idx_map_pattern (api_pattern),
    CONSTRAINT fk_map_menu FOREIGN KEY (menu_id)
        REFERENCES admin_menus(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE role_menu_permissions (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    role_id INT NOT NULL,
    menu_id BIGINT NOT NULL,
    can_view BOOLEAN NOT NULL DEFAULT TRUE,
    can_create BOOLEAN NOT NULL DEFAULT FALSE,
    can_edit BOOLEAN NOT NULL DEFAULT FALSE,
    can_delete BOOLEAN NOT NULL DEFAULT FALSE,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    UNIQUE KEY uk_role_menu (role_id, menu_id),
    INDEX idx_rmp_role (role_id),
    CONSTRAINT fk_rmp_menu FOREIGN KEY (menu_id)
        REFERENCES admin_menus(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
-- +goose StatementEnd

-- Seed menus
-- +goose StatementBegin
INSERT INTO admin_menus (menu_key, menu_name, sort_order, route, icon) VALUES
('dashboard', 'Dashboard', 1, '/admin/dashboard', 'dashboard'),
('users', 'User Management', 2, '/admin/users', 'users'),
('emails', 'Email Management', 3, '/admin/emails', 'mail'),
('domains', 'Domain Management', 4, '/admin/domains', 'globe'),
('settings', 'Settings', 5, '/admin/settings', 'settings'),
('content', 'Content Management', 6, '/admin/content', 'file-text');
-- +goose StatementEnd

-- Map menus to API endpoints
-- +goose StatementBegin
INSERT INTO menu_api_permissions (menu_id, http_method, api_pattern) VALUES
((SELECT id FROM admin_menus WHERE menu_key = 'dashboard'), 'GET', '/admin/overview'),
((SELECT id FROM admin_menus WHERE menu_key = 'users'), 'GET', '/user'),
((SELECT id FROM admin_menus WHERE menu_key = 'users'), 'GET', '/user/:id'),
((SELECT id FROM admin_menus WHERE menu_key = 'users'), 'POST', '/user'),
((SELECT id FROM admin_menus WHERE menu_key = 'users'), 'POST', '/user/bulk/v2'),
((SELECT id FROM admin_menus WHERE menu_key = 'users'), 'DELETE', '/user/:id'),
((SELECT id FROM admin_menus WHERE menu_key = 'emails'), 'GET', '/admin/inbox'),
((SELECT id FROM admin_menus WHERE menu_key = 'emails'), 'GET', '/admin/sent'),
((SELECT id FROM admin_menus WHERE menu_key = 'domains'), 'GET', '/domain'),
((SELECT id FROM admin_menus WHERE menu_key = 'domains'), 'POST', '/domain'),
((SELECT id FROM admin_menus WHERE menu_key = 'domains'), 'DELETE', '/domain/:id'),
((SELECT id FROM admin_menus WHERE menu_key = 'content'), 'PUT', '/admin/content/:key');
-- +goose StatementEnd

-- Default permissions for SuperAdmin (0) - full CRUD access
-- +goose StatementBegin
INSERT INTO role_menu_permissions (role_id, menu_id, can_view, can_create, can_edit, can_delete)
SELECT 0, id, TRUE, TRUE, TRUE, TRUE FROM admin_menus;
-- +goose StatementEnd

-- Default permissions for Admin (2) - limited access
-- +goose StatementBegin
INSERT INTO role_menu_permissions (role_id, menu_id, can_view, can_create, can_edit, can_delete)
SELECT 2, id, TRUE, TRUE, TRUE, FALSE FROM admin_menus WHERE menu_key IN ('dashboard', 'users', 'emails', 'content');
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS role_menu_permissions;
-- +goose StatementEnd

-- +goose StatementBegin
DROP TABLE IF EXISTS menu_api_permissions;
-- +goose StatementEnd

-- +goose StatementBegin
DROP TABLE IF EXISTS admin_menus;
-- +goose StatementEnd
