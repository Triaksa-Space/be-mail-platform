package admin

import (
	"database/sql"
	"time"
)

// DashboardCounter represents a counter in the dashboard_counters table
type DashboardCounter struct {
	ID           int64     `db:"id"`
	CounterKey   string    `db:"counter_key"`
	CounterValue int64     `db:"counter_value"`
	UpdatedAt    time.Time `db:"updated_at"`
}

// OverviewResponse represents the admin dashboard overview
type OverviewResponse struct {
	Stats       OverviewStats        `json:"stats"`
	Inbox       []OverviewInboxEmail `json:"inbox"`
	Sent        []OverviewSentEmail  `json:"sent"`
	GeneratedAt time.Time            `json:"generated_at"`
}

// OverviewStats contains dashboard statistics
type OverviewStats struct {
	TotalUsersMailria int64 `json:"total_users_mailria"`
	TotalUsersMailsaja int64 `json:"total_users_mailsaja"`
	TotalInbox        int64 `json:"total_inbox"`
	TotalSent         int64 `json:"total_sent"`
}

// OverviewInboxEmail represents an inbox email in overview
type OverviewInboxEmail struct {
	ID             string    `json:"id"`
	UserID         string    `json:"user_id"`
	UserEmail      string    `json:"user_email"`
	From           string    `json:"from"`
	FromName       string    `json:"from_name"`
	Subject        string    `json:"subject"`
	Preview        string    `json:"preview"`
	Body           string    `json:"body"`
	IsRead         bool      `json:"is_read"`
	HasAttachments bool      `json:"has_attachments"`
	ReceivedAt     time.Time `json:"received_at"`
}

// OverviewSentEmail represents a sent email in overview
type OverviewSentEmail struct {
	ID          string     `json:"id"`
	UserID      string     `json:"user_id"`
	UserEmail   string     `json:"user_email"`
	From        string     `json:"from"`
	To          string     `json:"to"`
	Subject     string     `json:"subject"`
	Preview     string     `json:"preview"`
	Body        string     `json:"body"`
	IsRead      bool       `json:"is_read"`
	Status      string     `json:"status"`
	SentAt      *time.Time `json:"sent_at"`
}

// Legacy types for backward compatibility (can be removed if not used elsewhere)
type UsersOverview struct {
	Total    int64            `json:"total"`
	ByDomain map[string]int64 `json:"by_domain"`
}

type EmailsOverview struct {
	TotalInbox int64 `json:"total_inbox"`
	TotalSent  int64 `json:"total_sent"`
}

type RecentOverview struct {
	Inbox []RecentInboxEmail `json:"inbox"`
	Sent  []RecentSentEmail  `json:"sent"`
}

type RecentInboxEmail struct {
	ID         string    `json:"id"`
	UserEmail  string    `json:"user_email"`
	From       string    `json:"from"`
	Subject    string    `json:"subject"`
	ReceivedAt time.Time `json:"received_at"`
}

type RecentSentEmail struct {
	ID        string    `json:"id"`
	UserEmail string    `json:"user_email"`
	To        string    `json:"to"`
	Subject   string    `json:"subject"`
	SentAt    time.Time `json:"sent_at"`
}

// AdminInboxEmail represents an email in the admin inbox view
type AdminInboxEmail struct {
	ID             int64          `db:"id"`
	UserID         int64          `db:"user_id"`
	UserEmail      string         `db:"user_email"`
	SenderEmail    string         `db:"sender_email"`
	SenderName     string         `db:"sender_name"`
	Subject        sql.NullString `db:"subject"`
	Preview        sql.NullString `db:"preview"`
	IsRead         bool           `db:"is_read"`
	HasAttachments bool           `db:"has_attachments"`
	Timestamp      time.Time      `db:"timestamp"`
}

// AdminInboxResponse represents the admin inbox list response
type AdminInboxResponse struct {
	Data       []AdminInboxEmailResponse `json:"data"`
	Pagination PaginationResponse        `json:"pagination"`
}

// AdminInboxEmailResponse represents an email in the response
type AdminInboxEmailResponse struct {
	ID             string    `json:"id"`
	UserID         string    `json:"user_id"`
	UserEmail      string    `json:"user_email"`
	From           string    `json:"from"`
	FromName       string    `json:"from_name"`
	Subject        string    `json:"subject"`
	Preview        string    `json:"preview"`
	IsRead         bool      `json:"is_read"`
	HasAttachments bool      `json:"has_attachments"`
	ReceivedAt     time.Time `json:"received_at"`
}

// AdminSentEmail represents a sent email in the admin view
type AdminSentEmail struct {
	ID          int64          `db:"id"`
	UserID      int64          `db:"user_id"`
	UserEmail   string         `db:"user_email"`
	FromEmail   string         `db:"from_email"`
	ToEmail     string         `db:"to_email"`
	Subject     string         `db:"subject"`
	BodyPreview sql.NullString `db:"body_preview"`
	IsRead      bool           `db:"is_read"`
	Status      string         `db:"status"`
	Provider    sql.NullString `db:"provider"`
	SentAt      sql.NullTime   `db:"sent_at"`
	CreatedAt   time.Time      `db:"created_at"`
}

// AdminSentResponse represents the admin sent list response
type AdminSentResponse struct {
	Data       []AdminSentEmailResponse `json:"data"`
	Pagination PaginationResponse       `json:"pagination"`
}

// AdminSentEmailResponse represents a sent email in the response
type AdminSentEmailResponse struct {
	ID          string     `json:"id"`
	UserID      string     `json:"user_id"`
	UserEmail   string     `json:"user_email"`
	From        string     `json:"from"`
	To          string     `json:"to"`
	Subject     string     `json:"subject"`
	BodyPreview string     `json:"body_preview"`
	IsRead      bool       `json:"is_read"`
	Status      string     `json:"status"`
	Provider    string     `json:"provider"`
	SentAt      *time.Time `json:"sent_at"`
}

// PaginationResponse represents pagination info
type PaginationResponse struct {
	Page       int `json:"page"`
	Limit      int `json:"limit"`
	Total      int `json:"total"`
	TotalPages int `json:"total_pages"`
}

// AdminMenu represents a menu item
type AdminMenu struct {
	ID        int64          `db:"id" json:"-"`
	MenuKey   string         `db:"menu_key" json:"key"`
	MenuName  string         `db:"menu_name" json:"name"`
	ParentID  sql.NullInt64  `db:"parent_id" json:"-"`
	SortOrder int            `db:"sort_order" json:"-"`
	Icon      sql.NullString `db:"icon" json:"icon"`
	Route     sql.NullString `db:"route" json:"route"`
	CreatedAt time.Time      `db:"created_at" json:"-"`
}

// MenuResponse represents a menu item in the response
type MenuResponse struct {
	Key   string `json:"key"`
	Name  string `json:"name"`
	Route string `json:"route"`
	Icon  string `json:"icon"`
}

// RolePermission represents a role's permission on a menu
type RolePermission struct {
	RoleID    int    `db:"role_id" json:"role_id"`
	MenuID    int64  `db:"menu_id" json:"-"`
	MenuKey   string `db:"menu_key" json:"menu_key"`
	CanView   bool   `db:"can_view" json:"can_view"`
	CanCreate bool   `db:"can_create" json:"can_create"`
	CanEdit   bool   `db:"can_edit" json:"can_edit"`
	CanDelete bool   `db:"can_delete" json:"can_delete"`
}

// RolePermissionsResponse represents permissions for a role
type RolePermissionsResponse struct {
	RoleID   int      `json:"role_id"`
	RoleName string   `json:"role_name"`
	Menus    []string `json:"menus"`
}

// UpdatePermissionsRequest represents the request to update permissions
type UpdatePermissionsRequest struct {
	Permissions []PermissionUpdate `json:"permissions"`
}

// PermissionUpdate represents a single permission update
type PermissionUpdate struct {
	MenuKey   string `json:"menu_key"`
	CanView   bool   `json:"can_view"`
	CanCreate bool   `json:"can_create"`
	CanEdit   bool   `json:"can_edit"`
	CanDelete bool   `json:"can_delete"`
}

// Role name mapping
var RoleNames = map[int]string{
	1: "User",
	2: "Admin",
}
