package content

import (
	"database/sql"
	"time"
)

// AppContent represents content stored in the app_contents table
type AppContent struct {
	ID            int64          `db:"id" json:"-"`
	ContentKey    string         `db:"content_key" json:"-"`
	ContentHTML   string         `db:"content_html" json:"content"`
	Version       int            `db:"version" json:"version"`
	UpdatedBy     sql.NullInt64  `db:"updated_by" json:"-"`
	UpdatedByName sql.NullString `db:"updated_by_name" json:"-"`
	CreatedAt     time.Time      `db:"created_at" json:"-"`
	UpdatedAt     time.Time      `db:"updated_at" json:"updated_at"`
}

// ContentResponse represents the public content response
type ContentResponse struct {
	Content   string    `json:"content"`
	Version   int       `json:"version"`
	UpdatedAt time.Time `json:"updated_at"`
}

// UpdateContentRequest represents the request to update content
type UpdateContentRequest struct {
	Content string `json:"content"`
}

// Valid content keys
const (
	ContentKeyTerms   = "terms"
	ContentKeyPrivacy = "privacy"
)

// ValidContentKeys is a map of valid content keys for validation
var ValidContentKeys = map[string]bool{
	ContentKeyTerms:   true,
	ContentKeyPrivacy: true,
}
