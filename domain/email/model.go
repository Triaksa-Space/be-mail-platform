package email

import "time"

type Email struct {
	ID        int64  `db:"id"`
	UserID    int64  `db:"user_id"`
	Sender    string `db:"sender"`
	Subject   string `db:"subject"`
	Preview   string `db:"preview"`
	Body      string `db:"body"`
	EmailType string `db:"email_type"`
	// Attachments string    `db:"attachments"` // JSON format
	Timestamp time.Time `db:"timestamp"`
	CreatedAt time.Time `db:"created_at"`
	UpdatedAt time.Time `db:"updated_at"`
}

type SendEmailRequest struct {
	UserID      int      `json:"user_id"`
	To          string   `json:"to" validate:"required,email"`
	Subject     string   `json:"subject"`
	Body        string   `json:"body"`
	Attachments []string `json:"attachments"`
}

// Convert timestamps to relative time
type EmailResponse struct {
	Email
	RelativeTime string `json:"RelativeTime"`
}
