package email

import "time"

type Email struct {
	ID          int64     `db:"id"`
	UserID      int64     `db:"user_id"`
	SenderEmail string    `db:"sender_email"`
	SenderName  string    `db:"sender_name"`
	Subject     string    `db:"subject"`
	Preview     string    `db:"preview"`
	Body        string    `db:"body"`
	EmailType   string    `db:"email_type"`
	Attachments string    `db:"attachments"` // JSON format
	MessageID   string    `db:"message_id"`  // Message ID from email provider
	Timestamp   time.Time `db:"timestamp"`
	CreatedAt   time.Time `db:"created_at"`
	UpdatedAt   time.Time `db:"updated_at"`
}

type SendEmailRequest struct {
	UserID      int          `json:"user_id"`
	To          string       `json:"to" validate:"required,email"`
	Subject     string       `json:"subject"`
	Body        string       `json:"body"`
	Attachments []Attachment `json:"attachments"`
}

// Convert timestamps to relative time
type EmailResponse struct {
	Email
	ListAttachments []string `json:"ListAttachments"`
	RelativeTime    string   `json:"RelativeTime"`
}

type Attachment struct {
	Filename    string `json:"filename"`
	ContentType string `json:"content_type"`
	Size        int64  `json:"size"`
	Content     []byte `json:"content"` // Raw content, not included in JSON
}

type ParsedEmail struct {
	MessageID   string       `json:"message_id"`
	Subject     string       `json:"subject"`
	From        string       `json:"from"`
	To          string       `json:"to"`
	Date        time.Time    `json:"date"`
	Body        string       `json:"body"`      // HTML formatted body
	PlainText   string       `json:"plaintext"` // Original plain text
	Attachments []Attachment `json:"attachments"`
}

type SyncStats struct {
	TotalEmails   int `json:"total_emails"`
	NewEmails     int `json:"new_emails"`
	SkippedEmails int `json:"skipped_emails"`
	FailedEmails  int `json:"failed_emails"`
}
