package email

import "time"

type Email struct {
	EmailEncodeID string    `json:"email_encode_id"` // Email Encoded ID
	UserEncodeID  string    `json:"user_encode_id"`  // User Encoded ID
	ID            int64     `db:"id"`
	IsRead        bool      `db:"is_read"`
	UserID        int64     `db:"user_id"`
	SenderEmail   string    `db:"sender_email"`
	SenderName    string    `db:"sender_name"`
	Subject       string    `db:"subject"`
	Preview       string    `db:"preview"`
	Body          string    `db:"body"`
	BodyEml       string    `db:"body_eml"`
	EmailType     string    `db:"email_type"`
	Attachments   string    `db:"attachments"` // JSON format
	MessageID     string    `db:"message_id"`  // Message ID from email provider
	Timestamp     time.Time `db:"timestamp" json:"received_at"`
	CreatedBy     int64     `db:"created_by"`
	UpdatedBy     *int      `db:"updated_by"`
	CreatedAt     time.Time `db:"created_at" json:"created_at"`
	UpdatedAt     time.Time `db:"updated_at"`
}

type PEmail struct {
	ID             string         `json:"id"`
	From           []EmailAddress `json:"from"`
	To             []EmailAddress `json:"to"`
	Cc             []EmailAddress `json:"cc,omitempty"`
	Bcc            []EmailAddress `json:"bcc,omitempty"`
	Subject        string         `json:"subject"`
	Date           time.Time      `json:"date"`
	TextBody       string         `json:"text_body,omitempty"`
	HTMLBody       string         `json:"html_body,omitempty"`
	Attachments    string         `db:"attachments"`
	EmlAttachments []Attachment   `json:"attachments,omitempty"`
	Timestamp      time.Time      `db:"timestamp"`
}

type SendEmailRequest struct {
	UserID      int          `json:"user_id"`
	To          string       `json:"to" validate:"required,email"`
	Subject     string       `json:"subject"`
	Body        string       `json:"body"`
	Attachments []Attachment `json:"attachments"`
}

type DeleteAttachmentParam struct {
	URL []string `json:"url"`
}

type SendEmailRequestURLAttachment struct {
	To          string   `json:"to"`
	Subject     string   `json:"subject"`
	Body        string   `json:"body"`
	Attachments []string `json:"attachments"` // URLs of the attachments
}

// Convert timestamps to relative time
type EmailResponse struct {
	Email
	From            string       `json:"From"`
	ListAttachments []Attachment `json:"ListAttachments"`
	RelativeTime    string       `json:"RelativeTime"`
}

type Attachment struct {
	Filename    string `json:"Filename"`
	ContentType string `json:"ContentType"`
	Content     []byte `json:"Content"`
	URL         string `json:"URL"` // URL to download the attachment from S3
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

type EmailAddress struct {
	Name    string `json:"name,omitempty"`
	Address string `json:"address"`
}

// SentEmail represents an email sent by a user
type SentEmail struct {
	ID                string     `json:"id"`
	UserID            int64      `db:"user_id" json:"-"`
	FromEmail         string     `db:"from_email" json:"from"`
	ToEmail           string     `db:"to_email" json:"to"`
	Subject           string     `db:"subject" json:"subject"`
	BodyPreview       string     `db:"body_preview" json:"body_preview"`
	Body              string     `db:"body" json:"body,omitempty"`
	Attachments       string     `db:"attachments" json:"attachments,omitempty"`
	Provider          string     `db:"provider" json:"provider,omitempty"`
	ProviderMessageID string     `db:"provider_message_id" json:"provider_message_id,omitempty"`
	Status            string     `db:"status" json:"status"`
	ErrorMessage      string     `db:"error_message" json:"error_message,omitempty"`
	SentAt            *time.Time `db:"sent_at" json:"sent_at"`
	CreatedAt         time.Time  `db:"created_at" json:"created_at"`
	HasAttachments    bool       `json:"has_attachments"`
}

// SentEmailDB represents the database structure
type SentEmailDB struct {
	ID                int64      `db:"id"`
	UserID            int64      `db:"user_id"`
	FromEmail         string     `db:"from_email"`
	ToEmail           string     `db:"to_email"`
	Subject           string     `db:"subject"`
	BodyPreview       *string    `db:"body_preview"`
	Body              string     `db:"body"`
	Attachments       *string    `db:"attachments"`
	Provider          *string    `db:"provider"`
	ProviderMessageID *string    `db:"provider_message_id"`
	Status            string     `db:"status"`
	ErrorMessage      *string    `db:"error_message"`
	SentAt            *time.Time `db:"sent_at"`
	CreatedAt         time.Time  `db:"created_at"`
}

// UserSentEmailsResponse represents the paginated response for user's sent emails
type UserSentEmailsResponse struct {
	Data       []SentEmail        `json:"data"`
	Pagination PaginationResponse `json:"pagination"`
}

// PaginationResponse represents pagination info
type PaginationResponse struct {
	Page       int `json:"page"`
	Limit      int `json:"limit"`
	Total      int `json:"total"`
	TotalPages int `json:"total_pages"`
}
