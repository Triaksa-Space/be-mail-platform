package email

import "time"

type Email struct {
	ID      int64  `db:"id"`
	UserID  int64  `db:"user_id"`
	Sender  string `db:"sender"`
	Subject string `db:"subject"`
	Preview string `db:"preview"`
	Body    string `db:"body"`
	// Attachments string    `db:"attachments"` // JSON format
	Timestamp time.Time `db:"timestamp"`
	CreatedAt time.Time `db:"created_at"`
	UpdatedAt time.Time `db:"updated_at"`
}
