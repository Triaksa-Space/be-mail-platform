package email

import "time"

type Email struct {
	ID          string    `db:"id"`
	UserID      string    `db:"user_id"`
	Subject     string    `db:"subject"`
	Body        string    `db:"body"`
	Attachments []string  `db:"attachments"`
	CreatedAt   time.Time `db:"created_at"`
	UpdatedAt   time.Time `db:"updated_at"`
}
