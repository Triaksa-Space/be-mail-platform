package domain

import "time"

type DomainEmail struct {
	ID        int64     `db:"id"`
	Domain    string    `db:"domain"`
	CreatedAt time.Time `db:"created_at"`
	UpdatedAt time.Time `db:"updated_at"`
}

type CreateDomainRequest struct {
	Domain string `json:"domain" validate:"required"`
}
