package user

import (
	"email-platform/config"
	"email-platform/utils"
	"time"
)

func CreateUser(email, password string) error {
	hashedPassword, err := utils.HashPassword(password)
	if err != nil {
		return err
	}

	_, err = config.DB.Exec(
		"INSERT INTO users (email, password, created_at, updated_at) VALUES (?, ?, ?, ?)",
		email, hashedPassword, time.Now(), time.Now(),
	)
	return err
}
