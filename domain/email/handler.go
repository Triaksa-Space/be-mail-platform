package email

import (
	"email-platform/config"
	"net/http"

	"github.com/labstack/echo/v4"
)

type SendEmailRequest struct {
	UserID      int64  `json:"user_id"`
	Subject     string `json:"subject"`
	Body        string `json:"body"`
	Attachments string `json:"attachments"`
}

func SendEmailHandler(c echo.Context) error {
	req := new(SendEmailRequest)
	if err := c.Bind(req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request"})
	}

	_, err := config.DB.Exec(
		"INSERT INTO emails (user_id, subject, body, attachments, created_at, updated_at) VALUES (?, ?, ?, ?, NOW(), NOW())",
		req.UserID, req.Subject, req.Body, req.Attachments,
	)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to send email"})
	}

	return c.JSON(http.StatusCreated, map[string]string{"message": "Email sent successfully"})
}
