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

func GetEmailHandler(c echo.Context) error {
	emailID := c.Param("id")

	// Fetch email details by ID
	var email Email
	err := config.DB.Get(&email, "SELECT * FROM emails WHERE id = ?", emailID)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "Email not found"})
	}

	return c.JSON(http.StatusOK, email)
}

func ListEmailsHandler(c echo.Context) error {
	// Fetch all emails
	var emails []Email
	err := config.DB.Select(&emails, "SELECT * FROM emails ORDER BY created_at DESC")
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to fetch emails"})
	}

	return c.JSON(http.StatusOK, emails)
}

func ListEmailByIDHandler(c echo.Context) error {
	userID := c.Param("user_id")

	// Fetch all emails
	var emails []Email
	err := config.DB.Select(&emails, "SELECT * FROM emails WHERE user_id = ? ORDER BY created_at DESC", userID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to fetch emails"})
	}

	return c.JSON(http.StatusOK, emails)
}

func DeleteEmailHandler(c echo.Context) error {
	emailID := c.Param("id")

	// Delete email by ID
	result, err := config.DB.Exec("DELETE FROM emails WHERE id = ?", emailID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to delete email"})
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil || rowsAffected == 0 {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "Email not found"})
	}

	return c.JSON(http.StatusOK, map[string]string{"message": "Email deleted successfully"})
}
