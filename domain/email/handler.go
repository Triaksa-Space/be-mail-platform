package email

import (
	"email-platform/utils"
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ses"
	"github.com/aws/aws-sdk-go-v2/service/ses/types"
	"github.com/labstack/echo/v4"
)

type SendEmailRequest struct {
	To          []string `json:"to" validate:"required"`
	Subject     string   `json:"subject" validate:"required"`
	Body        string   `json:"body" validate:"required"`
	Attachments []string `json:"attachments"`
}

func SendEmailHandler(c echo.Context) error {
	req := new(SendEmailRequest)
	if err := c.Bind(req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request"})
	}

	if err := c.Validate(req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	userID := c.Get("user_id").(string)

	// Send email via AWS SES
	sesClient := utils.CreateSESClient()
	input := &ses.SendEmailInput{
		Destination: &types.Destination{
			ToAddresses: req.To,
		},
		Message: &types.Message{
			Subject: &types.Content{
				Charset: aws.String("UTF-8"),
				Data:    aws.String(req.Subject),
			},
			Body: &types.Body{
				Text: &types.Content{
					Charset: aws.String("UTF-8"),
					Data:    aws.String(req.Body),
				},
			},
		},
		Source: aws.String("noreply@example.com"), // Replace with your verified SES email
	}

	_, err := sesClient.SendEmail(c.Request().Context(), input)
	if err != nil {
		log.Printf("Failed to send email: %v", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to send email"})
	}

	// Store email metadata in the database
	emailID := uuid.New().String()
	_, err = utils.DB.Exec(
		`INSERT INTO emails (id, user_id, subject, body, attachments, created_at, updated_at) 
         VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		emailID, userID, req.Subject, req.Body, req.Attachments, time.Now(), time.Now(),
	)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to save email metadata"})
	}

	return c.JSON(http.StatusCreated, map[string]string{"message": "email sent successfully", "email_id": emailID})
}

func GetEmailHandler(c echo.Context) error {
	emailID := c.Param("email_id")

	var email Email
	err := utils.DB.Get(&email, "SELECT * FROM emails WHERE id = $1", emailID)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "email not found"})
	}

	return c.JSON(http.StatusOK, email)
}

func ListEmailsHandler(c echo.Context) error {
	userID := c.Param("user_id")

	var emails []Email
	err := utils.DB.Select(&emails, "SELECT * FROM emails WHERE user_id = $1 ORDER BY created_at DESC", userID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to fetch emails"})
	}

	return c.JSON(http.StatusOK, emails)
}

func DeleteEmailHandler(c echo.Context) error {
	emailID := c.Param("id")

	// Check if the email exists
	var email Email
	err := utils.DB.Get(&email, "SELECT * FROM emails WHERE id = $1", emailID)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "email not found"})
	}

	// Delete the email
	_, err = utils.DB.Exec("DELETE FROM emails WHERE id = $1", emailID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to delete email"})
	}

	return c.JSON(http.StatusOK, map[string]string{"message": "email deleted successfully"})
}
