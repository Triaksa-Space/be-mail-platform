package email

import (
	"email-platform/config"
	"email-platform/domain/user"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
)

func DeductEmailLimit(userID int64) error {
	// Increment counter
	_, err := config.DB.Exec(`UPDATE users SET sent_emails = sent_emails - 1, last_login = NOW() WHERE id = ?`, userID)
	return err
}

func CheckEmailLimit(userID int64) error {
	var user user.User
	err := config.DB.Get(&user, `
        SELECT sent_emails, last_email_time 
        FROM users 
        WHERE id = ?`, userID)
	if err != nil {
		return err
	}

	// Reset counter if 24h passed
	if time.Since(*user.LastEmailTime) > 24*time.Hour {
		_, err := config.DB.Exec(`
            UPDATE users 
            SET sent_emails = 0, 
                last_email_time = NOW() 
            WHERE id = ?`, userID)
		return err
	}

	if user.SentEmails >= 3 {
		return errors.New("daily email limit exceeded (3 emails per 24 hours)")
	}

	// Increment counter
	_, err = config.DB.Exec(`
        UPDATE users 
        SET sent_emails = sent_emails + 1,
		last_login = NOW()
        WHERE id = ?`, userID)
	return err
}

func SendEmailHandler(c echo.Context) error {
	// Get user ID from context
	userID := c.Get("user_id").(int64)
	userEmail := c.Get("email").(string)

	// Check email limit
	if err := CheckEmailLimit(userID); err != nil {
		return c.JSON(http.StatusTooManyRequests, map[string]string{
			"error": err.Error(),
		})
	}

	// Parse and validate request
	req := new(SendEmailRequest)
	if err := c.Bind(req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid request payload",
		})
	}

	attachmentsStr := ""

	for _, attachment := range req.Attachments {
		// 	fmt.Println("Attachment Name:", attachment.Name)
		// 	fmt.Println("Attachment Content:", attachment.Content)
		attachmentsStr = attachmentsStr + "," + attachment.Name + ","
	}

	// // Initialize AWS session
	// sess, err := session.NewSession(&aws.Config{
	// 	Region: aws.String(viper.GetString("AWS_REGION")),
	// })
	// if err != nil {
	// 	return c.JSON(http.StatusInternalServerError, map[string]string{
	// 		"error": "Failed to initialize AWS session",
	// 	})
	// }

	// // Upload attachments to S3
	// var attachmentURLs []string
	// if len(req.Attachments) > 0 {
	// 	s3Client := s3.New(sess)
	// 	for idx, attachment := range req.Attachments {
	// 		key := fmt.Sprintf("attachments/%d/%d-%s", userID, time.Now().UnixNano(), idx)
	// 		_, err = s3Client.PutObject(&s3.PutObjectInput{
	// 			Bucket: aws.String(viper.GetString("AWS_S3_BUCKET")),
	// 			Key:    aws.String(key),
	// 			Body:   strings.NewReader(attachment),
	// 		})
	// 		if err != nil {
	// 			return c.JSON(http.StatusInternalServerError, map[string]string{
	// 				"error": "Failed to upload attachment",
	// 			})
	// 		}
	// 		attachmentURL := fmt.Sprintf("https://%s.s3.amazonaws.com/%s",
	// 			viper.GetString("AWS_S3_BUCKET"), key)
	// 		attachmentURLs = append(attachmentURLs, attachmentURL)
	// 	}
	// }

	// // Send email via SES
	// sesClient := ses.New(sess)
	// input := &ses.SendEmailInput{
	// 	Destination: &ses.Destination{
	// 		ToAddresses: []*string{aws.String(req.To)},
	// 	},
	// 	Message: &ses.Message{
	// 		Body: &ses.Body{
	// 			Text: &ses.Content{
	// 				Charset: aws.String("UTF-8"),
	// 				Data:    aws.String(req.Body),
	// 			},
	// 		},
	// 		Subject: &ses.Content{
	// 			Charset: aws.String("UTF-8"),
	// 			Data:    aws.String(req.Subject),
	// 		},
	// 	},
	// 	Source: aws.String(viper.GetString("SES_EMAIL_SOURCE")),
	// }

	// _, err = sesClient.SendEmail(input)
	// if err != nil {
	// 	return c.JSON(http.StatusInternalServerError, map[string]string{
	// 		"error": "Failed to send email",
	// 	})
	// }

	// Save email to database
	tx, err := config.DB.Begin()
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "Failed to start transaction",
		})
	}
	defer tx.Rollback()

	result, err := tx.Exec(`
        INSERT INTO emails (user_id, email_type, sender_email, sender_name, subject, body, attachments, timestamp, created_at, updated_at) 
        VALUES (?, "sent", ?, ?, ?, ?, ?, NOW(), NOW(), NOW())`,
		userID, userEmail, "", req.Subject, req.Body, attachmentsStr)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "Failed to save email",
		})
	}

	_, err = result.LastInsertId()
	if err != nil {
		// // DEDUCT COUNT SENT EMAIL
		// DeductEmailLimit(userID)
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "Failed to get email ID",
		})
	}

	// // Save attachments
	// for _, url := range attachmentURLs {
	// 	_, err = tx.Exec(`
	//         INSERT INTO email_attachments (email_id, url, created_at, updated_at)
	//         VALUES (?, ?, NOW(), NOW())`,
	// 		emailID, url)
	// 	if err != nil {
	// 		return c.JSON(http.StatusInternalServerError, map[string]string{
	// 			"error": "Failed to save attachment",
	// 		})
	// 	}
	// }

	if err := tx.Commit(); err != nil {
		// // DEDUCT COUNT SENT EMAIL
		// DeductEmailLimit(userID)
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "Failed to commit transaction",
		})
	}

	// TODO: Only ADD COUNT when email successfully
	return c.JSON(http.StatusOK, map[string]string{
		"message": "Email sent successfully",
	})
}

func GetEmailHandler(c echo.Context) error {
	emailID := c.Param("id")
	// TODO: ATTACHMENT DIBUAT TABLE SENDIRI SAJA

	// Fetch email details by ID
	var email Email
	err := config.DB.Get(&email, `SELECT id, 
            user_id, 
            sender_email, sender_name, 
            subject, 
            CONCAT(LEFT(body, 25), IF(LENGTH(body) > 25, '...', '')) as preview,
            body,
            timestamp, 
            created_at, 
            updated_at  FROM emails WHERE id = ? and email_type = "inbox"`, emailID)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "Email not found"})
	}

	var emailResp EmailResponse
	emailResp.Email = email
	emailResp.RelativeTime = formatRelativeTime(email.Timestamp)

	return c.JSON(http.StatusOK, emailResp)
}

func ListEmailsHandler(c echo.Context) error {
	// Fetch all emails
	var emails []Email
	err := config.DB.Select(&emails, `SELECT id, 
            user_id, 
            sender_email, sender_name, 
            subject, 
            CONCAT(LEFT(body, 25), IF(LENGTH(body) > 25, '...', '')) as preview,
            body,
            timestamp, 
            created_at, 
            updated_at FROM emails and email_type = "inbox" ORDER BY timestamp DESC`)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to fetch emails"})
	}

	return c.JSON(http.StatusOK, emails)
}

func SentEmailByIDHandler(c echo.Context) error {
	userID := c.Get("user_id").(int64)

	var user user.User
	err := config.DB.Get(&user, `
			SELECT id, email, role_id, last_login, sent_emails, last_email_time, created_at, updated_at
			FROM users 
			WHERE id = ?`, userID)
	if err != nil {
		return err
	}

	return c.JSON(http.StatusOK, user)
}

func ListEmailByTokenHandler(c echo.Context) error {
	userID := c.Get("user_id").(int64)

	var emails []Email
	err := config.DB.Select(&emails, `SELECT id, 
            user_id, 
            sender_email, sender_name, 
            subject, 
            CONCAT(LEFT(body, 25), IF(LENGTH(body) > 25, '...', '')) as preview,
            body,
            timestamp, 
            created_at, 
            updated_at FROM emails WHERE user_id = ? and email_type = "inbox" ORDER BY timestamp DESC`, userID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to fetch emails"})
	}

	response := make([]EmailResponse, len(emails))
	for i, email := range emails {
		response[i] = EmailResponse{
			Email:        email,
			RelativeTime: formatRelativeTime(email.Timestamp),
		}
	}

	return c.JSON(http.StatusOK, response)
}

func ListEmailByIDHandler(c echo.Context) error {
	userID := c.Param("id")

	var emails []Email
	err := config.DB.Select(&emails, `SELECT id, 
            user_id, 
            sender_email, sender_name, 
            subject, 
            CONCAT(LEFT(body, 25), IF(LENGTH(body) > 25, '...', '')) as preview,
            body,
            timestamp, 
            created_at, 
            updated_at FROM emails WHERE user_id = ? and email_type = "inbox" ORDER BY timestamp DESC`, userID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to fetch emails"})
	}

	response := make([]EmailResponse, len(emails))
	for i, email := range emails {
		response[i] = EmailResponse{
			Email:        email,
			RelativeTime: formatRelativeTime(email.Timestamp),
		}
	}

	return c.JSON(http.StatusOK, response)
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

func formatRelativeTime(t time.Time) string {
	now := time.Now()
	diff := now.Sub(t)

	switch {
	case diff < time.Minute:
		return "Just now"
	case diff < time.Hour:
		minutes := int(diff.Minutes())
		if minutes == 1 {
			return "1 Minute ago"
		}
		return fmt.Sprintf("%d Minutes ago", minutes)
	case diff < 24*time.Hour:
		hours := int(diff.Hours())
		if hours == 1 {
			return "1 Hour ago"
		}
		return fmt.Sprintf("%d Hours ago", hours)
	case diff < 48*time.Hour:
		return "Yesterday"
	default:
		return t.Format("02 Jan 2006")
	}
}
