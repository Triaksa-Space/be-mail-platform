package email

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"log"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/Triaksa-Space/be-mail-platform/config"
	"github.com/Triaksa-Space/be-mail-platform/domain/user"
	"github.com/Triaksa-Space/be-mail-platform/pkg"
	"github.com/Triaksa-Space/be-mail-platform/utils"
	"github.com/google/uuid"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/jhillyerd/enmime"
	"github.com/labstack/echo/v4"
	"github.com/spf13/viper"
)

type EmailService struct {
	S3Client   *s3.S3
	BucketName string
}

// Define the payload struct
type BounceMessage struct {
	Message string `json:"message"`
}

type BounceData struct {
	Bounce    BounceMessage `json:"bounce"`
	CreatedAt string        `json:"created_at"`
	EmailID   string        `json:"email_id"`
	From      string        `json:"from"`
	Subject   string        `json:"subject"`
	To        []string      `json:"to"`
}

type WebhookPayload struct {
	CreatedAt string     `json:"created_at"`
	Data      BounceData `json:"data"`
	Type      string     `json:"type"`
}

func DeductEmailLimit(userID int64) error {
	// Increment counter
	_, err := config.DB.Exec(`UPDATE users SET sent_emails = sent_emails - 1, last_login = NOW() WHERE id = ?`, userID)
	return err
}

func HandleEmailBounceHandler(c echo.Context) error {
	// Bind the JSON payload to the struct
	var payload WebhookPayload
	if err := c.Bind(&payload); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid request payload",
		})
	}

	// Process the data (e.g., log the bounce, update the database, etc.)
	// For demonstration, we'll just print the payload
	fmt.Printf("Received webhook payload: %+v\n", payload)
	// fmt.Println("payload.Data.From", payload.Data.From)
	userID, err := getUserByEmail(payload.Data.From)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "Failed to fetch user email",
		})
	}

	// SEND EMAIL TO SENDER using EMAIL_SUPPORT
	emailSupport := viper.GetString("EMAIL_SUPPORT")
	nameSupport := viper.GetString("NAME_SUPPORT")

	if utils.IsFromMailria(payload.Data.From) {
		emailSupport = viper.GetString("EMAIL_MAILRIA_SUPPORT")
		nameSupport = viper.GetString("NAME_MAILRIA_SUPPORT")
	}

	err = process10Emails(int64(userID), payload.Data.From)
	if err != nil {
		fmt.Println("Failed to process incoming emails", err)
	}
	fmt.Println("Finish refresh internal mailbox")

	// TODO: MAKE STANDARD BOUNCE EMAIL
	sendTo := ""
	notificationSubject := ""
	notificationBody := ""
	preview := ""
	if len(payload.Data.To) > 0 {
		sendTo = payload.Data.To[0]
	}

	// Check if bounce is 'address not found'
	if payload.Type == "email.bounced" {
		// Send custom notification email to sender
		notificationSubject = "Bounce Notification: Address Not Found"
		notificationBody = fmt.Sprintf(`
            <p>Your email to %s failed to deliver because the address was not found.</p>
            <p>Subject: %s</p>
            <p>Message: %s</p>
        `, payload.Data.To[0], payload.Data.Subject, payload.Data.Bounce.Message)

		preview = "Your email to " + sendTo + " failed to deliver because the address was not found."
	} else {
		notificationSubject = payload.Data.Subject
		notificationBody = payload.Data.Bounce.Message

		length := 25
		if len(payload.Data.Bounce.Message) > length {
			preview = payload.Data.Bounce.Message[:length]
		}
	}

	// Normalize the datetime string
	normalizedTimeStr := strings.Replace(payload.Data.CreatedAt, " ", "T", 1)
	if strings.HasSuffix(normalizedTimeStr, "+00") || strings.HasSuffix(normalizedTimeStr, "-00") {
		normalizedTimeStr += ":00"
	}

	// Define a layout matching the normalized datetime string
	const layout = "2006-01-02T15:04:05.999999-07:00"

	// Parse the datetime string to a time.Time object
	timestamp, err := time.Parse(layout, normalizedTimeStr)
	if err != nil {
		fmt.Printf("Failed to parse datetime: %v\n", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "Failed to parse datetime",
		})
	}

	// Format the time.Time object to a MySQL-compatible datetime string
	formattedTimestamp := timestamp.Format("2006-01-02 15:04:05")

	// Insert into user email that his email failed to send
	// Insert the processed email into the emails table
	_, err = config.DB.Exec(`
	INSERT INTO emails (
		user_id,
		sender_email,
		sender_name,
		subject,
		preview,
		body,
		email_type,
		attachments,
		message_id,
		timestamp,
		created_at,
		updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())
`,
		userID,
		emailSupport,
		nameSupport,
		notificationSubject,
		preview,
		notificationBody,
		"inbox", // Set email_type as needed
		"",
		payload.Data.EmailID,
		formattedTimestamp,
	)
	if err != nil {
		fmt.Printf("Failed to insert email %s into DB: %v\n", payload.Data.EmailID, err)
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "Failed to insert bounce email into DB" + err.Error(),
		})
	}

	// Return a success response
	return c.JSON(http.StatusOK, map[string]string{
		"message": "Email bounce notification received",
	})
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

	if user.SentEmails >= 3 {
		return errors.New("daily email limit exceeded (3 emails per 24 hours)")
	}

	if user.SentEmails == 0 {
		// first time sent email
		_, err := config.DB.Exec(`
            UPDATE users 
            SET sent_emails = 0, 
                last_email_time = NOW() 
            WHERE id = ?`, userID)
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

	return err
}

// DeleteUrlAttachmentHandler handles deleting an attachment from AWS S3 based on a provided URL
func DeleteUrlAttachmentHandler(c echo.Context) error {
	// Get the URL of the attachment from the request parameters
	// urlAttachment := c.Param("url_attachment")
	// Parse JSON payload
	var req DeleteAttachmentParam
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid request payload",
		})
	}

	// Initialize AWS session
	sess, err := pkg.InitAWS()
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "Failed to initialize AWS session",
		})
	}

	// Create S3 client
	s3Client := s3.New(sess)

	for _, urlAttachment := range req.URL {
		// Parse the URL to extract the bucket name and key
		parsedURL, err := url.Parse(urlAttachment)
		if err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{
				"error": "Invalid URL",
			})
		}

		// Extract the bucket name and key from the URL
		bucket := strings.Split(parsedURL.Host, ".")[0]
		key := strings.TrimPrefix(parsedURL.Path, "/")

		// Delete the object from S3
		_, err = s3Client.DeleteObject(&s3.DeleteObjectInput{
			Bucket: aws.String(bucket),
			Key:    aws.String(key),
		})
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{
				"error": fmt.Sprintf("Failed to delete object from S3: %v", err),
			})
		}
	}

	// Return a success response
	return c.JSON(http.StatusOK, map[string]string{
		"message": "Attachment deleted successfully",
	})
}

// SendEmailUrlAttachmentHandler handles sending emails with attachment URLs
func SendEmailUrlAttachmentHandler(c echo.Context) error {
	// Get user ID and email from context
	userID := c.Get("user_id").(int64)

	emailUser, err := getUserEmail(userID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "Failed to fetch user email",
		})
	}

	// Check email limit
	if err := CheckEmailLimit(userID); err != nil {
		return c.JSON(http.StatusTooManyRequests, map[string]string{
			"error": "Email limit exceeded",
		})
	}

	// Parse JSON payload
	var req SendEmailRequestURLAttachment
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid request payload",
		})
	}

	// Prepare attachments
	var attachments []pkg.Attachment
	for _, url := range req.Attachments {
		// Extract filename from URL
		parts := strings.Split(url, "/")
		filename := parts[len(parts)-1]

		attachments = append(attachments, pkg.Attachment{
			Filename:    filename,
			ContentType: "application/octet-stream", // Default content type
			Content:     nil,                        // Content is not needed for URL attachments
			URL:         url,
		})
	}

	// Send email via pkg/aws
	err = pkg.SendEmailWithAttachmentURL(req.To, emailUser, req.Subject, req.Body, attachments)
	if err != nil {
		fmt.Println("Failed to send email", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": err.Error(),
		})
	}

	// Save email to sent_emails table for tracking
	attachmentsJSON, _ := json.Marshal(req.Attachments)

	// Generate preview
	preview := generatePreview("", req.Body)
	if len(preview) > 500 {
		preview = preview[:500]
	}

	_, err = config.DB.Exec(`
		INSERT INTO sent_emails (
			user_id,
			from_email,
			to_email,
			subject,
			body_preview,
			body,
			attachments,
			provider,
			status,
			sent_at,
			created_at
		)
		VALUES (?, ?, ?, ?, ?, ?, ?, 'ses', 'sent', NOW(), NOW())`,
		userID, emailUser, req.To, req.Subject, preview, req.Body, attachmentsJSON)
	if err != nil {
		fmt.Println("Email sent but failed to save to sent_emails:", err)
	}

	// Update last login
	err = updateLastLogin(userID)
	if err != nil {
		fmt.Println("error updateLastLogin", err)
	}

	// Update limit if sent Email success
	err = updateLimitSentEmails(userID)
	if err != nil {
		fmt.Println("error updateLimitSentEmails", err)
	}

	return c.JSON(http.StatusOK, map[string]string{
		"message": "Email sent successfully",
	})
}

// SendEmailHandler handles sending emails with attachments
func SendEmailHandler(c echo.Context) error {
	// Get user ID and email from context
	userID := c.Get("user_id").(int64)

	emailUser, err := getUserEmail(userID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "Failed to fetch user email",
		})
	}

	// Check email limit
	if err := CheckEmailLimit(userID); err != nil {
		return c.JSON(http.StatusTooManyRequests, map[string]string{
			"error": "Email limit exceeded",
		})
	}

	// Parse form data
	to := c.FormValue("to")
	subject := c.FormValue("subject")
	body := c.FormValue("body")

	// Prepare attachments and upload to S3
	var attachments []pkg.Attachment
	var attachmentURLs []string

	form, err := c.MultipartForm()
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid form data",
		})
	}

	files := form.File["attachments"]
	for _, file := range files {
		src, err := file.Open()
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{
				"error": "Failed to open attachment",
			})
		}
		defer src.Close()

		content, err := io.ReadAll(src)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{
				"error": "Failed to read attachment",
			})
		}

		// Convert filename to lowercase and replace spaces with underscores
		filename := strings.ToLower(file.Filename)
		filename = strings.ReplaceAll(filename, " ", "_")

		// Append the attachment URL to the list
		attachmentURLs = append(attachmentURLs, filename)

		// Prepare the attachment for sending email
		attachments = append(attachments, pkg.Attachment{
			Filename:    filename,
			ContentType: file.Header.Get("Content-Type"),
			Content:     content,
		})
	}

	// Send email via pkg/aws
	err = pkg.SendEmail(to, emailUser, subject, body, attachments)
	if err != nil {
		fmt.Println("Failed to send email", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": err.Error(),
		})
	}

	// Save email to sent_emails table for tracking
	attachmentsJSON, _ := json.Marshal(attachmentURLs)

	// Generate preview
	preview := generatePreview("", body)
	if len(preview) > 500 {
		preview = preview[:500]
	}

	_, err = config.DB.Exec(`
		INSERT INTO sent_emails (
			user_id,
			from_email,
			to_email,
			subject,
			body_preview,
			body,
			attachments,
			provider,
			status,
			sent_at,
			created_at
		)
		VALUES (?, ?, ?, ?, ?, ?, ?, 'ses', 'sent', NOW(), NOW())`,
		userID, emailUser, to, subject, preview, body, attachmentsJSON)
	if err != nil {
		fmt.Println("Email sent but failed to save to sent_emails:", err)
	}

	// Update last login
	err = updateLastLogin(userID)
	if err != nil {
		fmt.Println("error updateLastLogin", err)
	}

	// Update limit if sent Email success
	err = updateLimitSentEmails(userID)
	if err != nil {
		fmt.Println("error updateLimitSentEmails", err)
	}

	return c.JSON(http.StatusOK, map[string]string{
		"message": "Email sent successfully",
	})
}

// SendEmailViaResendHandler handles sending emails with attachments
func SendEmailViaResendHandler(c echo.Context) error {
	// Get user ID and email from context
	userID := c.Get("user_id").(int64)

	emailUser, err := getUserEmail(userID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "Failed to fetch user email",
		})
	}

	// Check email limit
	if err := CheckEmailLimit(userID); err != nil {
		return c.JSON(http.StatusTooManyRequests, map[string]string{
			"error": "Email limit exceeded",
		})
	}

	// Parse JSON payload
	var req SendEmailRequestURLAttachment
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid request payload",
		})
	}

	// Prepare attachments
	var attachments []pkg.Attachment
	for _, url := range req.Attachments {
		// Extract filename from URL
		parts := strings.Split(url, "/")
		filename := parts[len(parts)-1]

		attachments = append(attachments, pkg.Attachment{
			Filename:    filename,
			ContentType: "application/octet-stream", // Default content type
			Content:     nil,                        // Content is not needed for URL attachments
			URL:         url,
		})
	}

	// Send email via pkg/aws
	err = pkg.SendEmailViaResend(emailUser, req.To, req.Subject, req.Body, attachments)
	if err != nil {
		fmt.Println("Failed to send email", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": err.Error(),
		})
	}

	// Save email to sent_emails table for tracking
	attachmentsJSON, _ := json.Marshal(req.Attachments)

	// Generate preview (strip HTML and limit length)
	preview := generatePreview("", req.Body)
	if len(preview) > 500 {
		preview = preview[:500]
	}

	_, err = config.DB.Exec(`
		INSERT INTO sent_emails (
			user_id,
			from_email,
			to_email,
			subject,
			body_preview,
			body,
			attachments,
			provider,
			status,
			sent_at,
			created_at
		)
		VALUES (?, ?, ?, ?, ?, ?, ?, 'resend', 'sent', NOW(), NOW())`,
		userID, emailUser, req.To, req.Subject, preview, req.Body, attachmentsJSON)
	if err != nil {
		fmt.Println("Email sent but failed to save to sent_emails:", err)
		// Don't return error since email was sent successfully
	}

	// Update last login
	err = updateLastLogin(userID)
	if err != nil {
		fmt.Println("error updateLastLogin", err)
	}

	// Update limit if sent Email success
	err = updateLimitSentEmails(userID)
	if err != nil {
		fmt.Println("error updateLimitSentEmails", err)
	}

	return c.JSON(http.StatusOK, map[string]string{
		"message": "Email sent successfully",
	})
}

func SendEmailSMTPHHandler(c echo.Context) error {
	fmt.Println("TEST HARAKA")
	// Get user ID and email from context
	userID := c.Get("user_id").(int64)

	emailUser, err := getUserEmail(userID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "Failed to fetch user email",
		})
	}

	// Check email limit
	if err := CheckEmailLimit(userID); err != nil {
		return c.JSON(http.StatusTooManyRequests, map[string]string{
			"error": "Email limit exceeded",
		})
	}

	// Parse form data
	to := c.FormValue("to")
	subject := c.FormValue("subject")
	body := c.FormValue("body")

	// Prepare attachments and upload to S3
	var attachments []pkg.Attachment
	var attachmentURLs []string

	form, err := c.MultipartForm()
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid form data",
		})
	}

	files := form.File["attachments"]
	for _, file := range files {
		src, err := file.Open()
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{
				"error": "Failed to open attachment",
			})
		}
		defer src.Close()

		content, err := io.ReadAll(src)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{
				"error": "Failed to read attachment",
			})
		}

		// Convert filename to lowercase and replace spaces with underscores
		filename := strings.ToLower(file.Filename)
		filename = strings.ReplaceAll(filename, " ", "_")

		// Append the attachment URL to the list
		attachmentURLs = append(attachmentURLs, filename)

		// Prepare the attachment for sending email
		attachments = append(attachments, pkg.Attachment{
			Filename:    filename,
			ContentType: file.Header.Get("Content-Type"),
			Content:     content,
		})
	}

	// Send email via pkg/aws
	err = pkg.SendEmailSMTP(emailUser, to, subject, body, attachments)
	if err != nil {
		fmt.Println("Failed to send email", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": err.Error(),
		})
	}

	// Save email to sent_emails table for tracking
	attachmentsJSON, _ := json.Marshal(attachmentURLs)

	// Generate preview
	preview := generatePreview("", body)
	if len(preview) > 500 {
		preview = preview[:500]
	}

	_, err = config.DB.Exec(`
		INSERT INTO sent_emails (
			user_id,
			from_email,
			to_email,
			subject,
			body_preview,
			body,
			attachments,
			provider,
			status,
			sent_at,
			created_at
		)
		VALUES (?, ?, ?, ?, ?, ?, ?, 'haraka', 'sent', NOW(), NOW())`,
		userID, emailUser, to, subject, preview, body, attachmentsJSON)
	if err != nil {
		fmt.Println("Email sent but failed to save to sent_emails:", err)
	}

	// Update last login
	err = updateLastLogin(userID)
	if err != nil {
		fmt.Println("error updateLastLogin", err)
	}

	// Update limit if sent Email success
	err = updateLimitSentEmails(userID)
	if err != nil {
		fmt.Println("error updateLimitSentEmails", err)
	}

	return c.JSON(http.StatusOK, map[string]string{
		"message": "Email sent successfully",
	})
}

// SendEmailSMTPHandler handles sending emails via SMTP with attachments
func SendEmailSMTPHandler(c echo.Context) error {
	// Get user ID and email from context
	userID := c.Get("user_id").(int64)

	emailUser, err := getUserEmail(userID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "Failed to fetch user email",
		})
	}

	// Check email limit
	if err := CheckEmailLimit(userID); err != nil {
		return c.JSON(http.StatusTooManyRequests, map[string]string{
			"error": "Email limit exceeded",
		})
	}

	// Parse form data
	to := c.FormValue("to")
	subject := c.FormValue("subject")
	body := c.FormValue("body")

	// Prepare attachments and upload to S3
	var attachments []pkg.Attachment
	var attachmentURLs []string

	form, err := c.MultipartForm()
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid form data",
		})
	}

	files := form.File["attachments"]
	for _, file := range files {
		src, err := file.Open()
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{
				"error": "Failed to open attachment",
			})
		}
		defer src.Close()

		content, err := io.ReadAll(src)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{
				"error": "Failed to read attachment",
			})
		}

		// Convert filename to lowercase and replace spaces with underscores
		filename := strings.ToLower(file.Filename)
		filename = strings.ReplaceAll(filename, " ", "_")

		// Append the attachment URL to the list
		attachmentURLs = append(attachmentURLs, filename)

		// Prepare the attachment for sending email
		attachments = append(attachments, pkg.Attachment{
			Filename:    filename,
			ContentType: file.Header.Get("Content-Type"),
			Content:     content,
		})
	}

	// Send email via pkg/aws
	err = pkg.SendEmailWithHARAKA(to, emailUser, subject, body, attachments)
	if err != nil {
		fmt.Println("Failed to send email", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": err.Error(),
		})
	}

	// Save email to sent_emails table for tracking
	attachmentsJSON, _ := json.Marshal(attachmentURLs)

	// Generate preview
	preview := generatePreview("", body)
	if len(preview) > 500 {
		preview = preview[:500]
	}

	_, err = config.DB.Exec(`
		INSERT INTO sent_emails (
			user_id,
			from_email,
			to_email,
			subject,
			body_preview,
			body,
			attachments,
			provider,
			status,
			sent_at,
			created_at
		)
		VALUES (?, ?, ?, ?, ?, ?, ?, 'smtp', 'sent', NOW(), NOW())`,
		userID, emailUser, to, subject, preview, body, attachmentsJSON)
	if err != nil {
		fmt.Println("Email sent but failed to save to sent_emails:", err)
	}

	// Update last login
	err = updateLastLogin(userID)
	if err != nil {
		fmt.Println("error updateLastLogin", err)
	}

	// Update limit if sent Email success
	err = updateLimitSentEmails(userID)
	if err != nil {
		fmt.Println("error updateLimitSentEmails", err)
	}

	return c.JSON(http.StatusOK, map[string]string{
		"message": "Email sent successfully",
	})
}

func GetFileEmailToDownloadHandler(c echo.Context) error {
	userID := c.Get("user_id").(int64)
	roleID := c.Get("role_id").(int64)
	// Get email ID and file URL from the request parameters
	// emailID := c.Param("id")
	// fileURL := c.Param("file_url")
	// Define a struct to parse the JSON payload
	type RequestPayload struct {
		EmailID string `json:"email_id"`
		FileURL string `json:"file_url"`
	}

	// Parse the JSON payload
	var payload RequestPayload
	if err := c.Bind(&payload); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request payload"})
	}

	emailID := payload.EmailID
	fileURL := payload.FileURL

	// Fetch the email record from the database
	var email Email
	var query string
	var err error

	if roleID == 1 {
		query = `SELECT id, 
            user_id, 
            sender_email, sender_name, 
            subject, 
            body,
			preview,
			message_id,
			attachments,
            timestamp, 
            created_at, 
            updated_at  FROM emails WHERE id = ? and user_id = ?`

		err = config.DB.Get(&email, query, emailID, userID)
	} else {
		query = `SELECT id, 
			user_id, 
			sender_email, sender_name, 
			subject, 
			body,
			preview,
			message_id,
			attachments,
			timestamp, 
			created_at, 
			updated_at  FROM emails WHERE id = ?`

		err = config.DB.Get(&email, query, emailID)
	}

	if err != nil {
		fmt.Println("Failed to fetch email", err)
		return c.JSON(http.StatusNotFound, map[string]string{"error": "Email not found"})
	}

	// Extract the file URL from the email record
	var attachmentURLs []string
	if err := json.Unmarshal([]byte(email.Attachments), &attachmentURLs); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to parse attachments"})
	}

	// Find the matching file URL
	var downloadURL string
	for _, url := range attachmentURLs {
		if strings.Contains(url, fileURL) {
			downloadURL = url
			break
		}
	}

	if downloadURL == "" {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "File not found"})
	}

	// Parse the S3 URL to get the bucket name and key
	parsedURL, err := url.Parse(downloadURL)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to parse file URL"})
	}

	bucket := strings.Split(parsedURL.Host, ".")[0]
	key := strings.TrimPrefix(parsedURL.Path, "/")

	// Initialize AWS session
	sess, err := pkg.InitAWS()
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to initialize AWS session"})
	}

	// Create S3 client
	s3Client := s3.New(sess)

	// Get the object from S3
	output, err := s3Client.GetObject(&s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to get file from S3"})
	}
	defer output.Body.Close()

	// Set the response headers
	c.Response().Header().Set(echo.HeaderContentType, *output.ContentType)
	c.Response().Header().Set(echo.HeaderContentDisposition, fmt.Sprintf("attachment; filename=%s", path.Base(key)))

	// Stream the file to the client
	if _, err := io.Copy(c.Response().Writer, output.Body); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to stream file"})
	}

	return nil
}

func GetEmailHandler(c echo.Context) error {
	userID := c.Get("user_id").(int64)
	emailID := c.Param("id")

	fmt.Println("emailID", emailID)

	emailIDDecode, err := utils.DecodeID(emailID)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid email ID"})
	}

	// Decode the encoded ID back to the original integer ID
	emailID = strconv.Itoa(emailIDDecode)

	var user user.User
	err = config.DB.Get(&user, `
			SELECT id, email, role_id, last_login, sent_emails, last_email_time, created_at, updated_at
			FROM users 
			WHERE id = ?`, userID)
	if err != nil {
		return err
	}

	// Fetch email details by ID
	var email Email
	if user.RoleID == 1 {
		err = config.DB.Get(&email, `SELECT id, 
            user_id, 
            sender_email, sender_name, 
            subject, 
            body,
			preview,
			message_id,
			attachments,
            timestamp, 
            created_at, 
            updated_at  FROM emails WHERE id = ? and user_id = ? and email_type = "inbox"`, emailID, user.ID)
		if err != nil {
			return c.JSON(http.StatusNotFound, map[string]string{"error": "Email not found"})
		}
	} else {
		err = config.DB.Get(&email, `SELECT id, 
            user_id, 
            sender_email, sender_name, 
            subject, 
            body,
			preview,
			message_id,
			attachments,
            timestamp, 
            created_at, 
            updated_at  FROM emails WHERE id = ? and email_type = "inbox"`, emailID)
		if err != nil {
			return c.JSON(http.StatusNotFound, map[string]string{"error": "Email not found"})
		}
	}

	// Get User From Email
	userFromEmail, _ := getUserEmail(email.UserID)

	var emailResp EmailResponse
	emailResp.Email = email
	emailResp.RelativeTime = formatRelativeTime(email.Timestamp)
	emailResp.ListAttachments = getAttachmentURLs(email.Attachments)
	emailResp.From = userFromEmail

	// Update last login
	err = updateLastLogin(userID)
	if err != nil {
		fmt.Println("error updateLastLogin", err)
	}

	if user.RoleID == 1 {
		// Update isRead
		err = updateIsRead(emailID)
		if err != nil {
			fmt.Println("error updateIsRead", err)
		}
	}

	return c.JSON(http.StatusOK, emailResp)
}

func ListEmailsHandler(c echo.Context) error {
	// Fetch all emails
	var emails []Email
	err := config.DB.Select(&emails, `SELECT id, 
			is_read,
            user_id, 
            sender_email, sender_name, 
            subject,
            body,
			preview,
            timestamp, 
            created_at, 
            updated_at FROM emails and email_type = "inbox" ORDER BY timestamp DESC`)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to fetch emails"})
	}

	var encodedEmails []Email
	for _, email := range emails {
		email.EmailEncodeID = utils.EncodeID(int(email.ID))
		email.UserEncodeID = utils.EncodeID(int(email.UserID))
		encodedEmails = append(encodedEmails, email)
	}

	return c.JSON(http.StatusOK, encodedEmails)
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

// ListSentEmailsByUserIDHandler returns sent emails for a specific user (admin only)
// GET /email/sent/by_user/:id
func ListSentEmailsByUserIDHandler(c echo.Context) error {
	// Decode user ID from param
	userIDParam := c.Param("id")
	targetUserID, err := utils.DecodeID(userIDParam)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid user ID",
		})
	}

	// Pagination
	page, _ := strconv.Atoi(c.QueryParam("page"))
	if page < 1 {
		page = 1
	}
	limit, _ := strconv.Atoi(c.QueryParam("limit"))
	if limit < 1 || limit > 100 {
		limit = 20
	}
	offset := (page - 1) * limit

	// Get total count
	var total int
	err = config.DB.Get(&total, `SELECT COUNT(*) FROM sent_emails WHERE user_id = ?`, targetUserID)
	if err != nil {
		fmt.Println("Error counting sent emails:", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
	}

	// Get sent emails
	type SentEmailRow struct {
		ID          int64          `db:"id"`
		UserID      int64          `db:"user_id"`
		FromEmail   string         `db:"from_email"`
		ToEmail     string         `db:"to_email"`
		Subject     string         `db:"subject"`
		BodyPreview sql.NullString `db:"body_preview"`
		Body        sql.NullString `db:"body"`
		Attachments sql.NullString `db:"attachments"`
		Provider    sql.NullString `db:"provider"`
		Status      string         `db:"status"`
		SentAt      sql.NullTime   `db:"sent_at"`
		CreatedAt   time.Time      `db:"created_at"`
	}

	var emails []SentEmailRow
	err = config.DB.Select(&emails, `
		SELECT id, user_id, from_email, to_email, subject, body_preview, body,
		       attachments, provider, status, sent_at, created_at
		FROM sent_emails
		WHERE user_id = ?
		ORDER BY COALESCE(sent_at, created_at) DESC
		LIMIT ? OFFSET ?
	`, targetUserID, limit, offset)

	if err != nil {
		fmt.Println("Error fetching sent emails:", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
	}

	// Build response
	data := make([]map[string]interface{}, 0)
	for _, e := range emails {
		bodyPreview := ""
		if e.BodyPreview.Valid {
			bodyPreview = e.BodyPreview.String
		}
		body := ""
		if e.Body.Valid {
			body = e.Body.String
		}
		attachments := ""
		if e.Attachments.Valid {
			attachments = e.Attachments.String
		}
		provider := ""
		if e.Provider.Valid {
			provider = e.Provider.String
		}
		var sentAt *time.Time
		if e.SentAt.Valid {
			sentAt = &e.SentAt.Time
		}

		hasAttachments := attachments != "" && attachments != "[]"

		data = append(data, map[string]interface{}{
			"id":              utils.EncodeID(int(e.ID)),
			"user_id":         utils.EncodeID(int(e.UserID)),
			"from":            e.FromEmail,
			"to":              e.ToEmail,
			"subject":         e.Subject,
			"body_preview":    bodyPreview,
			"body":            body,
			"attachments":     attachments,
			"has_attachments": hasAttachments,
			"provider":        provider,
			"status":          e.Status,
			"sent_at":         sentAt,
			"created_at":      e.CreatedAt,
		})
	}

	totalPages := (total + limit - 1) / limit

	return c.JSON(http.StatusOK, map[string]interface{}{
		"data": data,
		"pagination": map[string]interface{}{
			"page":        page,
			"limit":       limit,
			"total":       total,
			"total_pages": totalPages,
		},
	})
}

func ListEmailByTokenHandler(c echo.Context) error {
	userID := c.Get("user_id").(int64)

	emailUser, err := getUserEmail(userID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "Failed to fetch user email",
		})
	}

	err = processIncomingEmails(userID, emailUser)
	if err != nil {
		fmt.Println("Failed to process incoming emails", err)
	}
	fmt.Println("Finish refresh internal mailbox")

	var emails []Email
	err = config.DB.Select(&emails, `SELECT id, 
			is_read,
            user_id, 
            sender_email, sender_name, 
            subject, 
            preview,
            body,
            timestamp, 
            created_at, 
            updated_at FROM emails WHERE user_id = ? and email_type = "inbox" ORDER BY timestamp DESC LIMIT 10`, userID)
	if err != nil {
		fmt.Println("Failed to fetch emails", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to fetch emails"})
	}

	response := make([]EmailResponse, len(emails))
	for i, email := range emails {
		email.EmailEncodeID = utils.EncodeID(int(email.ID))
		email.UserEncodeID = utils.EncodeID(int(email.UserID))
		response[i] = EmailResponse{
			Email:        email,
			RelativeTime: formatRelativeTime(email.Timestamp),
		}
	}

	// Update last login
	err = updateLastLogin(userID)
	if err != nil {
		fmt.Println("error updateLastLogin", err)
	}

	return c.JSON(http.StatusOK, response)
}

func ListEmailByIDHandler(c echo.Context) error {
	userIDStr := c.Param("id")

	userIDDecode, err := utils.DecodeID(userIDStr)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid user ID"})
	}

	userID, err := strconv.ParseInt(strconv.Itoa(userIDDecode), 10, 64)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid user ID",
		})
	}

	emailUser, err := getUserEmail(userID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "Failed to fetch user email",
		})
	}

	err = processIncomingEmails(userID, emailUser)
	if err != nil {
		fmt.Println("Failed to process incoming emails", err)
	}
	fmt.Println("Finish refresh internal mailbox")

	var emails []Email
	err = config.DB.Select(&emails, `SELECT id, 
			is_read,
            user_id, 
            sender_email, 
			sender_name, 
            subject, 
            preview,
            body,
            timestamp,
			message_id,
			attachments, 
            created_at, 
            updated_at FROM emails WHERE user_id = ? and email_type = "inbox" ORDER BY timestamp DESC`, userID)
	if err != nil {
		fmt.Println("Failed to fetch emails", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to fetch emails"})
	}

	response := make([]EmailResponse, len(emails))
	for i, email := range emails {
		email.EmailEncodeID = utils.EncodeID(int(email.ID))
		email.UserEncodeID = utils.EncodeID(int(email.UserID))
		response[i] = EmailResponse{
			Email:        email,
			RelativeTime: formatRelativeTime(email.Timestamp),
		}
		// Convert JSON string to []string
		response[i].ListAttachments = getAttachmentURLs(email.Attachments)
	}

	return c.JSON(http.StatusOK, response)
}

func getAttachmentURLs(attachmentsJSON string) []Attachment {
	var urls []string
	attachments := make([]Attachment, len(urls))

	if attachmentsJSON != "" {
		if err := json.Unmarshal([]byte(attachmentsJSON), &urls); err != nil {
			fmt.Printf("Failed to unmarshal attachments: %v\n", err)
			return nil
		}

		for i, url := range urls {
			// Extract filename from URL path
			parts := strings.Split(url, "/")
			filename := parts[len(parts)-1]

			attachments[i] = Attachment{
				URL:         url,
				ContentType: "",
				Filename:    filename,
			}
		}
	}

	return attachments
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

// UploadAttachmentHandler handles the file upload to AWS S3
func UploadAttachmentHandler(c echo.Context) error {
	// Parse the multipart form data
	form, err := c.MultipartForm()
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid form data",
		})
	}

	// Get the file from the form data
	files := form.File["attachment"]
	if len(files) == 0 {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "No file uploaded",
		})
	}

	file := files[0]
	src, err := file.Open()
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "Failed to open attachment",
		})
	}
	defer src.Close()

	// Read the file content
	content, err := io.ReadAll(src)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "Failed to read attachment",
		})
	}

	// Generate a unique key for the file
	filename := strings.ToLower(file.Filename)
	filename = strings.ReplaceAll(filename, " ", "_")
	uniqueID := uuid.New().String()
	key := fmt.Sprintf("attachments/sent/%s_%s", uniqueID, filename)

	// Upload the file to S3
	url, err := pkg.UploadAttachment(content, key, file.Header.Get("Content-Type"))
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": fmt.Sprintf("Failed to upload file to S3: %v", err),
		})
	}

	// Return the pre-signed URL of the uploaded file
	return c.JSON(http.StatusOK, map[string]string{
		"url": url,
	})
}

// func GetInboxHandler(c echo.Context) error {
// 	// // Extract user email from context (assuming middleware sets this)
// 	// userEmail := c.Get("user_email").(string)

// 	// AWS S3 configuration
// 	bucketName := viper.GetString("S3_BUCKET_NAME") // e.g., "ses-mailsaja-received"
// 	prefix := viper.GetString("S3_PREFIX")          // e.g., "mailsaja@inbox-all/" mailsaja@inbox-all/

// 	// Initialize AWS session
// 	sess, _ := pkg.InitAWS()

// 	// Create S3 client
// 	s3Client, _ := pkg.InitS3(sess)

// 	// List objects in S3 bucket under the user's prefix
// 	listInput := &s3.ListObjectsV2Input{
// 		Bucket: aws.String(bucketName),
// 		Prefix: aws.String(prefix),
// 	}

// 	var emails []ParsedEmail

// 	err := s3Client.ListObjectsV2Pages(listInput, func(page *s3.ListObjectsV2Output, lastPage bool) bool {
// 		for _, obj := range page.Contents {
// 			// Get the object (email)
// 			getInput := &s3.GetObjectInput{
// 				Bucket: aws.String(bucketName),
// 				Key:    obj.Key,
// 			}
// 			getOutput, err := s3Client.GetObject(getInput)
// 			if err != nil {
// 				fmt.Println("Failed to get object:", err)
// 				continue
// 			}
// 			defer getOutput.Body.Close()

// 			// Read the object content
// 			buf := new(bytes.Buffer)
// 			_, err = io.Copy(buf, getOutput.Body)
// 			if err != nil {
// 				fmt.Println("Failed to read object content:", err)
// 				continue
// 			}

// 			// Parse the email
// 			emailContent := buf.String()
// 			msg, err := mail.ReadMessage(strings.NewReader(emailContent))
// 			if err != nil {
// 				fmt.Println("Failed to parse email:", err)
// 				continue
// 			}

// 			fmt.Println("msg", msg.Header)

// 			parsedEmail, err := parseEmailFromBucket(msg)
// 			if err != nil {
// 				fmt.Printf("Failed to parse email: %v\n", err)
// 				continue
// 			}

// 			emails = append(emails, *parsedEmail)
// 		}
// 		return !lastPage
// 	})
// 	if err != nil {
// 		fmt.Println("Failed to list objects:", err)
// 		return c.JSON(http.StatusInternalServerError, map[string]string{
// 			"error": "Failed to retrieve emails",
// 		})
// 	}

// 	return c.JSON(http.StatusOK, emails)
// }

// type RawEmailBatch struct {
// 	MessageIDs    []string
// 	EmailContents [][]byte
// }

// func SyncEmails() error {
// 	fmt.Println("Syncing emails...", time.Now())

// 	// AWS S3 configuration
// 	bucketName := viper.GetString("S3_BUCKET_NAME")
// 	prefix := viper.GetString("S3_PREFIX")

// 	// Initialize AWS session
// 	sess, err := pkg.InitAWS()
// 	if err != nil {
// 		return fmt.Errorf("failed to initialize AWS session: %v", err)
// 	}

// 	// Create S3 client
// 	s3Client := s3.New(sess)

// 	// Channel to send raw emails to the worker
// 	rawEmailChan := make(chan RawEmailBatch, 1000) // Buffered channel

// 	// WaitGroup to wait for workers to finish
// 	var wg sync.WaitGroup

// 	// Start worker pool
// 	numWorkers := 1 //runtime.NumCPU() * 2 // Adjust as needed
// 	for i := 0; i < numWorkers; i++ {
// 		wg.Add(1)
// 		go emailBatchWorker(i, &wg, rawEmailChan)
// 	}

// 	// List objects in S3 bucket and collect them into batches
// 	batchSize := 100 // Define batch size
// 	currentBatch := RawEmailBatch{
// 		MessageIDs:    []string{},
// 		EmailContents: [][]byte{},
// 	}

// 	err = s3Client.ListObjectsV2Pages(&s3.ListObjectsV2Input{
// 		Bucket: aws.String(bucketName),
// 		Prefix: aws.String(prefix),
// 	}, func(page *s3.ListObjectsV2Output, lastPage bool) bool {
// 		for _, obj := range page.Contents {
// 			messageID := *obj.Key
// 			if messageID == "" {
// 				continue
// 			}

// 			// Get the email object
// 			output, err := s3Client.GetObject(&s3.GetObjectInput{
// 				Bucket: aws.String(bucketName),
// 				Key:    aws.String(messageID),
// 			})
// 			if err != nil {
// 				fmt.Printf("Failed to get object %s: %v\n", messageID, err)
// 				continue
// 			}
// 			defer output.Body.Close()

// 			// Read the email content
// 			buf := new(bytes.Buffer)
// 			buf.ReadFrom(output.Body)
// 			emailContent := buf.Bytes()

// 			// Append to current batch
// 			currentBatch.MessageIDs = append(currentBatch.MessageIDs, messageID)
// 			currentBatch.EmailContents = append(currentBatch.EmailContents, emailContent)

// 			// If batch size is reached, send to worker
// 			if len(currentBatch.MessageIDs) >= batchSize {
// 				rawEmailChan <- currentBatch
// 				currentBatch = RawEmailBatch{
// 					MessageIDs:    []string{},
// 					EmailContents: [][]byte{},
// 				}
// 			}
// 		}
// 		return !lastPage
// 	})

// 	if err != nil {
// 		close(rawEmailChan)
// 		return fmt.Errorf("failed to list objects: %v", err)
// 	}

// 	// Send any remaining emails in the last batch
// 	if len(currentBatch.MessageIDs) > 0 {
// 		rawEmailChan <- currentBatch
// 	}

// 	// Close the channel to signal workers to finish
// 	close(rawEmailChan)

// 	// Wait for all workers to finish
// 	wg.Wait()

// 	fmt.Println("Sync completed.")
// 	return nil
// }

// func emailBatchWorker(workerID int, wg *sync.WaitGroup, rawEmailChan <-chan RawEmailBatch) {
// 	fmt.Println("Worker", workerID, "starting", time.Now())
// 	defer wg.Done()
// 	for batch := range rawEmailChan {
// 		fmt.Printf("Worker %d processing batch of %d emails\n", workerID, len(batch.MessageIDs))
// 		err := insertRawEmailBatch(batch)
// 		if err != nil {
// 			fmt.Printf("Worker %d: Error inserting batch: %v\n", workerID, err)
// 		}
// 	}
// 	fmt.Println("Worker", workerID, "finish", time.Now())
// 	fmt.Printf("Worker %d exiting\n", workerID)
// }

// func insertRawEmailBatch(batch RawEmailBatch) error {
// 	fmt.Println("Inserting batch of emails...", time.Now())
// 	fmt.Println("Batch size", len(batch.MessageIDs))
// 	// Prepare the SQL statement
// 	query := `
//         INSERT INTO incoming_emails (message_id, email_data, created_at, processed)
//         VALUES `
// 	valueStrings := []string{}
// 	valueArgs := []interface{}{}

// 	for i := range batch.MessageIDs {
// 		valueStrings = append(valueStrings, "(?, ?, NOW(), false)")
// 		valueArgs = append(valueArgs, batch.MessageIDs[i], batch.EmailContents[i])
// 	}

// 	query += strings.Join(valueStrings, ",")
// 	query += ";"

// 	// Execute the batch insert
// 	_, err := config.DB.Exec(query, valueArgs...)
// 	if err != nil {
// 		return fmt.Errorf("failed to insert raw email batch: %v", err)
// 	}
// 	fmt.Println("Finish batch of emails.", time.Now())
// 	return nil
// }

func SyncSentEmails() error {
	fmt.Println("Syncing sent emails...", time.Now())

	// Define the SQL query to fetch sent emails older than 7 days
	query := `
        SELECT id, attachments, timestamp
        FROM emails
        WHERE email_type = 'sent' 
          AND timestamp <= NOW() - INTERVAL 7 DAY
        ORDER BY id ASC;
    `

	var emails []Email
	err := config.DB.Select(&emails, query)
	if err != nil {
		fmt.Println("Failed to fetch sent emails:", err)
		return err
	}

	// Initialize AWS S3 session
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(viper.GetString("AWS_REGION")),
	})
	if err != nil {
		fmt.Println("Failed to create AWS session:", err)
		return err
	}

	s3Client := s3.New(sess)
	bucket := viper.GetString("AWS_S3_BUCKET")

	for _, email := range emails {
		// Parse attachments
		attachmentURLs, err := parseAttachments(email.Attachments)
		if err != nil {
			fmt.Printf("Failed to parse attachments for email ID %d: %v\n", email.ID, err)
			continue
		}

		// Flag to determine if all attachments were deleted successfully
		allDeleted := true

		for _, url := range attachmentURLs {
			key, err := extractS3KeyFromURL(url, bucket)
			if err != nil {
				fmt.Printf("Failed to extract S3 key from URL %s: %v\n", url, err)
				allDeleted = false
				break
			}

			// Delete the object from S3
			_, err = s3Client.DeleteObject(&s3.DeleteObjectInput{
				Bucket: aws.String(bucket),
				Key:    aws.String(key),
			})
			if err != nil {
				fmt.Printf("Failed to delete S3 object %s: %v\n", key, err)
				allDeleted = false
				break
			} else {
				fmt.Printf("Deleted S3 object %s\n", key)
			}
		}

		// If all attachments are deleted successfully, delete the email record
		if allDeleted {
			delQuery := `DELETE FROM emails WHERE id = ?`
			_, err := config.DB.Exec(delQuery, email.ID)
			if err != nil {
				fmt.Printf("Failed to delete email record ID %d: %v\n", email.ID, err)
			} else {
				fmt.Printf("Deleted email record ID %d from database\n", email.ID)
			}
		} else {
			fmt.Printf("Skipping deletion of email record ID %d due to attachment deletion failure\n", email.ID)
		}
	}

	fmt.Println("Finished syncing sent emails", time.Now())
	return nil
}

// OLD SYNC EMAILS
func SyncEmails() error {
	fmt.Println("Syncing emails...", time.Now())
	// AWS S3 configuration
	bucketName := viper.GetString("S3_BUCKET_NAME")
	prefix := viper.GetString("S3_PREFIX")

	fmt.Println("bucketName", bucketName)
	fmt.Println("prefix", prefix)
	fmt.Println(viper.GetString("AWS_REGION"))

	// Initialize AWS session
	sess, err := pkg.InitAWS()
	if err != nil {
		return fmt.Errorf("failed to initialize AWS session: %v", err)
	}

	// Create S3 client
	s3Client := s3.New(sess)

	// List objects in S3 bucket
	err = s3Client.ListObjectsV2Pages(&s3.ListObjectsV2Input{
		Bucket: aws.String(bucketName),
		Prefix: aws.String(prefix),
	}, func(page *s3.ListObjectsV2Output, lastPage bool) bool {
		fmt.Println("Processing ", len(page.Contents))
		for _, obj := range page.Contents {
			messageID := *obj.Key
			if messageID == "" {
				continue
			}
			fmt.Println("messageID", messageID)

			// Get the email object
			output, err := s3Client.GetObject(&s3.GetObjectInput{
				Bucket: aws.String(bucketName),
				Key:    aws.String(messageID),
			})
			if err != nil {
				fmt.Printf("Failed to get object %s: %v\n", messageID, err)
				continue
			}
			defer output.Body.Close()

			// Read the email content
			buf := new(bytes.Buffer)
			buf.ReadFrom(output.Body)
			emailContent := buf.Bytes()

			if emailContent == nil {
				fmt.Println("emailContent is empty")
				continue
			}
			// Store the raw email in the database
			err = storeRawEmail(s3Client, messageID, emailContent)
			if err != nil {
				fmt.Printf("Failed to store raw email %s: %v\n", messageID, err)
				continue
			}

			// Delete the email object from S3 after storing
			_, err = s3Client.DeleteObject(&s3.DeleteObjectInput{
				Bucket: aws.String(bucketName),
				Key:    aws.String(messageID),
			})
			if err != nil {
				fmt.Printf("Failed to delete object %s: %v\n", messageID, err)
				continue
			}
		}
		return !lastPage
	})

	if err != nil {
		return fmt.Errorf("failed to list objects: %v", err)
	}

	fmt.Println("Sync completed.", time.Now())
	return nil
}

func storeRawEmail(s3Client *s3.S3, messageID string, emailContent []byte) error {
	// Extract recipient email to associate with user
	// fmt.Println("start extract", time.Now())
	sendEmailTo, dateEmail, err := extractRecipientEmail(emailContent)
	if err != nil {
		return err
	}
	// fmt.Println("finish extract", time.Now())
	fmt.Println("sendEmailTo", sendEmailTo)
	fmt.Println("dateEmail", dateEmail)

	// if sendEmailTo not found delete
	// Get the user ID from the email address
	var userID int64
	err = config.DB.Get(&userID, `
		SELECT id 
		FROM users 
		WHERE email = ?`, sendEmailTo)
	fmt.Println("userID storeRawEmail", userID)
	if err != nil {
		fmt.Printf("Failed to get user ID for email %s: %v\n", sendEmailTo, err)
		fmt.Println("User not registered in our Database")
		bucketName := viper.GetString("S3_BUCKET_NAME")
		// Delete the email object from S3 after storing
		err := pkg.DeleteS3ByMessageID(s3Client, bucketName, messageID)
		if err != nil {
			fmt.Printf("Failed to delete object %s: %v\n", messageID, err)
			return err
		}
	}

	fmt.Println("start insert", time.Now())
	// Insert raw email into the raw_emails table
	_, err = config.DB.Exec(`
	    INSERT INTO incoming_emails (
			email_send_to,
	        message_id,
	        email_data,
	        created_at,
	        processed,
			email_date
	    ) VALUES (?, ?, ?, NOW(), false, ?)
	`, sendEmailTo, messageID, emailContent, dateEmail)
	if err != nil {
		fmt.Println("ERROR INSERT RAW EMAIL", err)

		if strings.Contains(err.Error(), "Incorrect datetime value") {
			fmt.Println("Error Incorrect datetime value", sendEmailTo)
			// Set dateEmail to today's date if there's an error
			dateEmail = time.Now()
			_, err = config.DB.Exec(`
                INSERT INTO incoming_emails (
                    email_send_to,
                    message_id,
                    email_data,
                    created_at,
                    processed,
                    email_date
                ) VALUES (?, ?, ?, NOW(), false, ?)
            `, sendEmailTo, messageID, emailContent, dateEmail)
			if err != nil {
				return fmt.Errorf("storeRawEmail: failed to insert raw email: %v", err)
			}
		} else {
			return fmt.Errorf("storeRawEmail: failed to insert raw email: %v", err)
		}
	}
	// err = processIncomingEmails(sendEmailTo)
	// fmt.Println("Err Process Incoming Emails", err)
	fmt.Println("finish insert", time.Now())

	return nil
}

func extractRecipientEmail(emailContent []byte) (string, time.Time, error) {
	env, err := enmime.ReadEnvelope(bytes.NewReader(emailContent))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to parse email: %v", err)
	}

	dateT, _ := env.Date()

	// Try to get the "To" address
	toAddresses := parseAddresses(env.GetHeader("To"))
	if len(toAddresses) == 0 || (len(toAddresses) == 1 && toAddresses[0].Address == "Undisclosed recipients") {
		// If "To" is empty or contains "Undisclosed recipients", try to extract from "Received" headers
		receivedHeaders := env.GetHeaderValues("Received")
		for _, receivedHeader := range receivedHeaders {
			if strings.Contains(receivedHeader, "for ") {
				parts := strings.Split(receivedHeader, "for ")
				if len(parts) > 1 {
					recipientPart := strings.TrimSpace(parts[1])
					recipientParts := strings.SplitN(recipientPart, ";", 2)
					if len(recipientParts) > 1 {
						recipient := strings.TrimSpace(recipientParts[0])
						dateStr := strings.TrimSpace(recipientParts[1])
						// Remove extra text " (UTC)" if present
						dateStr = strings.TrimSuffix(dateStr, " (UTC)")
						dateT, err := time.Parse(time.RFC1123Z, dateStr)
						if err != nil {
							fmt.Println("Failed to parse date:", err)
							return "", time.Time{}, fmt.Errorf("failed to parse date: %v", err)
						}
						fmt.Println("Received for recipient", recipient)
						return recipient, dateT, nil
					}
				}
			}
		}
		fmt.Println("extractRecipientEmail - Failed to parse TO and Received headers")
		return "", time.Time{}, fmt.Errorf("failed to parse recipient addresses")
	} else {
		fmt.Println("extractRecipientEmail - TO", toAddresses)
	}

	toFrom := parseAddresses(env.GetHeader("From"))
	if len(toFrom) == 0 {
		fmt.Println("extractRecipientEmail - Failed to parse FROM")
	} else {
		fmt.Println("extractRecipientEmail - FROM", toFrom)
	}

	return toAddresses[0].Address, dateT, nil
}

func SyncBucketInboxHandler(c echo.Context) error {
	// AWS S3 configuration
	bucketName := viper.GetString("S3_BUCKET_NAME")
	prefix := viper.GetString("S3_PREFIX")

	// Initialize AWS session
	sess, err := pkg.InitAWS()
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to initialize AWS session"})
	}

	// Create S3 client
	s3Client, _ := pkg.InitS3(sess)

	stats := SyncStats{}

	emails := []PEmail{}

	// List objects in S3 bucket
	err = s3Client.ListObjectsV2Pages(&s3.ListObjectsV2Input{
		Bucket: aws.String(bucketName),
		Prefix: aws.String(prefix),
	}, func(page *s3.ListObjectsV2Output, lastPage bool) bool {
		for _, obj := range page.Contents {
			stats.TotalEmails++
			messageID := *obj.Key
			if messageID == "" {
				stats.SkippedEmails++
				continue
			}
			// Get the email object
			output, err := s3Client.GetObject(&s3.GetObjectInput{
				Bucket: aws.String(bucketName),
				Key:    aws.String(messageID),
			})
			if err != nil {
				fmt.Printf("Failed to get object %s: %v\n", messageID, err)
				stats.FailedEmails++
				continue
			}
			defer output.Body.Close()

			// Read the email content
			buf := new(bytes.Buffer)
			buf.ReadFrom(output.Body)
			emailContent := buf.Bytes()

			// Parse the email
			env, err := enmime.ReadEnvelope(bytes.NewReader(emailContent))
			if err != nil {
				fmt.Printf("Failed to parse email %s: %v\n", messageID, err)
				stats.FailedEmails++
				continue
			}

			dateT, _ := env.Date()

			// Extract email information
			email := &PEmail{
				ID:       messageID,
				From:     parseAddresses(env.GetHeader("From")),
				To:       parseAddresses(env.GetHeader("To")),
				Cc:       parseAddresses(env.GetHeader("Cc")),
				Bcc:      parseAddresses(env.GetHeader("Bcc")),
				Subject:  env.GetHeader("Subject"),
				Date:     dateT,
				TextBody: env.Text,
				HTMLBody: env.HTML,
			}

			var attachmentURLs []string
			// Handle attachments
			for _, att := range env.Attachments {
				attachmentKey := fmt.Sprintf("attachments/%s/%s", email.ID, att.FileName)
				attachmentURL, err := pkg.UploadAttachment(att.Content, attachmentKey, att.ContentType)
				if err != nil {
					log.Printf("Failed to upload attachment: %v", err)
					continue
				}

				attachmentURLs = append(attachmentURLs, attachmentURL)
			}

			emails = append(emails, *email)
			attachmentsJSON, _ := json.Marshal(attachmentURLs)

			var preview string
			var bodyEmail string
			if email.HTMLBody != "" {
				bodyEmail = email.HTMLBody
			} else {
				bodyEmail = email.TextBody
			}

			// Get a 25-character preview of the body content
			preview = generatePreview(email.TextBody, email.HTMLBody)

			if email.ID == "" {
				email.ID = "NOTVALID"
			}

			sendEmailTo := email.To[0].Address

			for _, emailFrom := range email.From {
				var userID int64
				err = config.DB.Get(&userID, `
				SELECT id 
				FROM users 
				WHERE email = ?`, sendEmailTo)
				if err != nil {
					fmt.Println("Failed to get user ID", err)
					// TODO: berarti tidak ditemukan user nya dikita, mau diapakan? diterima oleh support kalo ada email masuk ke user yg tidak terdaftar kah?
				}

				// Insert into emails table
				_, err = config.DB.Exec(`
					INSERT INTO emails (
						user_id,
						sender_email,
						sender_name,
						subject,
						preview,
						body,
						email_type,
						attachments,
						message_id,
						timestamp,
						created_at,
						updated_at
					) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())
					`,
					userID,
					emailFrom.Address,
					emailFrom.Name,
					email.Subject,
					preview,
					bodyEmail,
					"inbox", // Set email_type as needed
					string(attachmentsJSON),
					email.ID,
					email.Date,
				)
				if err != nil {
					fmt.Printf("Failed to insert email %s into DB: %v\n", messageID, err)
					stats.FailedEmails++
					continue
				}

				stats.NewEmails++
			}
		}
		return !lastPage
	})

	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to list objects"})
	}

	return c.JSON(http.StatusOK, stats)
}

func parseAddresses(addresses string) []EmailAddress {
	var result []EmailAddress
	parsed, err := enmime.ParseAddressList(addresses)
	if err != nil {
		return result
	}
	for _, addr := range parsed {
		if addr.Name == "" {
			// Extract the name from the email address before the '@' symbol
			parts := strings.Split(addr.Address, "@")
			if len(parts) > 0 {
				addr.Name = parts[0]
			} else {
				addr.Name = addr.Address
			}
		}
		result = append(result, EmailAddress{
			Name:    addr.Name,
			Address: addr.Address,
		})
	}
	return result
}

func sanitizeText(s string) string {
	// Remove zero-width and other invisible characters using Unicode ranges
	s = regexp.MustCompile(`[\x{200B}-\x{200D}\x{FEFF}]`).ReplaceAllString(s, "")

	// Remove emojis and other special characters
	s = regexp.MustCompile(`[\x{1F300}-\x{1F6FF}]`).ReplaceAllString(s, "")

	// Only keep printable ASCII characters
	var result strings.Builder
	for _, r := range s {
		if unicode.IsPrint(r) && r < 128 {
			result.WriteRune(r)
		}
	}

	return strings.TrimSpace(result.String())
}

func generatePreview(plainText string, htmlBody string) string {
	var text string
	if plainText != "" {
		text = html2text(plainText)
	} else {
		text = html2text(htmlBody)
	}

	// Sanitize and normalize the text
	text = sanitizeText(text)

	// Generate a safe preview length
	runeCount := 0
	for i := range text {
		if runeCount >= 200 {
			return text[:i] + "..."
		}
		runeCount++
	}
	return text
}

// func generatePreview(plainText string, htmlBody string) string {
// 	var text string
// 	// fmt.Println("plainText", plainText)
// 	if plainText != "" {
// 		text = html2text(plainText)
// 	} else {
// 		// Convert HTML to plain text
// 		text = html2text(htmlBody)
// 	}
// 	// Generate a short preview
// 	if len(text) > 200 {
// 		return text[:200] + "..."
// 	}
// 	return text
// }

// // Simple HTML to text converter (you might want to use a proper library)
func html2text(contentHTML string) string {
	text := contentHTML
	text = strings.ReplaceAll(text, "<br>", "\n")
	text = strings.ReplaceAll(text, "<br/>", "\n")
	text = strings.ReplaceAll(text, "<br />", "\n")
	text = strings.ReplaceAll(text, "</p>", "\n")
	text = strings.ReplaceAll(text, "</div>", "\n")

	// Remove all other HTML tags
	re := regexp.MustCompile("<[^>]*>")
	text = re.ReplaceAllString(text, "")

	// Decode HTML entities
	text = html.UnescapeString(text)

	// Remove zero-width spaces
	text = strings.ReplaceAll(text, "\u200B", "")
	text = strings.ReplaceAll(text, "\u200C", "")
	text = strings.ReplaceAll(text, "\u200D", "")
	text = strings.ReplaceAll(text, "\xE2\x80", "")
	text = strings.ReplaceAll(text, "\xE2", "")

	// Remove non-printable characters
	text = removeNonPrintable(text)

	return strings.TrimSpace(text)
}

func removeNonPrintable(s string) string {
	var buf bytes.Buffer
	for _, r := range s {
		if unicode.IsPrint(r) {
			buf.WriteRune(r)
		}
	}
	return buf.String()
}

func updateLimitSentEmails(userID int64) error {
	// Increment counter
	_, err := config.DB.Exec(`
        UPDATE users 
        SET sent_emails = sent_emails + 1,
		last_login = NOW()
        WHERE id = ?`, userID)
	if err != nil {
		return err
	}

	return nil
}

func updateIsRead(emailID string) error {
	_, err := config.DB.Exec(`
		UPDATE emails 
		SET is_read = TRUE
		WHERE id = ?`, emailID)
	if err != nil {
		return err
	}

	return nil
}

func updateLastLogin(userID int64) error {
	// Update the user's last login time
	_, err := config.DB.Exec("UPDATE users SET last_login = ? WHERE id = ?", time.Now(), userID)
	if err != nil {
		return err
	}

	return nil
}

func processIncomingEmails(userID int64, emailSendTo string) error {
	fmt.Println("START processIncomingEmails", time.Now())

	err := process10Emails(userID, emailSendTo)
	if err != nil {
		fmt.Println("Failed to process 10 emails", err)
	}

	// Fetch unprocessed emails for the user from incoming_emails table
	var rawEmails []struct {
		ID        int64     `db:"id"`
		MessageID string    `db:"message_id"`
		EmailData []byte    `db:"email_data"`
		CreatedAt time.Time `db:"created_at"`
	}
	err = config.DB.Select(&rawEmails, `
        SELECT id, message_id, email_data, created_at
        FROM incoming_emails
        WHERE email_send_to = ? AND processed = FALSE
    `, emailSendTo)
	if err != nil {
		return fmt.Errorf("failed to fetch raw emails: %v", err)
	}

	fmt.Println("Start processIncomingEmails", len(rawEmails))
	for _, rawEmail := range rawEmails {
		// Parse the email content
		env, err := enmime.ReadEnvelope(bytes.NewReader(rawEmail.EmailData))
		if err != nil {
			fmt.Printf("Failed to parse email %s: %v\n", rawEmail.MessageID, err)
			continue
		}

		dateT, _ := env.Date()
		if dateT == (time.Time{}) {
			dateT = time.Now()
		}

		// Extract email information
		email := &PEmail{
			ID:       rawEmail.MessageID,
			From:     parseAddresses(env.GetHeader("From")),
			To:       parseAddresses(env.GetHeader("To")),
			Cc:       parseAddresses(env.GetHeader("Cc")),
			Bcc:      parseAddresses(env.GetHeader("Bcc")),
			Subject:  env.GetHeader("Subject"),
			Date:     dateT,
			TextBody: env.Text,
			HTMLBody: env.HTML,
		}

		// Handle attachments
		var attachmentURLs []string
		for _, att := range env.Attachments {
			attachmentKey := fmt.Sprintf("attachments/%s/%s", email.ID, att.FileName)
			attachmentURL, err := pkg.UploadAttachment(att.Content, attachmentKey, att.ContentType)
			if err != nil {
				log.Printf("Failed to upload attachment: %v", err)
				continue
			}
			attachmentURLs = append(attachmentURLs, attachmentURL)
		}
		attachmentsJSON, _ := json.Marshal(attachmentURLs)

		// Select the email body and generate a preview
		var bodyEmail string
		if email.HTMLBody != "" {
			bodyEmail = email.HTMLBody
		} else {
			bodyEmail = email.TextBody
		}
		preview := generatePreview(email.TextBody, email.HTMLBody)
		fmt.Println("preview", preview)
		fmt.Println("email.From", email.From)

		// Extract email information
		fromAddresses := parseAddresses(env.GetHeader("From"))
		if len(fromAddresses) == 0 {
			// Handle case where From is empty
			fromAddresses = append(fromAddresses, EmailAddress{
				Name:    "Unknown Sender",
				Address: "no-reply@example.com",
			})
		}

		// Get the user ID from the email address
		var userID int64
		err = config.DB.Get(&userID, `
            SELECT id 
            FROM users 
            WHERE email = ?`, emailSendTo)
		if err != nil {
			fmt.Printf("Failed to get user ID for email %s: %v\n", emailSendTo, err)
			continue
		}

		// Insert the processed email into the emails table
		_, err = config.DB.Exec(`
            INSERT INTO emails (
                user_id,
                sender_email,
                sender_name,
                subject,
                preview,
                body,
                email_type,
                attachments,
                message_id,
                timestamp,
                created_at,
                updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())
        `,
			userID,
			fromAddresses[0].Address,
			fromAddresses[0].Name,
			email.Subject,
			preview,
			bodyEmail,
			"inbox", // Set email_type as needed
			string(attachmentsJSON),
			email.ID,
			email.Date,
		)
		if err != nil {
			fmt.Printf("processIncomingEmails: Failed to insert email %s into DB: %v\n", email.ID, err)
			continue
		}

		// // Mark the raw email as processed
		// _, err = config.DB.Exec(`
		//     UPDATE incoming_emails
		//     SET processed = TRUE, processed_at = NOW()
		//     WHERE id = ?
		// `, rawEmail.ID)
		// if err != nil {
		// 	fmt.Printf("Failed to update raw email %s: %v\n", rawEmail.MessageID, err)
		// 	continue
		// }
		// Delete the raw email after successful processing
		_, err = config.DB.Exec(`
		DELETE FROM incoming_emails
		WHERE id = ?
		`, rawEmail.ID)
		if err != nil {
			fmt.Printf("Failed to delete raw email %s: %v\n", rawEmail.MessageID, err)
			continue
		}
	}
	fmt.Println("Finish processIncomingEmails", time.Now())

	return nil
}

func process10Emails(userID int64, emailSendTo string) error {
	fmt.Println("START process10Emails", time.Now())

	// Check the number of emails for the user
	var emailCount int
	err := config.DB.Get(&emailCount, `
		SELECT COUNT(*) 
		FROM emails 
		WHERE user_id = ? and email_type = 'inbox'
	`, userID)
	if err != nil {
		fmt.Printf("Failed to count emails for user %d: %v\n", userID, err)
		return err
	}

	// Delete the oldest email if the user has 10 emails
	if emailCount > 10 {
		fmt.Println("Deleting oldest email for user", userID)
		// Select the ID of the oldest email for the user
		var oldestEmailID int64
		err = config.DB.Get(&oldestEmailID, `
			SELECT id 
			FROM emails 
			WHERE user_id = ? and email_type = 'inbox'
			ORDER BY created_at ASC 
			LIMIT 1
		`, userID)
		if err != nil {
			fmt.Printf("Failed to select oldest email for user %d: %v\n", userID, err)
			return err
		}

		// Delete the oldest email
		_, err = config.DB.Exec(`
		DELETE FROM emails 
		WHERE id = ?
		`, oldestEmailID)
		if err != nil {
			fmt.Printf("Failed to delete oldest email for user %d: %v\n", userID, err)
			return err
		}
	}

	fmt.Println("Finish process10Emails", time.Now())

	return nil
}

func getUserEmail(userID int64) (string, error) {
	var emailUser string
	err := config.DB.Get(&emailUser, `
        SELECT email 
        FROM users 
        WHERE id = ? LIMIT 1`, userID)
	if err != nil {
		fmt.Println("Failed to fetch user email:", err)
		return "", err
	}
	return emailUser, nil
}

func getUserByEmail(email string) (int, error) {
	var userID int
	err := config.DB.Get(&userID, `
        SELECT id 
        FROM users 
        WHERE email = ? LIMIT 1`, email)
	if err != nil {
		fmt.Println("Failed to fetch user email:", err)
		return 0, err
	}
	return userID, nil
}

// parseAttachments parses the attachments field into a slice of URLs
// Assuming attachments are stored as a JSON array of strings
func parseAttachments(attachments string) ([]string, error) {
	var urls []string
	err := json.Unmarshal([]byte(attachments), &urls)
	if err != nil {
		return nil, err
	}
	return urls, nil
}

// extractS3KeyFromURL extracts the S3 object key from the given URL
func extractS3KeyFromURL(url, bucket string) (string, error) {
	// Example URL: https://your-bucket.s3.amazonaws.com/path/to/object
	prefix := fmt.Sprintf("https://%s.s3.amazonaws.com/", bucket)
	if !strings.HasPrefix(url, prefix) {
		return "", fmt.Errorf("URL does not match bucket prefix")
	}
	return strings.TrimPrefix(url, prefix), nil
}

// GetUserSentEmailsHandler returns the current user's sent emails
func GetUserSentEmailsHandler(c echo.Context) error {
	userID := c.Get("user_id").(int64)

	// Pagination
	page, _ := strconv.Atoi(c.QueryParam("page"))
	if page < 1 {
		page = 1
	}
	limit, _ := strconv.Atoi(c.QueryParam("limit"))
	if limit < 1 || limit > 100 {
		limit = 20
	}
	offset := (page - 1) * limit

	// Search filter
	search := c.QueryParam("search")

	// Build query
	var args []interface{}
	whereClause := "user_id = ?"
	args = append(args, userID)

	if search != "" {
		whereClause += " AND (to_email LIKE ? OR subject LIKE ?)"
		searchPattern := "%" + search + "%"
		args = append(args, searchPattern, searchPattern)
	}

	// Get total count
	var total int
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM sent_emails WHERE %s", whereClause)
	err := config.DB.Get(&total, countQuery, args...)
	if err != nil {
		fmt.Println("Error counting sent emails:", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
	}

	// Get sent emails
	args = append(args, limit, offset)
	query := fmt.Sprintf(`
		SELECT id, user_id, from_email, to_email, subject, body_preview, status, sent_at, created_at,
		       CASE WHEN attachments IS NOT NULL AND attachments != '' AND attachments != '[]' THEN 1 ELSE 0 END as has_attachments
		FROM sent_emails
		WHERE %s
		ORDER BY COALESCE(sent_at, created_at) DESC
		LIMIT ? OFFSET ?
	`, whereClause)

	type SentEmailRow struct {
		ID             int64      `db:"id"`
		UserID         int64      `db:"user_id"`
		FromEmail      string     `db:"from_email"`
		ToEmail        string     `db:"to_email"`
		Subject        string     `db:"subject"`
		BodyPreview    *string    `db:"body_preview"`
		Status         string     `db:"status"`
		SentAt         *time.Time `db:"sent_at"`
		CreatedAt      time.Time  `db:"created_at"`
		HasAttachments int        `db:"has_attachments"`
	}

	var emails []SentEmailRow
	err = config.DB.Select(&emails, query, args...)
	if err != nil {
		fmt.Println("Error fetching sent emails:", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
	}

	// Build response
	data := make([]SentEmail, 0)
	for _, e := range emails {
		bodyPreview := ""
		if e.BodyPreview != nil {
			bodyPreview = *e.BodyPreview
		}
		data = append(data, SentEmail{
			ID:             utils.EncodeID(int(e.ID)),
			FromEmail:      e.FromEmail,
			ToEmail:        e.ToEmail,
			Subject:        e.Subject,
			BodyPreview:    bodyPreview,
			Status:         e.Status,
			SentAt:         e.SentAt,
			CreatedAt:      e.CreatedAt,
			HasAttachments: e.HasAttachments == 1,
		})
	}

	totalPages := (total + limit - 1) / limit

	return c.JSON(http.StatusOK, UserSentEmailsResponse{
		Data: data,
		Pagination: PaginationResponse{
			Page:       page,
			Limit:      limit,
			Total:      total,
			TotalPages: totalPages,
		},
	})
}

// GetUserSentEmailDetailHandler returns a single sent email detail for the authenticated user
// GET /email/sent/detail/:id
func GetUserSentEmailDetailHandler(c echo.Context) error {
	userID := c.Get("user_id").(int64)

	// Decode email ID
	emailIDParam := c.Param("id")
	emailID, err := utils.DecodeID(emailIDParam)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid email ID",
		})
	}

	// Get sent email from database (only if belongs to user)
	type SentEmailDetail struct {
		ID          int64          `db:"id"`
		UserID      int64          `db:"user_id"`
		FromEmail   string         `db:"from_email"`
		ToEmail     string         `db:"to_email"`
		Subject     string         `db:"subject"`
		BodyPreview sql.NullString `db:"body_preview"`
		Body        sql.NullString `db:"body"`
		Attachments sql.NullString `db:"attachments"`
		Status      string         `db:"status"`
		SentAt      sql.NullTime   `db:"sent_at"`
		CreatedAt   time.Time      `db:"created_at"`
	}

	var email SentEmailDetail
	err = config.DB.Get(&email, `
		SELECT id, user_id, from_email, to_email, subject, body_preview, body,
		       attachments, status, sent_at, created_at
		FROM sent_emails
		WHERE id = ? AND user_id = ?
	`, emailID, userID)

	if err != nil {
		if err == sql.ErrNoRows {
			return c.JSON(http.StatusNotFound, map[string]string{
				"error": "Email not found",
			})
		}
		fmt.Println("Error fetching sent email detail:", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "Internal server error",
		})
	}

	// Build response
	bodyPreview := ""
	if email.BodyPreview.Valid {
		bodyPreview = email.BodyPreview.String
	}
	body := ""
	if email.Body.Valid {
		body = email.Body.String
	}
	attachments := ""
	if email.Attachments.Valid {
		attachments = email.Attachments.String
	}
	var sentAt *time.Time
	if email.SentAt.Valid {
		sentAt = &email.SentAt.Time
	}

	hasAttachments := attachments != "" && attachments != "[]"

	response := map[string]interface{}{
		"id":              utils.EncodeID(int(email.ID)),
		"from":            email.FromEmail,
		"to":              email.ToEmail,
		"subject":         email.Subject,
		"body_preview":    bodyPreview,
		"body":            body,
		"attachments":     attachments,
		"has_attachments": hasAttachments,
		"status":          email.Status,
		"sent_at":         sentAt,
		"created_at":      email.CreatedAt,
	}

	return c.JSON(http.StatusOK, response)
}

// SaveSentEmail saves a sent email to the sent_emails table
func SaveSentEmail(userID int64, fromEmail, toEmail, subject, body string, attachments []string, provider, providerMsgID, status string) error {
	// Create preview
	bodyPreview := body
	if len(bodyPreview) > 500 {
		bodyPreview = bodyPreview[:500]
	}

	// Convert attachments to JSON
	var attachmentsJSON *string
	if len(attachments) > 0 {
		jsonBytes, err := json.Marshal(attachments)
		if err == nil {
			str := string(jsonBytes)
			attachmentsJSON = &str
		}
	}

	_, err := config.DB.Exec(`
		INSERT INTO sent_emails (user_id, from_email, to_email, subject, body_preview, body, attachments, provider, provider_message_id, status, sent_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())
	`, userID, fromEmail, toEmail, subject, bodyPreview, body, attachmentsJSON, provider, providerMsgID, status)

	return err
}
