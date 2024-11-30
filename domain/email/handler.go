package email

import (
	"bytes"
	"email-platform/config"
	"email-platform/domain/user"
	"email-platform/pkg"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/mail"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/ses"
	"github.com/labstack/echo/v4"
	"github.com/spf13/viper"
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
		attachmentsStr = attachmentsStr + "," + attachment.Filename + ","
	}

	// Initialize AWS session
	sess, _ := pkg.InitAWS()

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

	// Send email via SES
	sesClient := ses.New(sess)

	input := &ses.SendEmailInput{
		Destination: &ses.Destination{
			ToAddresses: []*string{aws.String(req.To)},
		},
		Message: &ses.Message{
			Body: &ses.Body{
				Text: &ses.Content{
					Charset: aws.String("UTF-8"),
					Data:    aws.String(req.Body),
				},
			},
			Subject: &ses.Content{
				Charset: aws.String("UTF-8"),
				Data:    aws.String(req.Subject),
			},
		},
		Source: aws.String(userEmail),
	}

	_, err := sesClient.SendEmail(input)
	if err != nil {
		fmt.Println("Failed to send email", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "Failed to send email",
		})
	}

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

func GetInboxHandler(c echo.Context) error {
	// // Extract user email from context (assuming middleware sets this)
	// userEmail := c.Get("user_email").(string)

	// AWS S3 configuration
	bucketName := viper.GetString("S3_BUCKET_NAME") // e.g., "ses-mailsaja-received"
	prefix := viper.GetString("S3_PREFIX")          // e.g., "mailsaja@inbox-all/" mailsaja@inbox-all/

	// Initialize AWS session
	sess, _ := pkg.InitAWS()

	// Create S3 client
	s3Client, _ := pkg.InitS3(sess)

	// List objects in S3 bucket under the user's prefix
	listInput := &s3.ListObjectsV2Input{
		Bucket: aws.String(bucketName),
		Prefix: aws.String(prefix),
	}

	var emails []ParsedEmail

	err := s3Client.ListObjectsV2Pages(listInput, func(page *s3.ListObjectsV2Output, lastPage bool) bool {
		for _, obj := range page.Contents {
			// Get the object (email)
			getInput := &s3.GetObjectInput{
				Bucket: aws.String(bucketName),
				Key:    obj.Key,
			}
			getOutput, err := s3Client.GetObject(getInput)
			if err != nil {
				fmt.Println("Failed to get object:", err)
				continue
			}
			defer getOutput.Body.Close()

			// Read the object content
			buf := new(bytes.Buffer)
			_, err = io.Copy(buf, getOutput.Body)
			if err != nil {
				fmt.Println("Failed to read object content:", err)
				continue
			}

			// Parse the email
			emailContent := buf.String()
			msg, err := mail.ReadMessage(strings.NewReader(emailContent))
			if err != nil {
				fmt.Println("Failed to parse email:", err)
				continue
			}

			fmt.Println("msg", msg.Header)

			parsedEmail, err := parseEmailFromBucket(msg)
			if err != nil {
				fmt.Printf("Failed to parse email: %v\n", err)
				continue
			}

			emails = append(emails, *parsedEmail)
		}
		return !lastPage
	})
	if err != nil {
		fmt.Println("Failed to list objects:", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "Failed to retrieve emails",
		})
	}

	return c.JSON(http.StatusOK, emails)
}

func SyncBucketInboxHandler(c echo.Context) error {
	userEmail := c.Get("user_email").(string)
	userID := c.Get("user_id").(int64)

	// AWS S3 configuration
	bucketName := viper.GetString("S3_BUCKET_NAME")
	prefix := fmt.Sprintf("%s/", userEmail)

	// Initialize AWS session
	sess, err := pkg.InitAWS()
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to initialize AWS session"})
	}

	// Create S3 client
	s3Client, _ := pkg.InitS3(sess)

	stats := SyncStats{}

	// Fetch existing message IDs
	var existingMessageIDs []string
	err = config.DB.Select(&existingMessageIDs, "SELECT message_id FROM emails WHERE user_id = ?", userID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to fetch existing emails"})
	}
	existingMessages := make(map[string]bool)
	for _, id := range existingMessageIDs {
		existingMessages[id] = true
	}

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

			// Check if email already exists
			if existingMessages[messageID] {
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

			// Read email content
			emailContent, err := io.ReadAll(output.Body)
			if err != nil {
				fmt.Printf("Failed to read email %s: %v\n", messageID, err)
				stats.FailedEmails++
				continue
			}

			// Parse email
			msg, err := mail.ReadMessage(bytes.NewReader(emailContent))
			if err != nil {
				fmt.Printf("Failed to parse email %s: %v\n", messageID, err)
				stats.FailedEmails++
				continue
			}

			// Parse email into structured data
			parsedEmail, err := parseEmailFromBucket(msg)
			if err != nil {
				fmt.Printf("Failed to parse email content %s: %v\n", messageID, err)
				stats.FailedEmails++
				continue
			}

			// Prepare data for insertion
			senderName, senderEmail := parseEmailAddress(parsedEmail.From)
			preview := generatePreview(parsedEmail.PlainText, parsedEmail.Body)
			attachmentsJSON, err := json.Marshal(parsedEmail.Attachments)
			if err != nil {
				fmt.Printf("Failed to marshal attachments for email %s: %v\n", messageID, err)
				stats.FailedEmails++
				continue
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
				senderEmail,
				senderName,
				parsedEmail.Subject,
				preview,
				parsedEmail.Body,
				"", // Set email_type as needed
				string(attachmentsJSON),
				parsedEmail.MessageID,
				parsedEmail.Date,
			)
			if err != nil {
				fmt.Printf("Failed to insert email %s into DB: %v\n", messageID, err)
				stats.FailedEmails++
				continue
			}

			// Delete the object from S3
			_, err = s3Client.DeleteObject(&s3.DeleteObjectInput{
				Bucket: aws.String(bucketName),
				Key:    aws.String(messageID),
			})
			if err != nil {
				fmt.Printf("Failed to delete object %s from S3: %v\n", messageID, err)
				stats.FailedEmails++
				continue
			}

			stats.NewEmails++
		}
		return !lastPage
	})

	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to list objects"})
	}

	return c.JSON(http.StatusOK, stats)
}

// func ProcessEmailsFromS3() error {
// 	// AWS S3 configuration
// 	bucketName := viper.GetString("S3_BUCKET_NAME")
// 	prefix := viper.GetString("S3_PREFIX")

// 	// Initialize AWS session
// 	sess, _ := pkg.InitAWS()

// 	// Create S3 client
// 	s3Client, _ := pkg.InitS3(sess)

// 	// List objects in S3 bucket under the given prefix
// 	listInput := &s3.ListObjectsV2Input{
// 		Bucket: aws.String(bucketName),
// 		Prefix: aws.String(prefix),
// 	}

// 	err := s3Client.ListObjectsV2Pages(listInput, func(page *s3.ListObjectsV2Output, lastPage bool) bool {
// 		for _, obj := range page.Contents {
// 			messageID := *obj.Key

// 			// Get the object (email)
// 			getOutput, err := s3Client.GetObject(&s3.GetObjectInput{
// 				Bucket: aws.String(bucketName),
// 				Key:    aws.String(messageID),
// 			})
// 			if err != nil {
// 				fmt.Printf("Failed to get object %s: %v\n", messageID, err)
// 				continue
// 			}
// 			defer getOutput.Body.Close()

// 			// Read the object content
// 			emailContent, err := io.ReadAll(getOutput.Body)
// 			if err != nil {
// 				fmt.Printf("Failed to read object content for %s: %v\n", messageID, err)
// 				continue
// 			}

// 			// Parse the email
// 			msg, err := mail.ReadMessage(bytes.NewReader(emailContent))
// 			if err != nil {
// 				fmt.Printf("Failed to parse email %s: %v\n", messageID, err)
// 				continue
// 			}

// 			// Parse email into structured data
// 			parsedEmail, err := parseEmailFromBucket(msg)
// 			if err != nil {
// 				fmt.Printf("Failed to parse email content %s: %v\n", messageID, err)
// 				continue
// 			}

// 			// Insert into messages table
// 			err = insertEmailToDB(parsedEmail)
// 			if err != nil {
// 				fmt.Printf("Failed to insert email into DB %s: %v\n", messageID, err)
// 				continue
// 			}

// 			// Delete the object from S3
// 			_, err = s3Client.DeleteObject(&s3.DeleteObjectInput{
// 				Bucket: aws.String(bucketName),
// 				Key:    aws.String(messageID),
// 			})
// 			if err != nil {
// 				fmt.Printf("Failed to delete object %s from S3: %v\n", messageID, err)
// 				continue
// 			}

// 			fmt.Printf("Processed and deleted email %s\n", messageID)
// 		}
// 		return !lastPage
// 	})

// 	if err != nil {
// 		return fmt.Errorf("failed to list objects in S3 bucket: %v", err)
// 	}

// 	return nil
// }

func insertEmailToDB(email *ParsedEmail, userID int64) error {
	// Extract sender name and email from the "From" field
	senderName, senderEmail := parseEmailAddress(email.From)

	// Generate a preview from the plain text or HTML body
	preview := generatePreview(email.PlainText, email.Body)

	// Convert attachments to JSON format
	attachmentsJSON, err := json.Marshal(email.Attachments)
	if err != nil {
		return fmt.Errorf("failed to marshal attachments: %v", err)
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
		senderEmail,
		senderName,
		email.Subject,
		preview,
		email.Body,
		"", // Set email_type as needed
		string(attachmentsJSON),
		email.MessageID,
		email.Date, // Timestamp
	)
	return err
}

func parseEmailAddress(address string) (name string, email string) {
	addr, err := mail.ParseAddress(address)
	if err != nil {
		return "", address // Return raw address if parsing fails
	}
	return addr.Name, addr.Address
}

func generatePreview(plainText string, htmlBody string) string {
	var text string
	if plainText != "" {
		text = plainText
	} else {
		// Convert HTML to plain text
		text = html2text(htmlBody)
	}
	// Generate a short preview
	if len(text) > 200 {
		return text[:200] + "..."
	}
	return text
}

// Simple HTML to text converter (you might want to use a proper library)
func html2text(html string) string {
	// This is a very basic implementation
	// Consider using a proper HTML to text library
	text := html
	text = strings.ReplaceAll(text, "<br>", "\n")
	text = strings.ReplaceAll(text, "<br/>", "\n")
	text = strings.ReplaceAll(text, "<br />", "\n")
	text = strings.ReplaceAll(text, "</p>", "\n")
	text = strings.ReplaceAll(text, "</div>", "\n")

	// Remove all other HTML tags
	re := regexp.MustCompile("<[^>]*>")
	text = re.ReplaceAllString(text, "")

	// Decode HTML entities
	// text = html.UnescapeString(text)

	return strings.TrimSpace(text)
}

func parseEmailFromBucket(msg *mail.Message) (*ParsedEmail, error) {
	parsed := &ParsedEmail{
		MessageID: msg.Header.Get("Message-Id"),
		Subject:   msg.Header.Get("Subject"),
		From:      msg.Header.Get("From"),
		To:        msg.Header.Get("To"),
	}

	if dateStr := msg.Header.Get("Date"); dateStr != "" {
		if parsedDate, err := time.Parse(time.RFC1123Z, dateStr); err == nil {
			parsed.Date = parsedDate
		}
	}

	contentType := msg.Header.Get("Content-Type")
	if strings.HasPrefix(contentType, "multipart/") {
		_, params, err := mime.ParseMediaType(contentType)
		if err != nil {
			return nil, fmt.Errorf("failed to parse content type: %v", err)
		}

		mr := multipart.NewReader(msg.Body, params["boundary"])
		var htmlBody, plainBody string

		for {
			part, err := mr.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				continue
			}

			content, err := io.ReadAll(part)
			if err != nil {
				continue
			}

			partType, params, err := mime.ParseMediaType(part.Header.Get("Content-Type"))
			if err != nil {
				continue
			}

			disposition, _, err := mime.ParseMediaType(part.Header.Get("Content-Disposition"))
			isAttachment := err == nil && (disposition == "attachment" || part.FileName() != "")

			switch {
			case isAttachment:
				attachment := Attachment{
					Filename:    part.FileName(),
					ContentType: partType,
					Size:        int64(len(content)),
					Content:     content,
				}
				parsed.Attachments = append(parsed.Attachments, attachment)
			case strings.HasPrefix(partType, "multipart/"):
				// Handle nested multipart
				nestedMR := multipart.NewReader(bytes.NewReader(content), params["boundary"])
				handleNestedParts(nestedMR, parsed)
			case strings.HasPrefix(partType, "text/html"):
				htmlBody = string(content)
			case strings.HasPrefix(partType, "text/plain"):
				plainBody = string(content)
			}
		}

		// Prioritize HTML body if available
		if htmlBody != "" {
			parsed.Body = htmlBody
			parsed.PlainText = plainBody
		} else if plainBody != "" {
			parsed.PlainText = plainBody
			parsed.Body = textToHTML(plainBody)
		}
	} else {
		// Handle single part message
		body, err := io.ReadAll(msg.Body)
		if err == nil {
			if strings.HasPrefix(contentType, "text/html") {
				parsed.Body = string(body)
			} else {
				parsed.PlainText = string(body)
				parsed.Body = textToHTML(string(body))
			}
		}
	}

	return parsed, nil
}

func textToHTML(text string) string {
	// Convert plain text to HTML
	text = html.EscapeString(text)
	text = strings.ReplaceAll(text, "\n", "<br>")
	return fmt.Sprintf("<div style=\"font-family: Arial, sans-serif;\">%s</div>", text)
}

func handleNestedParts(mr *multipart.Reader, parsed *ParsedEmail) {
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}

		content, err := io.ReadAll(part)
		if err != nil {
			continue
		}

		partType := part.Header.Get("Content-Type")
		switch {
		case strings.HasPrefix(partType, "text/html"):
			parsed.Body = string(content)
		case strings.HasPrefix(partType, "text/plain"):
			parsed.PlainText = string(content)
		}
	}
}
