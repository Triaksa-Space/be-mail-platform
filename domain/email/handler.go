package email

import (
	"bytes"
	"email-platform/config"
	"email-platform/domain/user"
	"email-platform/pkg"
	"errors"
	"fmt"
	"html"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/mail"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
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
	s3Client := s3.New(sess)

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

			// Use the parsed email
			// fmt.Printf("From: %s\nSubject: %s\nDate: %s\n",
			// 	parsedEmail.From,
			// 	parsedEmail.Subject,
			// 	parsedEmail.Date.Format(time.RFC3339))
			// 	parsedEmail.MessageID
			// // Extract email fields
			// parsedEmail := ParsedEmail{
			// 	Subject: msg.Header.Get("Subject"),
			// 	From:    msg.Header.Get("From"),
			// 	Date:    msg.Header.Get("Date"),
			// 	To:      msg.Header.Get("To"),
			// 	Body:    "",
			// }

			// Read the body
			// bodyBytes, err := io.ReadAll(msg.Body)
			// if err != nil {
			// 	fmt.Println("Failed to read email body:", err)
			// }
			// parsedEmail.Body = string(bodyBytes)

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
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(viper.GetString("AWS_REGION")),
	})
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to initialize AWS"})
	}

	// Create S3 client
	s3Client := s3.New(sess)

	stats := SyncStats{}

	// List objects in S3 bucket
	err = s3Client.ListObjectsV2Pages(&s3.ListObjectsV2Input{
		Bucket: aws.String(bucketName),
		Prefix: aws.String(prefix),
	}, func(page *s3.ListObjectsV2Output, lastPage bool) bool {
		for _, obj := range page.Contents {
			stats.TotalEmails++

			// Check if email already exists
			var exists bool
			err := config.DB.Get(&exists, "SELECT EXISTS(SELECT 1 FROM emails WHERE message_id = ?)", *obj.Key)
			if err != nil {
				fmt.Printf("Error checking email existence: %v\n", err)
				stats.FailedEmails++
				continue
			}

			if exists {
				stats.SkippedEmails++
				continue
			}

			// Get the email object
			output, err := s3Client.GetObject(&s3.GetObjectInput{
				Bucket: aws.String(bucketName),
				Key:    obj.Key,
			})
			if err != nil {
				fmt.Printf("Failed to get object: %v\n", err)
				stats.FailedEmails++
				continue
			}
			defer output.Body.Close()

			// Read email content
			buf := new(bytes.Buffer)
			if _, err := io.Copy(buf, output.Body); err != nil {
				fmt.Printf("Failed to read email: %v\n", err)
				stats.FailedEmails++
				continue
			}

			// Parse email
			msg, err := mail.ReadMessage(strings.NewReader(buf.String()))
			if err != nil {
				fmt.Printf("Failed to parse email: %v\n", err)
				stats.FailedEmails++
				continue
			}

			// Read body
			body, err := io.ReadAll(msg.Body)
			if err != nil {
				fmt.Printf("Failed to read body: %v\n", err)
				stats.FailedEmails++
				continue
			}

			// Start transaction
			tx, err := config.DB.Begin()
			if err != nil {
				stats.FailedEmails++
				continue
			}
			defer tx.Rollback()

			// Insert email
			_, err = tx.Exec(`
                INSERT INTO emails (
                    user_id, message_id, subject, sender, recipient,
                    body, received_at, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, NOW(), NOW())
            `,
				userID,
				*obj.Key,
				msg.Header.Get("Subject"),
				msg.Header.Get("From"),
				msg.Header.Get("To"),
				string(body),
				output.LastModified,
			)
			if err != nil {
				fmt.Printf("Failed to insert email: %v\n", err)
				stats.FailedEmails++
				continue
			}

			if err := tx.Commit(); err != nil {
				fmt.Printf("Failed to commit transaction: %v\n", err)
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
