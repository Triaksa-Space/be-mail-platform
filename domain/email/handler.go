package email

import (
	"bytes"
	"email-platform/config"
	"email-platform/domain/user"
	"email-platform/pkg"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/jhillyerd/enmime"
	"github.com/labstack/echo/v4"
	"github.com/spf13/viper"
)

type EmailService struct {
	S3Client   *s3.S3
	BucketName string
}

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

// handler.go
func SendEmailHandler(c echo.Context) error {
	// Get user ID and email from context
	userID := c.Get("user_id").(int64)

	var emailUser string
	err := config.DB.Get(&emailUser, `
        SELECT email 
        FROM users 
        WHERE id = ? LIMIT 1`, userID)
	if err != nil {
		fmt.Println("Failed to fetch user email", err)
		return err
	}

	// Check email limit
	if err := CheckEmailLimit(userID); err != nil {
		return c.JSON(http.StatusTooManyRequests, map[string]string{
			"error": "Email limit exceeded",
		})
	}

	// Parse and validate request
	req := new(SendEmailRequest)
	if err := c.Bind(req); err != nil {
		fmt.Println("Failed to bind request", err)
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid request payload",
		})
	}

	// Prepare attachments and upload to S3
	var attachments []pkg.Attachment
	var attachmentURLs []string
	if len(req.Attachments) > 0 {
		for _, att := range req.Attachments {
			// Strip the data URL prefix if present
			content := att.Content
			contentStr := string(content)
			if strings.HasPrefix(contentStr, "data:") {
				parts := strings.SplitN(contentStr, ",", 2)
				if len(parts) == 2 {
					content = []byte(parts[1])
				}
			}

			// Decode base64 content
			decodedContent, err := base64.StdEncoding.DecodeString(base64.StdEncoding.EncodeToString(content))
			if err != nil {
				fmt.Printf("Failed to decode attachment %s: %v\n", att.Filename, err)
				return c.JSON(http.StatusBadRequest, map[string]string{
					"error": fmt.Sprintf("Invalid base64 content for attachment %s", att.Filename),
				})
			}

			// Generate a unique key for the attachment in S3
			// uniqueID := uuid.New().String()
			// attachmentKey := fmt.Sprintf("attachments/%s/%s_%s", emailUser, uniqueID, att.Filename)

			// // Upload the attachment to S3
			// attachmentURL, err := pkg.UploadAttachment(decodedContent, attachmentKey, att.ContentType)
			// if err != nil {
			// 	fmt.Printf("Failed to upload attachment %s: %v\n", att.Filename, err)
			// 	return c.JSON(http.StatusInternalServerError, map[string]string{
			// 		"error": fmt.Sprintf("Failed to upload attachment %s", att.Filename),
			// 	})
			// }

			// Convert filename to lowercase and replace spaces with underscores
			filename := strings.ToLower(att.Filename)
			filename = strings.ReplaceAll(filename, " ", "_")

			// // Append the attachment URL to the list
			attachmentURLs = append(attachmentURLs, filename)

			// // Prepare the attachment for sending email
			attachments = append(attachments, pkg.Attachment{
				Filename:    filename,
				ContentType: att.ContentType,
				Content:     decodedContent,
			})
		}
	}

	// Send email via pkg/aws
	err = pkg.SendEmail(req.To, emailUser, req.Subject, req.Body, attachments)
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

	attachmentsJSON, _ := json.Marshal(attachmentURLs)
	// fmt.Println("attachmentsJSON", attachmentsJSON)
	_, err = tx.Exec(`
        INSERT INTO emails (
            user_id,
            email_type,
            sender_email,
            sender_name,
            subject,
            body,
            attachments,
            timestamp,
            created_at,
            updated_at,
			created_by,
			updated_by
        ) 
        VALUES (?, "sent", ?, ?, ?, ?, ?, NOW(), NOW(), NOW(), ?, ?)`,
		userID, emailUser, "", req.Subject, req.Body, attachmentsJSON, userID, userID)
	if err != nil {
		fmt.Println("Failed to save email", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "Failed to save email",
		})
	}

	if err := tx.Commit(); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "Failed to commit transaction",
		})
	}

	// Update last login
	err = updateLastLogin(userID)
	if err != nil {
		fmt.Println("error updateLastLogin", err)
	}

	return c.JSON(http.StatusOK, map[string]string{
		"message": "Email sent successfully",
	})
}

func GetFileEmailToDownloadHandler(c echo.Context) error {
	userID := c.Get("user_id").(int64)
	// Get email ID and file URL from the request parameters
	emailID := c.Param("id")
	fileURL := c.Param("file_url")

	// Fetch the email record from the database
	var email Email
	err := config.DB.Get(&email, `SELECT id, 
            user_id, 
            sender_email, sender_name, 
            subject, 
            body,
			preview,
			message_id,
			attachments,
            timestamp, 
            created_at, 
            updated_at  FROM emails WHERE id = ? and user_id = ?`, emailID, userID)
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
	// TODO: ATTACHMENT DIBUAT TABLE SENDIRI SAJA

	// Fetch email details by ID
	var email Email
	err := config.DB.Get(&email, `SELECT id, 
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

	var emailResp EmailResponse
	emailResp.Email = email
	emailResp.RelativeTime = formatRelativeTime(email.Timestamp)
	emailResp.ListAttachments = getAttachmentURLs(email.Attachments)

	// Update last login
	err = updateLastLogin(userID)
	if err != nil {
		fmt.Println("error updateLastLogin", err)
	}

	return c.JSON(http.StatusOK, emailResp)
}

func ListEmailsHandler(c echo.Context) error {
	// Fetch all emails
	var emails []Email
	err := config.DB.Select(&emails, `SELECT id, 
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
	userID := c.Param("id")

	var emails []Email
	err := config.DB.Select(&emails, `SELECT id, 
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
	if err := json.Unmarshal([]byte(attachmentsJSON), &urls); err != nil {
		fmt.Printf("Failed to unmarshal attachments: %v\n", err)
		return nil
	}

	attachments := make([]Attachment, len(urls))
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

func CallbackNotifEmailHandler(c echo.Context) error {
	bodyBytes, err := ioutil.ReadAll(c.Request().Body)
	if err != nil {
		log.Println("Error reading request body:", err)
		return c.NoContent(http.StatusBadRequest)
	}

	var message pkg.SNSMessage
	if err := json.Unmarshal(bodyBytes, &message); err != nil {
		log.Println("Error unmarshaling SNS message:", err)
		return c.NoContent(http.StatusBadRequest)
	}

	// Validate the SNS message
	if err := pkg.VerifySNSMessage(message); err != nil {
		log.Println("SNS message verification failed:", err)
		return c.NoContent(http.StatusForbidden)
	}

	switch message.Type {
	case "SubscriptionConfirmation":
		// Confirm the subscription
		if err := pkg.ConfirmSubscription(message.SubscribeURL); err != nil {
			log.Println("Error confirming subscription:", err)
			return c.NoContent(http.StatusInternalServerError)
		}
		log.Println("Subscription confirmed.")
	case "Notification":
		// Process the notification
		if err := processNotification(message.Message); err != nil {
			log.Println("Error processing notification:", err)
			return c.NoContent(http.StatusInternalServerError)
		}
	default:
		log.Println("Unhandled message type:", message.Type)
	}

	return c.String(http.StatusOK, "OK")
}

func processNotification(message string) error {
	var s3Event pkg.S3Event
	if err := json.Unmarshal([]byte(message), &s3Event); err != nil {
		return err
	}

	// Iterate over the records (usually just one)
	for _, record := range s3Event.Records {
		bucketName := record.S3.Bucket.Name
		objectKey, err := url.QueryUnescape(record.S3.Object.Key)
		if err != nil {
			return err
		}

		log.Printf("New object in S3 - Bucket: %s, Key: %s\n", bucketName, objectKey)

		// Call your SyncFunc with the bucket and object key
		if err := SyncBucketInboxFunc(bucketName, objectKey); err != nil {
			return err
		}
	}

	return nil
}

func SyncBucketInboxFunc(bucketName, objectKey string) error {
	// Initialize AWS SDK session
	sess, err := pkg.InitAWS()
	if err != nil {
		fmt.Println("Failed to initialize AWS session:", err)
	}
	s3Svc := s3.New(sess)

	// Get the object from S3
	obj, err := s3Svc.GetObject(&s3.GetObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(objectKey),
	})
	if err != nil {
		return err
	}
	defer obj.Body.Close()

	// Read the object content
	body, err := io.ReadAll(obj.Body)
	if err != nil {
		return err
	}

	fmt.Println("Email content:", string(body))

	// Process the email content
	// For example, parse the email and store it in your database
	// ...

	return nil
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

func getPreview(body string, length int) string {
	if len(body) > length {
		return body[:length]
	}
	return body
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

// // Simple HTML to text converter (you might want to use a proper library)
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

func updateLastLogin(userID int64) error {
	// Update the user's last login time
	_, err := config.DB.Exec("UPDATE users SET last_login = ? WHERE id = ?", time.Now(), userID)
	if err != nil {
		return err
	}

	return nil
}
