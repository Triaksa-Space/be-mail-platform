package pkg

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"mime/multipart"
	"net/textproto"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/ses"
	"github.com/spf13/viper"
	"gopkg.in/gomail.v2"
)

// Attachment represents an email attachment
type Attachment struct {
	Filename    string
	ContentType string
	Content     []byte // Base64-encoded content
	URL         string
}

func InitAWS() (*session.Session, error) {
	// Initialize AWS session
	sess, err := session.NewSession(&aws.Config{
		Region:      aws.String(viper.GetString("AWS_REGION")),
		Credentials: credentials.NewStaticCredentials(viper.GetString("AWS_ACCESS_KEY"), viper.GetString("AWS_SECRET_KEY"), ""),
	})
	if err != nil {
		fmt.Println("Failed to initialize AWS session:", err)
		return nil, err
	}

	return sess, err
}

func InitS3(sess *session.Session) (*s3.S3, error) {
	// Initialize S3 client
	s3Client := s3.New(sess)
	return s3Client, nil
}

func CreateBucketFolderEmailUser(s3Client *s3.S3, reqEmail string) error {
	// Create the folder/prefix in S3
	bucketName := viper.GetString("S3_BUCKET_NAME") // "ses-mailsaja-received"
	folderKey := fmt.Sprintf("%s/", reqEmail)       // e.g., "person11@mailsaja.com/"

	// Upload an empty object to create the folder
	_, err := s3Client.PutObject(&s3.PutObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(folderKey),
		Body:   bytes.NewReader([]byte{}),
	})
	if err != nil {
		fmt.Println("Failed to create bucket folder:", err)
		return err
	}

	_, err = s3Client.PutObject(&s3.PutObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(reqEmail + "/"),
	})
	if err != nil {
		fmt.Println("Failed to create bucket folder:", err)
		return err
	}

	return nil
}

func DeleteS3ByMessageID(s3Client *s3.S3, bucketName, messageID string) error {
	// Delete the email object from S3 after storing
	_, err := s3Client.DeleteObject(&s3.DeleteObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(messageID),
	})
	if err != nil {
		fmt.Printf("Failed to delete object %s: %v\n", messageID, err)
		return err
	}

	return err
}

func DeleteS3FolderContents(s3Client *s3.S3, bucket, prefix string) error {
	// List all objects with the prefix
	listInput := &s3.ListObjectsV2Input{
		Bucket: aws.String(bucket),
		Prefix: aws.String(prefix),
	}

	// Delete objects in batches
	return s3Client.ListObjectsV2Pages(listInput, func(page *s3.ListObjectsV2Output, lastPage bool) bool {
		var objects []*s3.ObjectIdentifier
		for _, obj := range page.Contents {
			objects = append(objects, &s3.ObjectIdentifier{Key: obj.Key})
		}

		if len(objects) > 0 {
			deleteInput := &s3.DeleteObjectsInput{
				Bucket: aws.String(bucket),
				Delete: &s3.Delete{
					Objects: objects,
					Quiet:   aws.Bool(true),
				},
			}

			_, err := s3Client.DeleteObjects(deleteInput)
			if err != nil {
				fmt.Printf("Failed to delete objects: %v\n", err)
			}
		}

		return !lastPage
	})
}

func UploadAttachment(content []byte, key, contentType string) (string, error) {
	// Get S3 configuration
	bucketName := viper.GetString("S3_BUCKET_NAME")
	region := viper.GetString("AWS_REGION")

	// Create S3 client
	sess, _ := InitAWS()

	s3Client := s3.New(sess)

	// Upload to S3
	input := &s3.PutObjectInput{
		Bucket:      aws.String(bucketName),
		Key:         aws.String(key),
		Body:        bytes.NewReader(content),
		ContentType: aws.String(contentType),
	}

	_, err := s3Client.PutObject(input)
	if err != nil {
		return "", fmt.Errorf("failed to upload to S3: %v", err)
	}

	// Generate S3 URL
	s3URL := fmt.Sprintf("https://%s.s3.%s.amazonaws.com/%s",
		bucketName,
		region,
		key,
	)

	return s3URL, nil
}

// UploadAttachment uploads a file to S3 and returns the pre-signed URL
func UploadPreSignAttachment(content []byte, key string, contentType string) (string, error) {
	// Create the folder/prefix in S3
	bucketName := viper.GetString("S3_BUCKET_NAME") // "ses-mailsaja-received"

	sess, err := InitAWS()
	if err != nil {
		return "", fmt.Errorf("failed to create AWS session: %v", err)
	}

	s3Client := s3.New(sess)

	// Upload the file to S3
	_, err = s3Client.PutObject(&s3.PutObjectInput{
		Bucket:      aws.String(bucketName), // Replace with your S3 bucket name
		Key:         aws.String(key),
		Body:        bytes.NewReader(content),
		ContentType: aws.String(contentType),
	})
	if err != nil {
		return "", fmt.Errorf("failed to upload file to S3: %v", err)
	}

	// Generate a pre-signed URL for the uploaded file
	req, _ := s3Client.GetObjectRequest(&s3.GetObjectInput{
		Bucket: aws.String(bucketName), // Replace with your S3 bucket name
		Key:    aws.String(key),
	})
	urlStr, err := req.Presign((24 * 3) * time.Hour) // URL valid for 3 days
	if err != nil {
		return "", fmt.Errorf("failed to generate pre-signed URL: %v", err)
	}

	return urlStr, nil
}

// SendEmailWithAttachmentURL sends an email with optional attachments using AWS SES
func SendEmailWithAttachmentURL(toAddress, fromAddress, subject, htmlBody string, attachments []Attachment) error {
	// Initialize AWS session
	sess, err := InitAWS()
	if err != nil {
		return fmt.Errorf("failed to create AWS session: %v", err)
	}

	sesClient := ses.New(sess)

	// Build the email body
	var emailRaw bytes.Buffer
	writer := multipart.NewWriter(&emailRaw)

	// Write MIME headers
	emailHeaders := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"%s\"\r\n\r\n",
		fromAddress, toAddress, subject, writer.Boundary())
	emailRaw.Write([]byte(emailHeaders))

	// Calculate items per row and create rows of attachments
	const itemsPerRow = 4
	var attachmentRows []string
	var currentRow []string

	for i, att := range attachments {
		transformedFilename := transformFilename(att.Filename)
		attachmentItem := fmt.Sprintf(`
        <div style="display: inline-block; margin: 0 10px; width: calc(25%% - 20px); min-width: 200px; vertical-align: top;">
            <div style="border: 1px solid #e0e0e0; border-radius: 4px; background: #f8f9fa; padding: 12px; 
                        transition: all 0.2s ease-in-out; cursor: pointer;"
                 onmouseover="this.style.backgroundColor='#f0f0f0'; this.style.boxShadow='0 2px 5px rgba(0,0,0,0.1)'" 
                 onmouseout="this.style.backgroundColor='#f8f9fa'; this.style.boxShadow='none'">
                <a href="%s" style="text-decoration: none;" download="%s">
                    <table cellpadding="0" cellspacing="0" style="width: 100%%;">
                        <tr>
                            <td style="width: 36px; vertical-align: top;">
                                <img src="https://www.gstatic.com/images/icons/material/system_gm/1x/attach_file_grey600_24dp.png" 
                                     alt="Attachment" style="width: 24px; height: 24px;">
                            </td>
                            <td style="padding-left: 8px;">
                                <div style="font-family: Arial, sans-serif;">
                                    <div style="color: #1a73e8; font-size: 14px; 
                                            white-space: nowrap; overflow: hidden; text-overflow: ellipsis;" 
                                         title="%s">%s</div>
                                    <div style="color: #5f6368; font-size: 12px; margin-top: 4px;">
                                        Click to download
                                    </div>
                                </div>
                            </td>
                        </tr>
                    </table>
                </a>
            </div>
        </div>
        `, att.URL, att.Filename, transformedFilename, transformedFilename)

		currentRow = append(currentRow, attachmentItem)

		// When we reach itemsPerRow items or it's the last item, create a row
		if len(currentRow) == itemsPerRow || i == len(attachments)-1 {
			row := fmt.Sprintf(`
            <div style="display: flex; justify-content: flex-start; margin-bottom: 20px; flex-wrap: wrap;">
                %s
            </div>`, strings.Join(currentRow, ""))
			attachmentRows = append(attachmentRows, row)
			currentRow = []string{} // Reset current row
		}
	}

	// If there are attachments, append them to the HTML body
	if len(attachmentRows) > 0 {
		val := ""
		if len(attachments) > 1 {
			val = "s"
		}

		htmlBody += fmt.Sprintf(`
            <div style="margin-top: 20px; border-top: 1px solid #e0e0e0; padding-top: 20px;">
                <div style="color: #5f6368; font-family: Arial, sans-serif; font-size: 14px; margin-bottom: 10px;">
                    %d Attachment%s
                </div>
                %s
            </div>
        `, len(attachments), val, strings.Join(attachmentRows, ""))
	}

	// Write the HTML body part
	htmlPartHeaders := textproto.MIMEHeader{}
	htmlPartHeaders.Set("Content-Type", "text/html; charset=UTF-8")
	htmlPartHeaders.Set("Content-Transfer-Encoding", "base64")

	htmlPart, _ := writer.CreatePart(htmlPartHeaders)
	encodedBody := base64.StdEncoding.EncodeToString([]byte(htmlBody))
	htmlPart.Write([]byte(encodedBody))

	fmt.Println("htmlPart", htmlPart)

	writer.Close()

	// Send the email
	input := &ses.SendRawEmailInput{
		RawMessage: &ses.RawMessage{
			Data: emailRaw.Bytes(),
		},
	}

	_, err = sesClient.SendRawEmail(input)
	if err != nil {
		return fmt.Errorf("failed to send email: %v", err)
	}

	return nil
}

// TransformFilename transforms the filename to the desired format
func TransformFilename(filename string) string {
	// Split the filename by underscore
	parts := strings.Split(filename, "_")
	if len(parts) > 1 {
		// Return the last part of the split filename
		return parts[len(parts)-1]
	}
	// Return the original filename if it doesn't contain an underscore
	return filename
}

// SendEmailWithHARAKA sends an email with optional attachments using Haraka SMTP server
func SendEmailWithHARAKA(toAddress, fromAddress, subject, htmlBody string, attachments []Attachment) error {
	// SMTP server configuration
	smtpHost := viper.GetString("SMTP_HOST")
	smtpPort := viper.GetInt("SMTP_PORT")
	smtpUser := viper.GetString("SMTP_USERNAME")
	smtpPassword := viper.GetString("SMTP_PASSWORD")

	fmt.Println("SMTP_HOST: ", smtpHost)
	fmt.Println("SMTP_USERNAME: ", smtpUser)

	// Create a new email message
	m := gomail.NewMessage()
	m.SetHeader("From", fromAddress)
	m.SetHeader("To", toAddress)
	m.SetHeader("Subject", subject)
	m.SetBody("text/html", htmlBody)

	// Calculate items per row and create rows of attachments
	const itemsPerRow = 4
	var attachmentRows []string
	var currentRow []string

	for i, att := range attachments {
		transformedFilename := TransformFilename(att.Filename)
		attachmentItem := fmt.Sprintf(`
        <div style="display: inline-block; margin: 0 10px; width: calc(25%% - 20px); min-width: 200px; vertical-align: top;">
            <div style="border: 1px solid #e0e0e0; border-radius: 4px; background: #f8f9fa; padding: 12px; 
                        transition: all 0.2s ease-in-out; cursor: pointer;"
                 onmouseover="this.style.backgroundColor='#f0f0f0'; this.style.boxShadow='0 2px 5px rgba(0,0,0,0.1)'" 
                 onmouseout="this.style.backgroundColor='#f8f9fa'; this.style.boxShadow='none'">
                <a href="%s" style="text-decoration: none;" download="%s">
                    <table cellpadding="0" cellspacing="0" style="width: 100%%;">
                        <tr>
                            <td style="width: 36px; vertical-align: top;">
                                <img src="https://www.gstatic.com/images/icons/material/system_gm/1x/attach_file_grey600_24dp.png" 
                                     alt="Attachment" style="width: 24px; height: 24px;">
                            </td>
                            <td style="padding-left: 8px;">
                                <div style="font-family: Arial, sans-serif;">
                                    <div style="color: #1a73e8; font-size: 14px; 
                                            white-space: nowrap; overflow: hidden; text-overflow: ellipsis;" 
                                         title="%s">%s</div>
                                    <div style="color: #5f6368; font-size: 12px; margin-top: 4px;">
                                        Click to download
                                    </div>
                                </div>
                            </td>
                        </tr>
                    </table>
                </a>
            </div>
        </div>
        `, att.URL, att.Filename, transformedFilename, transformedFilename)

		currentRow = append(currentRow, attachmentItem)

		// When we reach itemsPerRow items or it's the last item, create a row
		if len(currentRow) == itemsPerRow || i == len(attachments)-1 {
			row := fmt.Sprintf(`
            <div style="display: flex; justify-content: flex-start; margin-bottom: 20px; flex-wrap: wrap;">
                %s
            </div>`, strings.Join(currentRow, ""))
			attachmentRows = append(attachmentRows, row)
			currentRow = []string{} // Reset current row
		}
	}

	// If there are attachments, append them to the HTML body
	if len(attachmentRows) > 0 {
		val := ""
		if len(attachments) > 1 {
			val = "s"
		}

		htmlBody += fmt.Sprintf(`
            <div style="margin-top: 20px; border-top: 1px solid #e0e0e0; padding-top: 20px;">
                <div style="color: #5f6368; font-family: Arial, sans-serif; font-size: 14px; margin-bottom: 10px;">
                    %d Attachment%s
                </div>
                %s
            </div>
        `, len(attachments), val, strings.Join(attachmentRows, ""))
	}

	// Add attachments to the email
	for _, att := range attachments {
		m.Attach(att.Filename, gomail.SetCopyFunc(func(w io.Writer) error {
			_, err := w.Write(att.Content)
			return err
		}))
	}

	// Send the email using Haraka SMTP
	d := gomail.NewDialer(smtpHost, smtpPort, smtpUser, smtpPassword)
	if err := d.DialAndSend(m); err != nil {
		fmt.Println("SendMail via HARAKA err", err)
		return fmt.Errorf("failed to send email: %v", err)
	}

	fmt.Println("Email sent successfully")
	return nil
}

// TransformFilename transforms the filename to the desired format
func transformFilename(filename string) string {
	// Split the filename by underscore
	parts := strings.Split(filename, "_")
	if len(parts) > 1 {
		// Return the last part of the split filename
		return parts[len(parts)-1]
	}
	// Return the original filename if it doesn't contain an underscore
	return filename
}

// SendEmail sends an email with optional attachments using AWS SES
func SendEmail(toAddress, fromAddress, subject, htmlBody string, attachments []Attachment) error {
	// Initialize AWS session
	sess, _ := InitAWS()

	sesClient := ses.New(sess)

	// Build the email body
	var emailRaw bytes.Buffer
	writer := multipart.NewWriter(&emailRaw)

	// Write MIME headers
	emailHeaders := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"%s\"\r\n\r\n",
		fromAddress, toAddress, subject, writer.Boundary())
	emailRaw.Write([]byte(emailHeaders))

	// Write the HTML body part
	htmlPartHeaders := textproto.MIMEHeader{}
	htmlPartHeaders.Set("Content-Type", "text/html; charset=UTF-8")
	htmlPartHeaders.Set("Content-Transfer-Encoding", "base64")

	htmlPart, _ := writer.CreatePart(htmlPartHeaders)
	encodedBody := base64.StdEncoding.EncodeToString([]byte(htmlBody))
	htmlPart.Write([]byte(encodedBody))

	// Write attachments
	for _, att := range attachments {
		attachmentPartHeaders := textproto.MIMEHeader{}
		attachmentPartHeaders.Set("Content-Type", att.ContentType+"; name=\""+att.Filename+"\"")
		attachmentPartHeaders.Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", att.Filename))
		attachmentPartHeaders.Set("Content-Transfer-Encoding", "base64")

		attachmentPart, err := writer.CreatePart(attachmentPartHeaders)
		if err != nil {
			return err
		}

		// Stream encode to handle large files
		encoder := base64.NewEncoder(base64.StdEncoding, attachmentPart)
		_, err = encoder.Write(att.Content)
		if err != nil {
			return err
		}
		encoder.Close()
	}

	writer.Close()

	// Send the email
	input := &ses.SendRawEmailInput{
		RawMessage: &ses.RawMessage{
			Data: emailRaw.Bytes(),
		},
	}

	_, err := sesClient.SendRawEmail(input)
	if err != nil {
		return fmt.Errorf("failed to send email: %v", err)
	}

	return nil
}

func ExtractNameFromEmail(email string) string {
	if email == "" {
		// Extract the name from the email address before the '@' symbol
		parts := strings.Split(email, "@")
		if len(parts) > 0 {
			return parts[0]
		}
		return ""
	}
	return email
}
