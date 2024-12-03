package pkg

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"mime/multipart"
	"net/textproto"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/ses"
	"github.com/spf13/viper"
)

// Attachment represents an email attachment
type Attachment struct {
	Filename    string
	ContentType string
	Content     []byte // Base64-encoded content
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
		attachmentHeaders := textproto.MIMEHeader{}
		attachmentHeaders.Set("Content-Type", fmt.Sprintf("%s; name=\"%s\"", att.ContentType, att.Filename))
		attachmentHeaders.Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", att.Filename))
		attachmentHeaders.Set("Content-Transfer-Encoding", "base64")

		attachmentPart, _ := writer.CreatePart(attachmentHeaders)
		encodedContent := base64.StdEncoding.EncodeToString(att.Content)
		attachmentPart.Write([]byte(encodedContent))
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
