package pkg

import (
	"fmt"
	"io"

	"github.com/spf13/viper"
	"gopkg.in/gomail.v2"
)

func SendEmailSMTP(from, to, subject, body string, attachments []Attachment) error {
	// SMTP configuration
	smtpHost := viper.GetString("SMTP_HOST")
	smtpPort := viper.GetInt("SMTP_PORT")
	smtpUsername := viper.GetString("SMTP_USERNAME")
	smtpPassword := viper.GetString("SMTP_PASSWORD")

	fmt.Println("SMTP_HOST", smtpHost)
	fmt.Println("SMTP_PORT", smtpPort)
	fmt.Println("SMTP_USERNAME", smtpUsername)

	// Create a new email message
	m := gomail.NewMessage()
	m.SetHeader("From", from) // Replace with your verified email address
	m.SetHeader("To", to)
	m.SetHeader("Subject", subject)
	m.SetBody("text/html", body)

	// Add attachments
	for _, att := range attachments {
		m.Attach(att.Filename, gomail.SetCopyFunc(func(w io.Writer) error {
			_, err := w.Write(att.Content)
			return err
		}), gomail.SetHeader(map[string][]string{
			"Content-Type": {att.ContentType},
		}))
	}

	// Create a new SMTP dialer
	d := gomail.NewDialer(smtpHost, smtpPort, smtpUsername, smtpPassword)

	// Send the email
	if err := d.DialAndSend(m); err != nil {
		fmt.Println("HARAKA Failed to send email:", err)
		return err
	}

	return nil
}
