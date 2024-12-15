package pkg

import (
	"fmt"

	"github.com/Triaksa-Space/be-mail-platform/utils"
	"github.com/resend/resend-go/v2"
	"github.com/spf13/viper"
)

func SendEmailViaResend(from, to, subject, body string, attachments []Attachment) error {
	apiKey := viper.GetString("RESEND_API")

	if utils.IsFromMailria(from) {
		apiKey = viper.GetString("RESEND_MAILRIA_API")
	}

	var paramResend resend.SendEmailRequest

	paramResend.From = from
	paramResend.To = []string{to}
	paramResend.Subject = subject
	paramResend.Html = body

	for _, attachment := range attachments {
		var paramAttachmentResend resend.Attachment
		paramAttachmentResend.Path = attachment.URL
		paramAttachmentResend.Filename = attachment.Filename
		paramResend.Attachments = append(paramResend.Attachments, &paramAttachmentResend)
	}

	client := resend.NewClient(apiKey)

	sent, err := client.Emails.Send(&paramResend)
	if err != nil {
		fmt.Println("RESEND Failed to send email:", err)
		return err
	}

	fmt.Println("RESEND Email sent:", sent.Id)

	return nil
}
