package pkg

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type SNSMessage struct {
	Type             string `json:"Type"`
	MessageId        string `json:"MessageId"`
	TopicArn         string `json:"TopicArn"`
	Subject          string `json:"Subject"`
	Message          string `json:"Message"`
	Timestamp        string `json:"Timestamp"`
	SignatureVersion string `json:"SignatureVersion"`
	Signature        string `json:"Signature"`
	SigningCertURL   string `json:"SigningCertURL"`
	UnsubscribeURL   string `json:"UnsubscribeURL"`
	SubscribeURL     string `json:"SubscribeURL"`
	Token            string `json:"Token"`
}

type S3Event struct {
	Records []struct {
		S3 struct {
			Bucket struct {
				Name string `json:"name"`
			} `json:"bucket"`
			Object struct {
				Key string `json:"key"`
			} `json:"object"`
		} `json:"s3"`
	} `json:"Records"`
}

func ConfirmSubscription(subscribeURL string) error {
	resp, err := http.Get(subscribeURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Failed to confirm subscription, status code: %d", resp.StatusCode)
	}
	return nil
}

func VerifySNSMessage(message SNSMessage) error {
	// Download the certificate
	resp, err := http.Get(message.SigningCertURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	certData, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	cert, err := x509.ParseCertificate(certData)
	if err != nil {
		return err
	}

	// Build the string to sign
	stringToSign := BuildStringToSign(message)

	// Decode the signature
	signature, err := base64.StdEncoding.DecodeString(message.Signature)
	if err != nil {
		return err
	}

	// Verify the signature
	err = cert.CheckSignature(x509.SHA1WithRSA, []byte(stringToSign), signature)
	if err != nil {
		return err
	}

	return nil
}

func BuildStringToSign(message SNSMessage) string {
	var signLines []string

	if message.Type != "" {
		signLines = append(signLines, "Message")
		signLines = append(signLines, message.Message)
	}

	if message.MessageId != "" {
		signLines = append(signLines, "MessageId")
		signLines = append(signLines, message.MessageId)
	}

	if message.Subject != "" {
		signLines = append(signLines, "Subject")
		signLines = append(signLines, message.Subject)
	}

	if message.Timestamp != "" {
		signLines = append(signLines, "Timestamp")
		signLines = append(signLines, message.Timestamp)
	}

	if message.TopicArn != "" {
		signLines = append(signLines, "TopicArn")
		signLines = append(signLines, message.TopicArn)
	}

	if message.Type != "" {
		signLines = append(signLines, "Type")
		signLines = append(signLines, message.Type)
	}

	return strings.Join(signLines, "\n") + "\n"
}
