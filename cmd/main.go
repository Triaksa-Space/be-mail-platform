package main

import (
	"email-platform/config"
	"email-platform/routes"
	"fmt"
	"os"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run cmd/main.go [server|receive_email]")
		os.Exit(1)
	}

	config.InitConfig()
	config.InitDB()

	switch os.Args[1] {
	case "server":
		startServer()
	// case "receive_email":
	// 	startSNSListener()
	default:
		fmt.Printf("Unknown command: %s\n", os.Args[1])
		os.Exit(1)
	}
}

func startServer() {
	e := echo.New()

	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins:     []string{"http://localhost:3000"},
		AllowMethods:     []string{echo.GET, echo.POST, echo.PUT, echo.DELETE, echo.OPTIONS},
		AllowHeaders:     []string{echo.HeaderOrigin, echo.HeaderContentType, echo.HeaderAccept, echo.HeaderAuthorization},
		ExposeHeaders:    []string{echo.HeaderContentLength},
		AllowCredentials: true,
		MaxAge:           86400,
	}))

	routes.RegisterRoutes(e)
	e.Logger.Fatal(e.Start(":8080"))
}

// func startSNSListener() {
// 	// Initialize AWS session
// 	sess, err := session.NewSession(&aws.Config{
// 		Region: aws.String(viper.GetString("AWS_REGION")),
// 	})
// 	if err != nil {
// 		fmt.Printf("Failed to create AWS session: %v\n", err)
// 		os.Exit(1)
// 	}

// 	snsClient := sns.New(sess)

// 	// Create Echo instance for SNS endpoint
// 	e := echo.New()
// 	e.Use(middleware.Logger())
// 	e.Use(middleware.Recover())

// 	// SNS endpoint
// 	e.POST("/sns", func(c echo.Context) error {
// 		// Read the raw body
// 		body, err := io.ReadAll(c.Request().Body)
// 		if err != nil {
// 			return c.String(http.StatusBadRequest, "Failed to read body")
// 		}

// 		// Parse the SNS message
// 		var message struct {
// 			Type             string `json:"Type"`
// 			MessageId        string `json:"MessageId"`
// 			Token            string `json:"Token"`
// 			TopicArn         string `json:"TopicArn"`
// 			Message          string `json:"Message"`
// 			SubscribeURL     string `json:"SubscribeURL"`
// 			Timestamp        string `json:"Timestamp"`
// 			SignatureVersion string `json:"SignatureVersion"`
// 			Signature        string `json:"Signature"`
// 			SigningCertURL   string `json:"SigningCertURL"`
// 		}

// 		if err := json.Unmarshal(body, &message); err != nil {
// 			return c.String(http.StatusBadRequest, "Invalid SNS message format")
// 		}

// 		switch message.Type {
// 		case "SubscriptionConfirmation":
// 			// Handle subscription confirmation
// 			resp, err := http.Get(message.SubscribeURL)
// 			if err != nil {
// 				fmt.Printf("Failed to confirm subscription: %v\n", err)
// 				return c.String(http.StatusInternalServerError, "Failed to confirm subscription")
// 			}
// 			defer resp.Body.Close()
// 			fmt.Printf("Subscription confirmed for topic: %s\n", message.TopicArn)

// 		case "Notification":
// 			// Parse the actual message
// 			var emailNotification struct {
// 				NotificationType string `json:"notificationType"`
// 				Mail             struct {
// 					MessageId   string   `json:"messageId"`
// 					Source      string   `json:"source"`
// 					Destination []string `json:"destination"`
// 				} `json:"mail"`
// 			}

// 			if err := json.Unmarshal([]byte(message.Message), &emailNotification); err != nil {
// 				return c.String(http.StatusBadRequest, "Invalid email notification format")
// 			}

// 			fmt.Printf("Received email notification: %s from %s to %v\n",
// 				emailNotification.Mail.MessageId,
// 				emailNotification.Mail.Source,
// 				emailNotification.Mail.Destination)

// 			// Process the email based on notification type
// 			switch emailNotification.NotificationType {
// 			case "Received":
// 				// Handle received email
// 				if err := processReceivedEmail(emailNotification.Mail.MessageId); err != nil {
// 					fmt.Printf("Failed to process email: %v\n", err)
// 				}
// 			}

// 		case "UnsubscribeConfirmation":
// 			fmt.Printf("Unsubscribed from topic: %s\n", message.TopicArn)
// 		}

// 		return c.String(http.StatusOK, "OK")
// 	})

// 	// Start the server
// 	fmt.Println("Starting SNS listener on :8081")
// 	if err := e.Start(":8081"); err != nil {
// 		fmt.Printf("Failed to start SNS listener: %v\n", err)
// 		os.Exit(1)
// 	}
// }

// func processReceivedEmail(messageId string) error {
// 	// Initialize S3 client
// 	sess, err := session.NewSession(&aws.Config{
// 		Region: aws.String(viper.GetString("AWS_REGION")),
// 	})
// 	if err != nil {
// 		return fmt.Errorf("failed to create AWS session: %v", err)
// 	}

// 	s3Client := s3.New(sess)

// 	// Get the email from S3
// 	input := &s3.GetObjectInput{
// 		Bucket: aws.String(viper.GetString("S3_BUCKET_NAME")),
// 		Key:    aws.String(messageId),
// 	}

// 	result, err := s3Client.GetObject(input)
// 	if err != nil {
// 		return fmt.Errorf("failed to get email from S3: %v", err)
// 	}
// 	defer result.Body.Close()

// 	// Read and parse the email
// 	msg, err := mail.ReadMessage(result.Body)
// 	if err != nil {
// 		return fmt.Errorf("failed to parse email: %v", err)
// 	}

// 	// Store email in database
// 	tx, err := config.DB.Begin()
// 	if err != nil {
// 		return fmt.Errorf("failed to start transaction: %v", err)
// 	}
// 	defer tx.Rollback()

// 	// Insert email record
// 	_, err = tx.Exec(`
//         INSERT INTO emails (message_id, subject, sender, recipient, received_at)
//         VALUES (?, ?, ?, ?, NOW())`,
// 		messageId,
// 		msg.Header.Get("Subject"),
// 		msg.Header.Get("From"),
// 		msg.Header.Get("To"),
// 	)
// 	if err != nil {
// 		return fmt.Errorf("failed to insert email: %v", err)
// 	}

// 	return tx.Commit()
// }
