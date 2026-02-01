package email

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/Triaksa-Space/be-mail-platform/config"
	"github.com/Triaksa-Space/be-mail-platform/pkg"
	"github.com/jhillyerd/enmime"
)

// ProcessConfig holds configuration for the email processor
type ProcessConfig struct {
	BatchSize   int // Number of emails to fetch per batch
	WorkerCount int // Number of parallel workers
	MaxRetries  int // Maximum retries for failed processing
}

// DefaultProcessConfig returns default configuration
func DefaultProcessConfig() ProcessConfig {
	return ProcessConfig{
		BatchSize:   50,  // Process 50 emails per batch
		WorkerCount: 10,  // 10 parallel workers
		MaxRetries:  3,   // Retry failed emails 3 times
	}
}

// IncomingEmail represents a raw email from incoming_emails table
type IncomingEmail struct {
	ID          int64     `db:"id"`
	EmailSendTo string    `db:"email_send_to"`
	MessageID   string    `db:"message_id"`
	EmailData   []byte    `db:"email_data"`
	EmailDate   time.Time `db:"email_date"`
	CreatedAt   time.Time `db:"created_at"`
	Processed   bool      `db:"processed"`
}

// ProcessResult holds the result of processing an email
type ProcessResult struct {
	EmailID int64
	Success bool
	Error   error
}

// ProcessAllPendingEmails processes all unprocessed emails from incoming_emails table
// This is the main function called by the cron job
func ProcessAllPendingEmails() error {
	cfg := DefaultProcessConfig()
	return ProcessAllPendingEmailsWithConfig(cfg)
}

// ProcessAllPendingEmailsWithConfig processes emails with custom configuration
func ProcessAllPendingEmailsWithConfig(cfg ProcessConfig) error {
	startTime := time.Now()
	fmt.Printf("[Processor] Starting email processing at %v\n", startTime)

	// Fetch batch of unprocessed emails
	var pendingEmails []IncomingEmail
	err := config.DB.Select(&pendingEmails, `
		SELECT id, email_send_to, message_id, email_data, email_date, created_at, processed
		FROM incoming_emails
		WHERE processed = FALSE
		ORDER BY created_at ASC
		LIMIT ?
	`, cfg.BatchSize)

	if err != nil {
		return fmt.Errorf("failed to fetch pending emails: %v", err)
	}

	if len(pendingEmails) == 0 {
		fmt.Println("[Processor] No pending emails to process")
		return nil
	}

	fmt.Printf("[Processor] Found %d pending emails to process\n", len(pendingEmails))

	// Create worker pool
	emailChan := make(chan IncomingEmail, len(pendingEmails))
	resultChan := make(chan ProcessResult, len(pendingEmails))
	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < cfg.WorkerCount; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for email := range emailChan {
				result := processOneEmail(workerID, email)
				resultChan <- result
			}
		}(i)
	}

	// Send emails to workers
	for _, email := range pendingEmails {
		emailChan <- email
	}
	close(emailChan)

	// Wait for all workers to finish
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Collect results
	successCount := 0
	failedCount := 0
	for result := range resultChan {
		if result.Success {
			successCount++
		} else {
			failedCount++
			fmt.Printf("[Processor] Failed to process email ID %d: %v\n", result.EmailID, result.Error)
		}
	}

	duration := time.Since(startTime)
	fmt.Printf("[Processor] Completed: %d success, %d failed in %v\n", successCount, failedCount, duration)

	return nil
}

// processOneEmail processes a single email (called by workers)
func processOneEmail(workerID int, rawEmail IncomingEmail) ProcessResult {
	result := ProcessResult{EmailID: rawEmail.ID}

	// Get user ID from email address
	var userID int64
	err := config.DB.Get(&userID, `
		SELECT id FROM users WHERE email = ?
	`, rawEmail.EmailSendTo)

	if err != nil {
		// User not found - mark as processed and skip
		markEmailProcessed(rawEmail.ID)
		result.Success = true // Not an error, just no user
		fmt.Printf("[Worker %d] No user found for %s, skipping\n", workerID, rawEmail.EmailSendTo)
		return result
	}

	// Enforce email limit per user (keep max 10 inbox emails)
	enforceEmailLimit(userID, 10)

	// Parse the email content
	env, err := enmime.ReadEnvelope(bytes.NewReader(rawEmail.EmailData))
	if err != nil {
		result.Error = fmt.Errorf("failed to parse email: %v", err)
		markEmailFailed(rawEmail.ID)
		return result
	}

	// Extract email date
	dateT, _ := env.Date()
	if dateT.IsZero() {
		dateT = rawEmail.EmailDate
		if dateT.IsZero() {
			dateT = time.Now()
		}
	}

	// Extract sender information
	fromAddresses := parseAddresses(env.GetHeader("From"))
	if len(fromAddresses) == 0 {
		fromAddresses = append(fromAddresses, EmailAddress{
			Name:    "Unknown Sender",
			Address: "unknown@unknown.com",
		})
	}

	// Handle attachments
	var attachmentURLs []string
	for _, att := range env.Attachments {
		attachmentKey := fmt.Sprintf("attachments/%s/%s", rawEmail.MessageID, att.FileName)
		attachmentURL, err := pkg.UploadAttachment(att.Content, attachmentKey, att.ContentType)
		if err != nil {
			log.Printf("[Worker %d] Failed to upload attachment: %v", workerID, err)
			continue
		}
		attachmentURLs = append(attachmentURLs, attachmentURL)
	}
	attachmentsJSON, _ := json.Marshal(attachmentURLs)

	// Select the email body and generate a preview
	var bodyEmail string
	if env.HTML != "" {
		bodyEmail = env.HTML
	} else {
		bodyEmail = env.Text
	}
	preview := generatePreview(env.Text, env.HTML)

	// Get subject
	subject := env.GetHeader("Subject")

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
		fromAddresses[0].Address,
		fromAddresses[0].Name,
		subject,
		preview,
		bodyEmail,
		"inbox",
		string(attachmentsJSON),
		rawEmail.MessageID,
		dateT,
	)

	if err != nil {
		result.Error = fmt.Errorf("failed to insert email: %v", err)
		markEmailFailed(rawEmail.ID)
		return result
	}

	// Delete from incoming_emails after successful processing
	_, err = config.DB.Exec(`DELETE FROM incoming_emails WHERE id = ?`, rawEmail.ID)
	if err != nil {
		log.Printf("[Worker %d] Failed to delete incoming email %d: %v", workerID, rawEmail.ID, err)
	}

	result.Success = true
	fmt.Printf("[Worker %d] Processed email for %s (ID: %d)\n", workerID, rawEmail.EmailSendTo, rawEmail.ID)
	return result
}

// enforceEmailLimit keeps only the latest N emails for a user
func enforceEmailLimit(userID int64, maxEmails int) {
	var emailCount int
	err := config.DB.Get(&emailCount, `
		SELECT COUNT(*) FROM emails
		WHERE user_id = ? AND email_type = 'inbox'
	`, userID)

	if err != nil || emailCount <= maxEmails {
		return
	}

	// Delete oldest emails to maintain limit
	deleteCount := emailCount - maxEmails + 1 // +1 to make room for new email
	_, err = config.DB.Exec(`
		DELETE FROM emails
		WHERE id IN (
			SELECT id FROM (
				SELECT id FROM emails
				WHERE user_id = ? AND email_type = 'inbox'
				ORDER BY timestamp ASC
				LIMIT ?
			) AS oldest
		)
	`, userID, deleteCount)

	if err != nil {
		fmt.Printf("Failed to enforce email limit for user %d: %v\n", userID, err)
	}
}

// markEmailProcessed marks an email as processed without inserting
func markEmailProcessed(emailID int64) {
	_, _ = config.DB.Exec(`
		UPDATE incoming_emails SET processed = TRUE WHERE id = ?
	`, emailID)
}

// markEmailFailed increments retry count or marks as failed
func markEmailFailed(emailID int64) {
	// For now, just mark as processed to avoid infinite retries
	// In production, you might want a retry_count column
	_, _ = config.DB.Exec(`
		UPDATE incoming_emails SET processed = TRUE WHERE id = ?
	`, emailID)
}

// GetProcessingStats returns statistics about email processing
func GetProcessingStats() (map[string]int64, error) {
	stats := make(map[string]int64)

	// Pending emails
	var pending int64
	config.DB.Get(&pending, `SELECT COUNT(*) FROM incoming_emails WHERE processed = FALSE`)
	stats["pending"] = pending

	// Processed today
	var processedToday int64
	config.DB.Get(&processedToday, `
		SELECT COUNT(*) FROM emails
		WHERE email_type = 'inbox' AND DATE(created_at) = CURDATE()
	`)
	stats["processed_today"] = processedToday

	// Total emails
	var total int64
	config.DB.Get(&total, `SELECT COUNT(*) FROM emails WHERE email_type = 'inbox'`)
	stats["total_emails"] = total

	return stats, nil
}
