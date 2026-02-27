package email

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/Triaksa-Space/be-mail-platform/config"
	"github.com/Triaksa-Space/be-mail-platform/pkg"
	"github.com/Triaksa-Space/be-mail-platform/pkg/logger"
	"github.com/jhillyerd/enmime"
	"github.com/labstack/echo/v4"
)

// processMu ensures only one ProcessAllPendingEmails runs at a time.
// If cron and a manual trigger overlap, the second call returns immediately.
var processMu sync.Mutex

// ProcessConfig holds configuration for the email processor
type ProcessConfig struct {
	BatchSize    int  // Number of emails to fetch per batch
	WorkerCount  int  // Number of parallel workers
	MaxRetries   int  // Maximum retries for failed processing
	ForceProcess bool // Skip retry_count filter (for on-demand admin processing)
}

// DefaultProcessConfig returns default configuration
func DefaultProcessConfig() ProcessConfig {
	return ProcessConfig{
		BatchSize:   50, // Process 50 emails per batch
		WorkerCount: 10, // 10 parallel workers
		MaxRetries:  3,  // Retry failed emails 3 times
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
	RetryCount  int       `db:"retry_count"`
}

// ProcessResult holds the result of processing an email
type ProcessResult struct {
	EmailID int64
	Success bool
	Error   error
}

// ProcessAllPendingEmails processes all unprocessed emails from incoming_emails table
// This is the main function called by the cron job (respects retry_count limit)
func ProcessAllPendingEmails() error {
	cfg := DefaultProcessConfig()
	return ProcessAllPendingEmailsWithConfig(cfg)
}

// ForceProcessAllPendingEmails processes ALL pending emails regardless of retry_count.
// Use this for on-demand triggers (e.g. admin inbox) so emails that the cron
// already gave up on (retry_count >= 3) are still picked up immediately.
func ForceProcessAllPendingEmails() error {
	cfg := DefaultProcessConfig()
	cfg.ForceProcess = true
	return ProcessAllPendingEmailsWithConfig(cfg)
}

// ProcessAllPendingEmailsWithConfig processes emails with custom configuration
func ProcessAllPendingEmailsWithConfig(cfg ProcessConfig) error {
	// Guard: if another process call is already running (cron or manual), skip.
	if !processMu.TryLock() {
		logger.Get().WithComponent("email_processor").Debug("Process already running, skipping concurrent call")
		return nil
	}
	defer processMu.Unlock()

	log := logger.Get().WithComponent("email_processor")
	startTime := time.Now()

	log.Debug("Starting email processing",
		logger.BatchSize(cfg.BatchSize),
		logger.Int("workers", cfg.WorkerCount),
	)

	// Fetch batch of unprocessed emails.
	// ForceProcess bypasses the retry_count limit so on-demand admin requests
	// can still pick up emails that exhausted their cron retries.
	var pendingEmails []IncomingEmail
	var err error
	if cfg.ForceProcess {
		err = config.DB.Select(&pendingEmails, `
			SELECT id, email_send_to, message_id, email_data, email_date, created_at, processed, retry_count
			FROM incoming_emails
			WHERE processed = FALSE
			ORDER BY created_at ASC
			LIMIT ?
		`, cfg.BatchSize)
	} else {
		err = config.DB.Select(&pendingEmails, `
			SELECT id, email_send_to, message_id, email_data, email_date, created_at, processed, retry_count
			FROM incoming_emails
			WHERE processed = FALSE AND retry_count < ?
			ORDER BY created_at ASC
			LIMIT ?
		`, cfg.MaxRetries, cfg.BatchSize)
	}

	if err != nil {
		log.Error("Failed to fetch pending emails", err)
		return fmt.Errorf("failed to fetch pending emails: %w", err)
	}

	if len(pendingEmails) == 0 {
		log.Debug("No pending emails to process")
		return nil
	}

	log.Info("Found pending emails to process", logger.Count(len(pendingEmails)))

	// Create worker pool
	emailChan := make(chan IncomingEmail, len(pendingEmails))
	resultChan := make(chan ProcessResult, len(pendingEmails))
	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < cfg.WorkerCount; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			workerLog := log.WithFields(logger.WorkerID(workerID))
			for email := range emailChan {
				result := processOneEmail(workerLog, workerID, email)
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
			log.Warn("Failed to process email",
				logger.EmailID(result.EmailID),
				logger.Err(result.Error),
			)
		}
	}

	duration := time.Since(startTime)
	log.Info("Email processing completed",
		logger.ProcessedCount(successCount),
		logger.FailedCount(failedCount),
		logger.Duration("duration_ms", duration),
	)

	return nil
}

// processOneEmail processes a single email (called by workers)
func processOneEmail(log logger.Logger, workerID int, rawEmail IncomingEmail) ProcessResult {
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
		log.Debug("No user found for email, skipping",
			logger.Email(rawEmail.EmailSendTo),
			logger.EmailID(rawEmail.ID),
		)
		return result
	}

	// Enforce email limit per user (keep max 10 inbox emails)
	enforceEmailLimit(userID, 10)

	// Parse the email content
	env, err := enmime.ReadEnvelope(bytes.NewReader(rawEmail.EmailData))
	if err != nil {
		result.Error = fmt.Errorf("failed to parse email: %w", err)
		markEmailFailed(rawEmail.ID)
		log.Error("Failed to parse email", err,
			logger.EmailID(rawEmail.ID),
			logger.MessageID(rawEmail.MessageID),
		)
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
			log.Warn("Failed to upload attachment",
				logger.String("filename", att.FileName),
				logger.Err(err),
			)
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

	// Insert into emails table — INSERT IGNORE prevents duplicates if two
	// concurrent processes (cron + manual trigger) race on the same message_id.
	_, err = config.DB.Exec(`
		INSERT IGNORE INTO emails (
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
		result.Error = fmt.Errorf("failed to insert email: %w", err)
		markEmailFailed(rawEmail.ID)
		log.Error("Failed to insert email to database", err,
			logger.EmailID(rawEmail.ID),
			logger.UserID(userID),
		)
		return result
	}

	config.IncrementCounter("total_inbox", 1)

	// Delete from incoming_emails after successful processing
	_, err = config.DB.Exec(`DELETE FROM incoming_emails WHERE id = ?`, rawEmail.ID)
	if err != nil {
		log.Warn("Failed to delete incoming email after processing",
			logger.EmailID(rawEmail.ID),
			logger.Err(err),
		)
	}

	result.Success = true
	log.Debug("Email processed successfully",
		logger.Email(rawEmail.EmailSendTo),
		logger.EmailID(rawEmail.ID),
		logger.UserID(userID),
	)
	return result
}

// enforceEmailLimit keeps only the latest N emails for a user
func enforceEmailLimit(userID int64, maxEmails int) {
	log := logger.Get().WithComponent("email_limit")

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
	result, err := config.DB.Exec(`
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
		log.Warn("Failed to enforce email limit",
			logger.UserID(userID),
			logger.Err(err),
		)
		return
	}

	rowsDeleted, _ := result.RowsAffected()
	if rowsDeleted > 0 {
		log.Debug("Enforced email limit",
			logger.UserID(userID),
			logger.Int64("deleted_count", rowsDeleted),
		)
		config.IncrementCounter("total_inbox", -rowsDeleted)
	}
}

// markEmailProcessed marks an email as processed without inserting
func markEmailProcessed(emailID int64) {
	_, err := config.DB.Exec(`
		UPDATE incoming_emails SET processed = TRUE WHERE id = ?
	`, emailID)
	if err != nil {
		log := logger.Get().WithComponent("email_processor")
		log.Warn("Failed to mark email as processed",
			logger.EmailID(emailID),
			logger.Err(err),
		)
	}
}

// markEmailFailed increments retry_count. Once it reaches MaxRetries the
// fetch query excludes the row, so it is never retried again.
func markEmailFailed(emailID int64) {
	_, err := config.DB.Exec(`
		UPDATE incoming_emails SET retry_count = retry_count + 1 WHERE id = ?
	`, emailID)
	if err != nil {
		log := logger.Get().WithComponent("email_processor")
		log.Warn("Failed to increment retry count",
			logger.EmailID(emailID),
			logger.Err(err),
		)
	}
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

// TriggerProcessEmailsHandler allows admins to manually trigger email processing
// via POST /admin/process-emails. Safe to call while cron is running — the
// processMu mutex ensures only one execution runs at a time.
func TriggerProcessEmailsHandler(c echo.Context) error {
	log := logger.Get().WithComponent("manual_process")
	log.Info("Manual email processing triggered")

	if err := ProcessAllPendingEmails(); err != nil {
		log.Error("Manual process failed", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "Failed to process emails",
		})
	}

	return c.JSON(http.StatusOK, map[string]string{
		"message": "Email processing completed",
	})
}
