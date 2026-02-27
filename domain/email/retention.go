package email

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Triaksa-Space/be-mail-platform/config"
	"github.com/Triaksa-Space/be-mail-platform/pkg/logger"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/labstack/echo/v4"
	"github.com/spf13/viper"
)

const retentionBatchSize = 1000
const retentionDays = 100
const retentionMaxBatchDelete = 500 // max rows to delete per API request

// RunDataRetention hard-deletes emails older than 100 days from emails,
// sent_emails, and incoming_emails tables. Emails aged exactly 100 days are
// kept; deletion starts at day 101. It also cleans up S3 attachments.
func RunDataRetention() error {
	log := logger.Get().WithComponent("retention")
	start := time.Now()

	log.Info("Data retention started",
		logger.Int("retention_days", retentionDays),
		logger.Int("batch_size", retentionBatchSize),
	)

	// Initialize S3 client for attachment cleanup
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(viper.GetString("AWS_REGION")),
	})
	if err != nil {
		log.Error("Failed to create AWS session", err)
		return fmt.Errorf("failed to create AWS session: %w", err)
	}
	s3Client := s3.New(sess)
	bucket := viper.GetString("AWS_S3_BUCKET")

	// 1. Delete from emails table (with S3 cleanup)
	emailsDeleted, err := retentionDeleteEmails(log, s3Client, bucket)
	if err != nil {
		log.Error("Retention failed on emails table", err)
	}

	// 2. Delete from sent_emails table (with S3 cleanup)
	sentDeleted, err := retentionDeleteSentEmails(log, s3Client, bucket)
	if err != nil {
		log.Error("Retention failed on sent_emails table", err)
	}

	// 3. Delete from incoming_emails table (no attachments to clean)
	incomingDeleted, err := retentionDeleteFromTable(log, "incoming_emails")
	if err != nil {
		log.Error("Retention failed on incoming_emails table", err)
	}

	// 4. Update dashboard counters
	if emailsDeleted > 0 {
		if _, err := config.DB.Exec(`
			UPDATE dashboard_counters
			SET counter_value = GREATEST(counter_value - ?, 0), updated_at = NOW()
			WHERE counter_key = 'total_inbox'
		`, emailsDeleted); err != nil {
			log.Error("Failed to update total_inbox counter", err)
		}
	}

	if sentDeleted > 0 {
		if _, err := config.DB.Exec(`
			UPDATE dashboard_counters
			SET counter_value = GREATEST(counter_value - ?, 0), updated_at = NOW()
			WHERE counter_key = 'total_sent'
		`, sentDeleted); err != nil {
			log.Error("Failed to update total_sent counter", err)
		}
	}

	duration := time.Since(start)
	log.Info("Data retention completed",
		logger.Int64("emails_deleted", emailsDeleted),
		logger.Int64("sent_emails_deleted", sentDeleted),
		logger.Int64("incoming_emails_deleted", incomingDeleted),
		logger.Duration("duration", duration),
	)

	return nil
}

// retentionDeleteEmails deletes old emails with S3 attachment cleanup.
func retentionDeleteEmails(log logger.Logger, s3Client *s3.S3, bucket string) (int64, error) {
	log = log.WithComponent("retention.emails")
	var totalDeleted int64

	for {
		// Fetch batch of emails to delete (need attachment URLs for S3 cleanup)
		var emails []struct {
			ID          int64  `db:"id"`
			Attachments string `db:"attachments"`
		}
		err := config.DB.Select(&emails, `
			SELECT id, COALESCE(attachments, '') AS attachments
			FROM emails
			WHERE created_at < NOW() - INTERVAL 101 DAY
			ORDER BY id ASC
			LIMIT ?
		`, retentionBatchSize)
		if err != nil {
			return totalDeleted, fmt.Errorf("failed to fetch emails for retention: %w", err)
		}

		if len(emails) == 0 {
			break
		}

		// Delete S3 attachments for this batch
		for _, e := range emails {
			if e.Attachments == "" || e.Attachments == "[]" || e.Attachments == "null" {
				continue
			}
			deleteS3Attachments(log, s3Client, bucket, e.ID, e.Attachments)
		}

		// Collect IDs for batch delete
		ids := make([]int64, len(emails))
		for i, e := range emails {
			ids[i] = e.ID
		}

		// Batch delete by IDs
		deleted, err := deleteByIDs(log, "emails", ids)
		if err != nil {
			return totalDeleted, err
		}
		totalDeleted += deleted

		log.Debug("Batch deleted from emails",
			logger.Int64("batch_deleted", deleted),
			logger.Int64("total_deleted", totalDeleted),
		)
	}

	log.Info("Emails retention complete", logger.Int64("total_deleted", totalDeleted))
	return totalDeleted, nil
}

// retentionDeleteSentEmails deletes old sent_emails with S3 attachment cleanup.
func retentionDeleteSentEmails(log logger.Logger, s3Client *s3.S3, bucket string) (int64, error) {
	log = log.WithComponent("retention.sent_emails")
	var totalDeleted int64

	for {
		// Fetch batch of sent_emails to delete
		var emails []struct {
			ID          int64   `db:"id"`
			Attachments *string `db:"attachments"`
		}
		err := config.DB.Select(&emails, `
			SELECT id, attachments
			FROM sent_emails
			WHERE created_at < NOW() - INTERVAL 101 DAY
			ORDER BY id ASC
			LIMIT ?
		`, retentionBatchSize)
		if err != nil {
			return totalDeleted, fmt.Errorf("failed to fetch sent_emails for retention: %w", err)
		}

		if len(emails) == 0 {
			break
		}

		// Delete S3 attachments for this batch
		for _, e := range emails {
			if e.Attachments == nil || *e.Attachments == "" || *e.Attachments == "[]" || *e.Attachments == "null" {
				continue
			}
			deleteS3Attachments(log, s3Client, bucket, e.ID, *e.Attachments)
		}

		// Collect IDs for batch delete
		ids := make([]int64, len(emails))
		for i, e := range emails {
			ids[i] = e.ID
		}

		deleted, err := deleteByIDs(log, "sent_emails", ids)
		if err != nil {
			return totalDeleted, err
		}
		totalDeleted += deleted

		log.Debug("Batch deleted from sent_emails",
			logger.Int64("batch_deleted", deleted),
			logger.Int64("total_deleted", totalDeleted),
		)
	}

	log.Info("Sent emails retention complete", logger.Int64("total_deleted", totalDeleted))
	return totalDeleted, nil
}

// retentionDeleteFromTable batch-deletes old rows from a table (no S3 cleanup).
func retentionDeleteFromTable(log logger.Logger, table string) (int64, error) {
	log = log.WithComponent("retention." + table)
	var totalDeleted int64

	for {
		result, err := config.DB.Exec(fmt.Sprintf(`
			DELETE FROM %s
			WHERE created_at < NOW() - INTERVAL 101 DAY
			ORDER BY id ASC
			LIMIT ?
		`, table), retentionBatchSize)
		if err != nil {
			return totalDeleted, fmt.Errorf("failed to delete from %s: %w", table, err)
		}

		affected, err := result.RowsAffected()
		if err != nil {
			return totalDeleted, fmt.Errorf("failed to get rows affected for %s: %w", table, err)
		}

		totalDeleted += affected

		if affected < retentionBatchSize {
			break
		}

		log.Debug("Batch deleted from "+table,
			logger.Int64("batch_deleted", affected),
			logger.Int64("total_deleted", totalDeleted),
		)
	}

	log.Info(table+" retention complete", logger.Int64("total_deleted", totalDeleted))
	return totalDeleted, nil
}

// deleteByIDs deletes rows by their IDs from the given table.
func deleteByIDs(log logger.Logger, table string, ids []int64) (int64, error) {
	if len(ids) == 0 {
		return 0, nil
	}

	placeholders := make([]string, len(ids))
	args := make([]interface{}, len(ids))
	for i, id := range ids {
		placeholders[i] = "?"
		args[i] = id
	}

	query := fmt.Sprintf("DELETE FROM %s WHERE id IN (%s)", table, strings.Join(placeholders, ","))
	result, err := config.DB.Exec(query, args...)
	if err != nil {
		return 0, fmt.Errorf("failed to delete from %s by IDs: %w", table, err)
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to get rows affected for %s: %w", table, err)
	}

	return affected, nil
}

// ListRetentionEmailsHandler returns paginated emails that are >= retentionDays old.
// GET /admin/retention/emails?table=emails&page=1&limit=50
func ListRetentionEmailsHandler(c echo.Context) error {
	log := logger.Get().WithComponent("retention_list")

	tableParam := c.QueryParam("table")
	if tableParam == "" {
		tableParam = "emails"
	}
	allowedTables := map[string]bool{
		"emails":          true,
		"sent_emails":     true,
		"incoming_emails": true,
	}
	if !allowedTables[tableParam] {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "table must be one of: emails, sent_emails, incoming_emails",
		})
	}

	page, _ := strconv.Atoi(c.QueryParam("page"))
	if page < 1 {
		page = 1
	}
	limit, _ := strconv.Atoi(c.QueryParam("limit"))
	if limit < 1 || limit > 200 {
		limit = 50
	}
	offset := (page - 1) * limit

	var total int
	if err := config.DB.Get(&total, fmt.Sprintf(
		"SELECT COUNT(*) FROM %s WHERE created_at < NOW() - INTERVAL %d DAY",
		tableParam, retentionDays,
	)); err != nil {
		log.Error("Failed to count retention emails", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to count"})
	}

	// Build column list per table using a safe alias
	var selectSQL string
	switch tableParam {
	case "emails":
		selectSQL = fmt.Sprintf(
			"SELECT id, COALESCE(subject,'') AS subject, sender_email, created_at"+
				" FROM emails WHERE created_at < NOW() - INTERVAL %d DAY"+
				" ORDER BY id ASC LIMIT ? OFFSET ?", retentionDays)
	case "sent_emails":
		selectSQL = fmt.Sprintf(
			"SELECT id, COALESCE(subject,'') AS subject, from_email AS sender_email, created_at"+
				" FROM sent_emails WHERE created_at < NOW() - INTERVAL %d DAY"+
				" ORDER BY id ASC LIMIT ? OFFSET ?", retentionDays)
	case "incoming_emails":
		selectSQL = fmt.Sprintf(
			"SELECT id, '' AS subject, email_send_to AS sender_email, created_at"+
				" FROM incoming_emails WHERE created_at < NOW() - INTERVAL %d DAY"+
				" ORDER BY id ASC LIMIT ? OFFSET ?", retentionDays)
	}

	type retentionRow struct {
		ID          int64     `db:"id"`
		Subject     string    `db:"subject"`
		SenderEmail string    `db:"sender_email"`
		CreatedAt   time.Time `db:"created_at"`
	}
	var rows []retentionRow
	if err := config.DB.Select(&rows, selectSQL, limit, offset); err != nil {
		log.Error("Failed to list retention emails", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to list"})
	}

	type responseItem struct {
		ID          int64     `json:"id"`
		Subject     string    `json:"subject,omitempty"`
		SenderEmail string    `json:"sender_email,omitempty"`
		CreatedAt   time.Time `json:"created_at"`
		AgeDays     int       `json:"age_days"`
	}
	now := time.Now()
	items := make([]responseItem, len(rows))
	for i, r := range rows {
		items[i] = responseItem{
			ID:          r.ID,
			Subject:     r.Subject,
			SenderEmail: r.SenderEmail,
			CreatedAt:   r.CreatedAt,
			AgeDays:     int(now.Sub(r.CreatedAt).Hours() / 24),
		}
	}

	totalPages := (total + limit - 1) / limit
	return c.JSON(http.StatusOK, map[string]interface{}{
		"table": tableParam,
		"data":  items,
		"pagination": map[string]interface{}{
			"page":        page,
			"limit":       limit,
			"total":       total,
			"total_pages": totalPages,
		},
	})
}

// BatchDeleteRetentionEmailsHandler hard-deletes the oldest N expired emails.
// DELETE /admin/retention/emails
// Body: { "table": "emails", "limit": 100 }  — max 500 per request
func BatchDeleteRetentionEmailsHandler(c echo.Context) error {
	log := logger.Get().WithComponent("retention_batch_delete")

	var req struct {
		Table string `json:"table"`
		Limit int    `json:"limit"`
	}
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}

	allowedTables := map[string]bool{
		"emails":          true,
		"sent_emails":     true,
		"incoming_emails": true,
	}
	if !allowedTables[req.Table] {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "table must be one of: emails, sent_emails, incoming_emails",
		})
	}
	if req.Limit < 1 {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "limit must be >= 1"})
	}
	if req.Limit > retentionMaxBatchDelete {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": fmt.Sprintf("max limit is %d per request", retentionMaxBatchDelete),
		})
	}

	// Fetch the oldest N eligible rows (+ attachments for S3 cleanup)
	type fetchRow struct {
		ID          int64  `db:"id"`
		Attachments string `db:"attachments"`
	}
	var fetchSQL string
	if req.Table == "emails" || req.Table == "sent_emails" {
		fetchSQL = fmt.Sprintf(
			"SELECT id, COALESCE(attachments,'') AS attachments FROM %s"+
				" WHERE created_at < NOW() - INTERVAL %d DAY"+
				" ORDER BY id ASC LIMIT ?",
			req.Table, retentionDays)
	} else {
		fetchSQL = fmt.Sprintf(
			"SELECT id, '' AS attachments FROM %s"+
				" WHERE created_at < NOW() - INTERVAL %d DAY"+
				" ORDER BY id ASC LIMIT ?",
			req.Table, retentionDays)
	}
	var rows []fetchRow
	if err := config.DB.Select(&rows, fetchSQL, req.Limit); err != nil {
		log.Error("Failed to fetch rows for retention delete", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to fetch rows"})
	}
	if len(rows) == 0 {
		return c.JSON(http.StatusOK, map[string]interface{}{
			"deleted": 0,
			"table":   req.Table,
		})
	}

	// Build IN clause from fetched IDs
	placeholders := make([]string, len(rows))
	args := make([]interface{}, len(rows))
	for i, r := range rows {
		placeholders[i] = "?"
		args[i] = r.ID
	}
	inClause := strings.Join(placeholders, ",")

	// For emails and sent_emails: clean up S3 attachments before deleting rows
	if req.Table == "emails" || req.Table == "sent_emails" {
		sess, err := session.NewSession(&aws.Config{
			Region: aws.String(viper.GetString("AWS_REGION")),
		})
		if err != nil {
			log.Warn("Failed to create AWS session for S3 cleanup",
				logger.String("error", err.Error()),
			)
		} else {
			s3Client := s3.New(sess)
			bucket := viper.GetString("AWS_S3_BUCKET")
			for _, row := range rows {
				if row.Attachments == "" || row.Attachments == "[]" || row.Attachments == "null" {
					continue
				}
				deleteS3Attachments(log, s3Client, bucket, row.ID, row.Attachments)
			}
		}
	}

	// Delete by IDs (date guard ensures only truly old rows are removed)
	deleteSQL := fmt.Sprintf(
		"DELETE FROM %s WHERE id IN (%s) AND created_at < NOW() - INTERVAL %d DAY",
		req.Table, inClause, retentionDays,
	)
	result, err := config.DB.Exec(deleteSQL, args...)
	if err != nil {
		log.Error("Failed to batch delete retention emails", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to delete"})
	}
	deleted, _ := result.RowsAffected()

	// Update dashboard counters
	if deleted > 0 {
		switch req.Table {
		case "emails":
			if _, err := config.DB.Exec(`
				UPDATE dashboard_counters
				SET counter_value = GREATEST(counter_value - ?, 0), updated_at = NOW()
				WHERE counter_key = 'total_inbox'
			`, deleted); err != nil {
				log.Warn("Failed to update total_inbox counter",
					logger.String("error", err.Error()),
				)
			}
		case "sent_emails":
			if _, err := config.DB.Exec(`
				UPDATE dashboard_counters
				SET counter_value = GREATEST(counter_value - ?, 0), updated_at = NOW()
				WHERE counter_key = 'total_sent'
			`, deleted); err != nil {
				log.Warn("Failed to update total_sent counter",
					logger.String("error", err.Error()),
				)
			}
		}
	}

	log.Info("Batch retention delete complete",
		logger.String("table", req.Table),
		logger.Int("limit", req.Limit),
		logger.Int64("deleted", deleted),
	)
	return c.JSON(http.StatusOK, map[string]interface{}{
		"deleted": deleted,
		"table":   req.Table,
	})
}

// deleteS3Attachments parses attachment URLs and deletes them from S3.
// Errors are logged but do not block email deletion.
func deleteS3Attachments(log logger.Logger, s3Client *s3.S3, bucket string, emailID int64, attachmentsJSON string) {
	urls, err := parseAttachments(attachmentsJSON)
	if err != nil {
		log.Warn("Failed to parse attachments",
			logger.Int64("email_id", emailID),
			logger.String("error", err.Error()),
		)
		return
	}

	for _, url := range urls {
		key, err := extractS3KeyFromURL(url, bucket)
		if err != nil {
			log.Warn("Failed to extract S3 key",
				logger.Int64("email_id", emailID),
				logger.String("url", url),
				logger.String("error", err.Error()),
			)
			continue
		}

		_, err = s3Client.DeleteObject(&s3.DeleteObjectInput{
			Bucket: aws.String(bucket),
			Key:    aws.String(key),
		})
		if err != nil {
			log.Warn("Failed to delete S3 object",
				logger.Int64("email_id", emailID),
				logger.String("key", key),
				logger.String("error", err.Error()),
			)
			continue
		}
	}
}
