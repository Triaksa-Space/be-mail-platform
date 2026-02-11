package user

import (
	"database/sql"
	"encoding/csv"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Triaksa-Space/be-mail-platform/config"
	"github.com/Triaksa-Space/be-mail-platform/pkg"
	"github.com/Triaksa-Space/be-mail-platform/pkg/apperrors"
	"github.com/Triaksa-Space/be-mail-platform/pkg/logger"
	"github.com/Triaksa-Space/be-mail-platform/utils"
	"github.com/spf13/viper"

	"github.com/labstack/echo/v4"
	"golang.org/x/exp/rand"
)

// NOTE: LoginHandler and LogoutHandler have been moved to domain/auth package
// Use auth.LoginHandler for /login and /user/login routes

func ChangePasswordAdminHandler(c echo.Context) error {
	log := logger.Get().WithComponent("user")
	superAdminID := c.Get("user_id").(int64)
	log = log.WithUserID(superAdminID)

	_, err := getUserAdminByID(superAdminID)
	if err != nil {
		log.Warn("Access denied - not an admin")
		return apperrors.RespondWithError(c, apperrors.NewForbidden(
			apperrors.ErrCodeForbidden,
			"Access Denied.",
		))
	}

	req := new(AdminChangePasswordRequest)
	if err := c.Bind(req); err != nil {
		return apperrors.RespondWithError(c, apperrors.NewBadRequest(
			apperrors.ErrCodeValidationFailed,
			"Invalid request payload.",
		))
	}

	if req.UserID == 0 {
		req.UserID = int(superAdminID)
	}

	var hashedPassword string
	err = config.DB.Get(&hashedPassword, "SELECT password FROM users WHERE id = ?", req.UserID)
	if err != nil {
		log.Error("Failed to fetch user password", err, logger.Int("target_user_id", req.UserID))
		return apperrors.RespondWithError(c, apperrors.NewInternal(
			apperrors.ErrCodeDatabaseError,
			"Internal server error.",
			err,
		))
	}

	if req.UserID != 0 && req.OldPassword != "" {
		if !utils.CheckPasswordHash(req.OldPassword, hashedPassword) {
			return apperrors.RespondWithError(c, apperrors.NewUnauthorized(
				apperrors.ErrCodeInvalidPassword,
				"The password you entered is incorrect.",
			))
		}

		if utils.CheckPasswordHash(req.NewPassword, hashedPassword) {
			return apperrors.RespondWithError(c, apperrors.NewBadRequest(
				apperrors.ErrCodeValidationFailed,
				"The new password cannot be the same as the old password.",
			))
		}
	}

	newHashedPassword, err := utils.HashPassword(req.NewPassword)
	if err != nil {
		log.Error("Failed to hash new password", err)
		return apperrors.RespondWithError(c, apperrors.NewInternal(
			apperrors.ErrCodeUnexpectedError,
			"Internal server error.",
			err,
		))
	}

	_, err = config.DB.Exec("UPDATE users SET password = ?, updated_at = NOW() WHERE id = ?", newHashedPassword, req.UserID)
	if err != nil {
		log.Error("Failed to update password", err, logger.Int("target_user_id", req.UserID))
		return apperrors.RespondWithError(c, apperrors.NewInternal(
			apperrors.ErrCodeDatabaseError,
			"Internal server error.",
			err,
		))
	}

	if err := updateLastLogin(superAdminID); err != nil {
		log.Warn("Failed to update last login", logger.Err(err))
	}

	log.Info("Admin password changed successfully", logger.Int("target_user_id", req.UserID))
	return c.JSON(http.StatusOK, map[string]string{"message": "Password updated successfully."})
}

func ChangePasswordHandler(c echo.Context) error {
	log := logger.Get().WithComponent("user")
	userID := c.Get("user_id").(int64)
	log = log.WithUserID(userID)

	req := new(ChangePasswordRequest)
	if err := c.Bind(req); err != nil {
		return apperrors.RespondWithError(c, apperrors.NewBadRequest(
			apperrors.ErrCodeValidationFailed,
			"Invalid request payload.",
		))
	}

	if req.UserID == 0 {
		req.UserID = int(userID)
	}

	var user struct {
		HashedPassword string     `db:"password"`
		FailedAttempts int        `db:"failed_attempts"`
		LastFailedAt   *time.Time `db:"last_failed_at"`
	}

	err := config.DB.Get(&user, `
        SELECT password, failed_attempts, last_failed_at
        FROM users WHERE id = ?`, req.UserID)
	if err != nil {
		log.Error("Failed to fetch user data for password change", err)
		return apperrors.RespondWithError(c, apperrors.NewInternal(
			apperrors.ErrCodeDatabaseError,
			"Internal server error.",
			err,
		))
	}

	maxAttempts := 5
	blockDuration := time.Hour
	if user.FailedAttempts >= maxAttempts && user.LastFailedAt != nil {
		if time.Since(*user.LastFailedAt) < blockDuration {
			log.Warn("Password change blocked - too many failed attempts")
			return apperrors.RespondWithError(c, apperrors.NewTooManyRequests(
				apperrors.ErrCodeRateLimitExceeded,
				"Account is temporarily locked. Please try again later.",
			))
		} else {
			_, err = config.DB.Exec(`
                UPDATE users
                SET failed_attempts = 0,
                    last_failed_at = NULL
                WHERE id = ?`, req.UserID)
			if err != nil {
				log.Error("Failed to reset failed attempts", err)
				return apperrors.RespondWithError(c, apperrors.NewInternal(
					apperrors.ErrCodeDatabaseError,
					"Internal server error.",
					err,
				))
			}
			user.FailedAttempts = 0
			user.LastFailedAt = nil
		}
	}

	if req.OldPassword != "" {
		if !utils.CheckPasswordHash(req.OldPassword, user.HashedPassword) {
			log.Debug("Incorrect old password provided")

			_, err = config.DB.Exec(`
                UPDATE users
                SET failed_attempts = failed_attempts + 1,
                    last_failed_at = NOW()
                WHERE id = ?`, req.UserID)
			if err != nil {
				log.Error("Failed to increment failed attempts", err)
			}

			return apperrors.RespondWithError(c, apperrors.NewUnauthorized(
				apperrors.ErrCodeInvalidPassword,
				"The password you entered is incorrect.",
			))
		}

		if utils.CheckPasswordHash(req.NewPassword, user.HashedPassword) {
			return apperrors.RespondWithError(c, apperrors.NewBadRequest(
				apperrors.ErrCodeValidationFailed,
				"The new password cannot be the same as the old password.",
			))
		}
	}

	newHashedPassword, err := utils.HashPassword(req.NewPassword)
	if err != nil {
		log.Error("Failed to hash new password", err)
		return apperrors.RespondWithError(c, apperrors.NewInternal(
			apperrors.ErrCodeUnexpectedError,
			"Internal server error.",
			err,
		))
	}

	// Update the user's password and reset failed attempts
	_, err = config.DB.Exec(`
        UPDATE users
        SET password = ?,
            failed_attempts = 0,
            last_failed_at = NULL,
            updated_at = NOW()
        WHERE id = ?`, newHashedPassword, req.UserID)
	if err != nil {
		log.Error("Failed to update password in database", err)
		return apperrors.RespondWithError(c, apperrors.NewInternal(
			apperrors.ErrCodeDatabaseError,
			"Internal server error.",
			err,
		))
	}

	if err := updateLastLogin(userID); err != nil {
		log.Warn("Failed to update last login", logger.Err(err))
	}

	log.Info("Password changed successfully")
	return c.JSON(http.StatusOK, map[string]string{"message": "Password changed successfully."})
}

func CreateUserAdminHandler(c echo.Context) error {
	log := logger.Get().WithComponent("user")
	userID := c.Get("user_id").(int64)
	log = log.WithUserID(userID)

	req := new(CreateAdminRequest)
	if err := c.Bind(req); err != nil {
		return apperrors.RespondWithError(c, apperrors.NewBadRequest(
			apperrors.ErrCodeValidationFailed,
			"Invalid request payload.",
		))
	}

	userName, err := getUserSuperAdminByID(userID)
	if err != nil {
		log.Error("Failed to verify super admin", err)
		return apperrors.RespondWithError(c, apperrors.NewForbidden(
			apperrors.ErrCodeForbidden,
			"Access denied.",
		))
	}

	hashedPassword, err := utils.HashPassword(req.Password)
	if err != nil {
		log.Error("Failed to hash password", err)
		return apperrors.RespondWithError(c, apperrors.NewInternal(
			apperrors.ErrCodeUnexpectedError,
			"Internal server error.",
			err,
		))
	}

	_, err = config.DB.Exec(
		"INSERT INTO users (email, password, role_id, created_at, updated_at, last_login, created_by, updated_by, created_by_name, updated_by_name) VALUES (?, ?, ?, NOW(), NOW(), NOW(), ?, ?, ?, ?)",
		req.Username, hashedPassword, 2, userID, userID, userName, userName,
	)
	if err != nil {
		log.Error("Failed to create admin user", err, logger.Email(req.Username))
		return apperrors.RespondWithError(c, apperrors.NewInternal(
			apperrors.ErrCodeDatabaseError,
			"Failed to create user.",
			err,
		))
	}

	log.Info("Admin user created successfully", logger.Email(req.Username))
	return c.JSON(http.StatusCreated, map[string]string{"message": "User created successfully."})
}

func CreateInitUserAdminHandler(c echo.Context) error {
	// log := logger.Get().WithComponent("user")
	// userID := c.Get("user_id").(int64)
	// log = log.WithUserID(userID)

	req := new(CreateAdminRequest)
	if err := c.Bind(req); err != nil {
		return apperrors.RespondWithError(c, apperrors.NewBadRequest(
			apperrors.ErrCodeValidationFailed,
			"Invalid request payload.",
		))
	}

	// userName, err := getUserSuperAdminByID(userID)
	// if err != nil {
	// 	log.Error("Failed to verify super admin", err)
	// 	return apperrors.RespondWithError(c, apperrors.NewForbidden(
	// 		apperrors.ErrCodeForbidden,
	// 		"Access denied",
	// 	))
	// }

	hashedPassword, err := utils.HashPassword(req.Password)
	if err != nil {
		// log.Error("Failed to hash password", err)
		return apperrors.RespondWithError(c, apperrors.NewInternal(
			apperrors.ErrCodeUnexpectedError,
			"Internal server error.",
			err,
		))
	}

	_, err = config.DB.Exec(
		"INSERT INTO users (email, password, role_id, created_at, updated_at, last_login, created_by, updated_by, created_by_name, updated_by_name) VALUES (?, ?, ?, NOW(), NOW(), NOW(), ?, ?, ?, ?)",
		req.Username, hashedPassword, 0, 0, 0, "", "",
	)
	if err != nil {
		// log.Error("Failed to create admin user", err, logger.Email(req.Username))
		return apperrors.RespondWithError(c, apperrors.NewInternal(
			apperrors.ErrCodeDatabaseError,
			"Failed to create user.",
			err,
		))
	}

	// log.Info("Admin user created successfully", logger.Email(req.Username))
	return c.JSON(http.StatusCreated, map[string]string{"message": "User created successfully."})
}

func CreateUserHandler(c echo.Context) error {
	log := logger.Get().WithComponent("user")
	userID := c.Get("user_id").(int64)
	log = log.WithUserID(userID)

	req := new(CreateUserRequest)
	if err := c.Bind(req); err != nil {
		return apperrors.RespondWithError(c, apperrors.NewBadRequest(
			apperrors.ErrCodeValidationFailed,
			"Invalid request payload.",
		))
	}

	userName, err := getUserAdminByID(userID)
	if err != nil {
		log.Error("Failed to verify admin permissions", err)
		return apperrors.RespondWithError(c, apperrors.NewForbidden(
			apperrors.ErrCodeForbidden,
			"Access denied.",
		))
	}

	hashedPassword, err := utils.HashPassword(req.Password)
	if err != nil {
		log.Error("Failed to hash password", err)
		return apperrors.RespondWithError(c, apperrors.NewInternal(
			apperrors.ErrCodeUnexpectedError,
			"Internal server error.",
			err,
		))
	}

	_, err = config.DB.Exec(
		"INSERT INTO users (email, password, role_id, created_at, updated_at, last_login, created_by, updated_by, created_by_name, updated_by_name) VALUES (?, ?, ?, NOW(), NOW(), NOW(), ?, ?, ?, ?)",
		req.Email, hashedPassword, 1, userID, userID, userName, userName,
	)
	if err != nil {
		log.Error("Failed to create user", err, logger.Email(req.Email))
		return apperrors.RespondWithError(c, apperrors.NewInternal(
			apperrors.ErrCodeDatabaseError,
			"Failed to create user.",
			err,
		))
	}

	// Insert into table generated_email
	_, err = config.DB.Exec(
		"INSERT INTO generated_emails (username, created_at, updated_at, created_by, updated_by) VALUES (?, NOW(), NOW(), ?, ?)",
		req.Email, userID, userID, // Hardcoded role ID for no, userName, userNamew
	)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	return c.JSON(http.StatusCreated, map[string]string{"message": "User created successfully."})
}

// generateBaseUsernames generates all potential usernames based on request parameters
// Returns a slice of base usernames (before collision resolution)
func generateBaseUsernames(baseName string, domain string, quantity int, names [][]string) ([]string, error) {
	usernames := make([]string, 0, quantity)

	for i := 0; i < quantity; i++ {
		var username string
		if baseName == "random" {
			if len(names) == 0 {
				return nil, fmt.Errorf("no names available")
			}
			name := names[i%len(names)]
			username = fmt.Sprintf("%s%s@%s", name[0], name[1], domain)
		} else {
			username = fmt.Sprintf("%s@%s", baseName, domain)
			if i > 0 {
				username = fmt.Sprintf("%s%d@%s", baseName, i, domain)
			}
		}
		usernames = append(usernames, strings.ToLower(username))
	}

	return usernames, nil
}

// batchCheckExistingEmails checks which emails already exist in the database
// Returns a map of existing emails for O(1) lookup
func batchCheckExistingEmails(emails []string, domain string) (map[string]bool, error) {
	existingMap := make(map[string]bool)
	if len(emails) == 0 {
		return existingMap, nil
	}

	// Get all users with matching domain to check for collisions
	// This fetches all emails at once instead of one-by-one
	var existingEmails []string
	query := "SELECT email FROM users WHERE email LIKE ?"
	err := config.DB.Select(&existingEmails, query, "%@"+domain)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch existing emails: %w", err)
	}

	// Build lookup map
	for _, email := range existingEmails {
		existingMap[strings.ToLower(email)] = true
	}

	return existingMap, nil
}

// findAvailableUsername finds an available username given existing emails map
// It modifies the existingMap to track newly allocated usernames
func findAvailableUsername(baseUsername string, domain string, existingMap map[string]bool) string {
	username := strings.ToLower(baseUsername)

	// If doesn't exist, use it directly
	if !existingMap[username] {
		existingMap[username] = true // Mark as taken for subsequent calls
		return username
	}

	// Extract the local part before @
	localPart := strings.Split(username, "@")[0]

	// Extract trailing digits from the original username
	re := regexp.MustCompile(`^(.*?)(\d+)$`)
	matches := re.FindStringSubmatch(localPart)

	var namePart string
	var counter int

	if len(matches) == 3 {
		namePart = matches[1]
		counter, _ = strconv.Atoi(matches[2])
		counter++ // Start from the next number
	} else {
		namePart = localPart
		counter = 1
	}

	// Find available username by incrementing counter
	for {
		candidate := fmt.Sprintf("%s%d@%s", namePart, counter, domain)
		if !existingMap[candidate] {
			existingMap[candidate] = true // Mark as taken
			return candidate
		}
		counter++
		// Safety limit to prevent infinite loops
		if counter > 100000 {
			break
		}
	}

	return username // Fallback (shouldn't reach here normally)
}

func BulkCreateUserHandler(c echo.Context) error {
	log := logger.Get().WithComponent("user_bulk_create")
	userID := c.Get("user_id").(int64)
	log = log.WithUserID(userID)

	userName, err := getUserAdminByID(userID)
	if err != nil {
		log.Error("Failed to get admin user", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	req := new(BulkCreateUserRequest)
	if err := c.Bind(req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	if req.BaseName == "" || req.Quantity == 0 {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "BaseName and Quantity are required."})
	}

	log.Info("Starting bulk user creation",
		logger.Int("quantity", req.Quantity),
		logger.String("domain", req.Domain),
		logger.String("base_name", req.BaseName),
	)

	// Load names if random mode
	var names [][]string
	if req.BaseName == "random" {
		file, err := os.Open("names.csv")
		if err != nil {
			log.Warn("Failed to open names.csv, using default list", logger.Err(err))
			names = ListOfNames
		} else {
			defer file.Close()
			reader := csv.NewReader(file)
			names, err = reader.ReadAll()
			if err != nil {
				log.Error("Failed to read names.csv", err)
				return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to read names.csv."})
			}
		}
		rand.Seed(uint64(time.Now().UnixNano()))
		rand.Shuffle(len(names), func(i, j int) { names[i], names[j] = names[j], names[i] })
	}

	// Step 1: Generate all base usernames
	baseUsernames, err := generateBaseUsernames(req.BaseName, req.Domain, req.Quantity, names)
	if err != nil {
		log.Error("Failed to generate usernames", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	// Step 2: Batch check existing emails (single query instead of N queries)
	existingMap, err := batchCheckExistingEmails(baseUsernames, req.Domain)
	if err != nil {
		log.Error("Failed to check existing emails", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	// Step 3: Resolve collisions and get final usernames
	finalUsernames := make([]string, 0, req.Quantity)
	for _, baseUsername := range baseUsernames {
		availableUsername := findAvailableUsername(baseUsername, req.Domain, existingMap)
		finalUsernames = append(finalUsernames, availableUsername)
	}

	// Step 4: Hash password once (same for all users in this batch)
	hashedPassword, err := utils.HashPassword(req.Password)
	if err != nil {
		log.Error("Failed to hash password", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	// Step 5: Create users in a single transaction
	createdUsers := []map[string]string{}
	skippedUsers := []map[string]string{}

	tx, err := config.DB.Begin()
	if err != nil {
		log.Error("Failed to start transaction", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	defer tx.Rollback()

	for i, username := range finalUsernames {
		// Insert user
		_, err = tx.Exec(
			"INSERT INTO users (email, password, role_id, created_at, updated_at, last_login, created_by, updated_by, created_by_name, updated_by_name) VALUES (?, ?, 1, NOW(), NOW(), NOW(), ?, ?, ?, ?)",
			username, hashedPassword, userID, userID, userName, userName,
		)
		if err != nil {
			log.Warn("Failed to insert user", logger.String("email", username), logger.Err(err))
			skippedUsers = append(skippedUsers, map[string]string{"email": username, "reason": err.Error()})
			continue
		}

		// Insert generated email
		_, err = tx.Exec(
			"INSERT INTO generated_emails (username, created_at, updated_at, created_by, updated_by) VALUES (?, NOW(), NOW(), ?, ?)",
			username, userID, userID,
		)
		if err != nil {
			log.Warn("Failed to insert generated email", logger.String("email", username), logger.Err(err))
			continue
		}

		createdUsers = append(createdUsers, map[string]string{
			"No":       fmt.Sprintf("%d", i+1),
			"Email":    username,
			"Password": req.Password,
		})
	}

	if err := tx.Commit(); err != nil {
		log.Error("Failed to commit transaction", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	log.Info("Bulk user creation completed",
		logger.Int("created", len(createdUsers)),
		logger.Int("skipped", len(skippedUsers)),
	)

	// Generate the email body with enhanced styling
	var emailBody strings.Builder
	emailBody.WriteString(`
    <table style="width: 100%; border-collapse: collapse;">
        <tr style="background-color: #f2f2f2;">
            <th style="border: 1px solid #ddd; padding: 8px; width: 50px; text-align: center;">No</th>
            <th style="border: 1px solid #ddd; padding: 8px;">Email</th>
            <th style="border: 1px solid #ddd; padding: 8px;">Password</th>
        </tr>
`)

	for i, user := range createdUsers {
		emailBody.WriteString(fmt.Sprintf(`
        <tr>
            <td style="border: 1px solid #ddd; padding: 8px; text-align: center;">%d</td>
            <td style="border: 1px solid #ddd; padding: 8px;">%s</td>
            <td style="border: 1px solid #ddd; padding: 8px;">%s</td>
        </tr>
    `, i+1, user["Email"], user["Password"]))
	}

	emailBody.WriteString("</table>")

	emailUser := viper.GetString("EMAIL_SUPPORT")
	err = pkg.SendEmailViaResend(emailUser, req.SendTo, "Mailria Create Bulk User", emailBody.String(), nil)
	if err != nil {
		log.Error("Failed to send email", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": err.Error(),
		})
	}

	return c.JSON(http.StatusCreated, map[string]interface{}{
		"message":       fmt.Sprintf("%d users created successfully", len(createdUsers)),
		"created_users": createdUsers,
		"skipped_users": skippedUsers,
		"send_to":       req.SendTo,
		"email_body":    emailBody.String(),
	})
}

func DeleteUserAdminHandler(c echo.Context) error {
	userID := c.Param("id")

	// Get user email before deletion for S3
	var userEmail string
	err := config.DB.Get(&userEmail, "SELECT email FROM users WHERE id = ? and role_id=2", userID) // 2 is admin 1 is userEmail 0 is superAdmin
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "User not found."})
	}

	// Start transaction
	tx, err := config.DB.Begin()
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to start transaction."})
	}
	defer tx.Rollback()

	// Delete emails
	_, err = tx.Exec("DELETE FROM emails WHERE user_id = ?", userID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to delete emails."})
	}

	// Delete user
	result, err := tx.Exec("DELETE FROM users WHERE id = ?", userID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to delete user."})
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "User not found."})
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to commit transaction."})
	}

	return c.JSON(http.StatusOK, map[string]string{"message": "User and associated data deleted successfully."})
}

// ONLY ADMIN CAN DELETE USER EMAIL
func DeleteUserHandler(c echo.Context) error {
	userID := c.Param("id")

	// Get user email before deletion for S3
	var userEmail string
	err := config.DB.Get(&userEmail, "SELECT email FROM users WHERE id = ? and role_id=1", userID)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "User not found."})
	}

	// Start transaction
	tx, err := config.DB.Begin()
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to start transaction."})
	}
	defer tx.Rollback()

	// Delete emails
	_, err = tx.Exec("DELETE FROM emails WHERE user_id = ?", userID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to delete emails."})
	}

	// Delete user
	result, err := tx.Exec("DELETE FROM users WHERE id = ?", userID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to delete user."})
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "User not found."})
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to commit transaction."})
	}

	// TODO: SEARCH HIS ATTACHMENT AND DELETE IT
	// // Initialize AWS session
	// sess, _ := pkg.InitAWS()
	// s3Client, _ := pkg.InitS3(sess)

	// // Delete S3 folder
	// bucketName := viper.GetString("S3_BUCKET_NAME")
	// prefix := fmt.Sprintf("%s/", userEmail)

	// // List and delete all objects with the user's prefix
	// err = pkg.DeleteS3FolderContents(s3Client, bucketName, prefix)
	// if err != nil {
	// 	fmt.Println("Failed to delete S3 folder:", err)
	// 	return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to delete user files."})
	// }

	return c.JSON(http.StatusOK, map[string]string{"message": "User and associated data deleted successfully."})
}

func GetUserHandler(c echo.Context) error {
	userID := c.Param("id")

	userIDDecode, err := utils.DecodeID(userID)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid user ID."})
	}

	userID = strconv.Itoa(userIDDecode)

	// Fetch user details by ID
	var user User
	err = config.DB.Get(&user, "SELECT * FROM users WHERE role_id = 1 AND id = ?", userID)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": err.Error()})
	}

	return c.JSON(http.StatusOK, user)
}

func GetUserMeHandler(c echo.Context) error {
	// Extract user ID from JWT (set by JWT middleware)
	userID := c.Get("user_id").(int64)

	// Fetch user details by ID
	var user User
	err := config.DB.Get(&user, "SELECT * FROM users WHERE id = ?", userID)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": err.Error()})
	}

	// Update last login
	err = updateLastLogin(user.ID)
	if err != nil {
		fmt.Println("error updateLastLogin", err)
	}

	// Build response
	response := map[string]interface{}{
		"id":            utils.EncodeID(int(user.ID)),
		"email":         user.Email,
		"role_id":       user.RoleID,
		"binding_email": user.BindingEmail,
		"created_at":    user.CreatedAt,
		"updated_at":    user.UpdatedAt,
	}

	// For admin users (role_id = 2), include permissions
	if user.RoleID == 2 {
		var permissions []string
		err := config.DB.Select(&permissions, `
			SELECT permission_key FROM admin_permissions
			WHERE user_id = ?
			ORDER BY permission_key
		`, userID)
		if err != nil {
			fmt.Println("Error fetching admin permissions:", err)
			permissions = []string{}
		}
		response["permissions"] = permissions
	}

	// For superadmin (role_id = 0), return all permissions
	if user.RoleID == 0 {
		response["permissions"] = []string{
			"overview", "user_list", "create_single", "create_bulk",
			"all_inbox", "all_sent", "terms_of_services", "privacy_policy",
			"roles_permissions",
		}
	}

	return c.JSON(http.StatusOK, response)
}

func ListAdminUsersHandler(c echo.Context) error {
	searchUsername := strings.TrimSpace(c.QueryParam("email"))

	// Validate sort fields to prevent SQL injection - use whitelist
	sortFields := c.QueryParam("sort_fields")
	allowedSorts := map[string]string{
		"last_login desc": "last_login DESC",
		"last_login asc":  "last_login ASC",
		"last_login_desc": "last_login DESC",
		"last_login_asc":  "last_login ASC",
		"email desc":      "email DESC",
		"email asc":       "email ASC",
		"email_desc":      "email DESC",
		"email_asc":       "email ASC",
		"created_at desc": "created_at DESC",
		"created_at asc":  "created_at ASC",
		"created_at_desc": "created_at DESC",
		"created_at_asc":  "created_at ASC",
	}

	orderBy, ok := allowedSorts[sortFields]
	if !ok {
		orderBy = "last_login DESC" // Default safe value
	}

	// Fetch paginated users with parameterized query
	var users []User
	var err error

	if searchUsername != "" {
		query := fmt.Sprintf("SELECT * FROM users WHERE role_id = 2 AND email LIKE ? ORDER BY %s", orderBy)
		err = config.DB.Select(&users, query, "%"+searchUsername+"%")
	} else {
		query := fmt.Sprintf("SELECT * FROM users WHERE role_id = 2 ORDER BY %s", orderBy)
		err = config.DB.Select(&users, query)
	}

	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Database error."})
	}

	var encodeUsers []User
	for _, user := range users {
		user.UserEncodeID = utils.EncodeID(int(user.ID))

		encodeUsers = append(encodeUsers, user)
	}

	response := PaginatedUsers{
		Users: encodeUsers,
	}

	return c.JSON(http.StatusOK, response)
}

// ListUsersHandler handles the request to list users with pagination and sorting
func ListUsersHandler(c echo.Context) error {
	// Get pagination parameters
	page, err := strconv.Atoi(c.QueryParam("page"))
	if err != nil || page < 1 {
		page = 1
	}
	pageSize, err := strconv.Atoi(c.QueryParam("page_size"))
	if err != nil || pageSize < 1 {
		pageSize = 10 // Default page size
	}

	// Sanitize and validate email search parameter
	searchEmail := strings.TrimSpace(c.QueryParam("email"))
	if len(searchEmail) > 255 { // Add length limit
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Email search parameter too long."})
	}

	// Validate sort fields to prevent SQL injection
	// Get sorting parameters
	sortFields := c.QueryParam("sort_fields")
	if sortFields == "" {
		sortFields = "last_login desc" // Default sort field
	}

	allowedSortFields := map[string]bool{
		"last_login desc": true,
		"last_login asc":  true,
		"email desc":      true,
		"email asc":       true,
		"created_at desc": true,
		"created_at asc":  true,
		// Add other allowed sort fields
	}
	if !allowedSortFields[sortFields] {
		sortFields = "last_login desc" // Default safe value
	}

	// Calculate offset
	offset := (page - 1) * pageSize

	// Get total count of users
	var totalCount int
	countQuery := "SELECT COUNT(*) FROM users WHERE role_id = 1"
	if searchEmail != "" {
		countQuery += " AND email LIKE ?"
		err = config.DB.Get(&totalCount, countQuery, "%"+searchEmail+"%")
	} else {
		err = config.DB.Get(&totalCount, countQuery)
	}
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	// Fetch paginated users
	var users []User
	query := "SELECT * FROM users WHERE role_id = 1"
	if searchEmail != "" {
		query += " AND email LIKE ?"
	}
	query += " ORDER BY " + sortFields + " LIMIT ? OFFSET ?"
	if searchEmail != "" {
		err = config.DB.Select(&users, query, "%"+searchEmail+"%", pageSize, offset)
	} else {
		err = config.DB.Select(&users, query, pageSize, offset)
	}
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	var encodeUsers []User
	for _, user := range users {
		user.UserEncodeID = utils.EncodeID(int(user.ID))
		encodeUsers = append(encodeUsers, user)
	}

	// Calculate total pages
	totalPages := (totalCount + pageSize - 1) / pageSize

	response := PaginatedUsers{
		Users:       encodeUsers,
		TotalCount:  totalCount,
		ActiveCount: totalCount, // Assuming activeCount is the same as totalCount for now
		Page:        page,
		PageSize:    pageSize,
		TotalPages:  totalPages,
	}

	return c.JSON(http.StatusOK, response)
}

func updateLastLogin(userID int64) error {
	// Update the user's last login time
	_, err := config.DB.Exec("UPDATE users SET last_login = ? WHERE id = ?", time.Now(), userID)
	if err != nil {
		return err
	}

	return nil
}

func getUserSuperAdminByID(userID int64) (string, error) {
	var user string
	query := `
        SELECT email
        FROM users
        WHERE id = ? AND role_id = 0
    `

	// Execute the query
	err := config.DB.Get(&user, query, userID)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", err
		}
		return "", err
	}

	return user, nil
}

func getUserAdminByID(userID int64) (string, error) {
	var user string
	query := `
        SELECT email
        FROM users
        WHERE id = ? AND (role_id = 2 OR role_id = 0) limit 1
    `

	// Execute the query
	err := config.DB.Get(&user, query, userID)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", err
		}
		return "", err
	}

	return user, nil
}

// SetBindingEmailRequest represents the request to set binding email
type SetBindingEmailRequest struct {
	BindingEmail string `json:"binding_email"`
}

// SetBindingEmailHandler allows users to set their binding email for password recovery
func SetBindingEmailHandler(c echo.Context) error {
	userID := c.Get("user_id").(int64)

	req := new(SetBindingEmailRequest)
	if err := c.Bind(req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	if req.BindingEmail == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error":   "invalid_email",
			"message": "Please provide a valid email address.",
		})
	}

	// Basic email validation
	if !strings.Contains(req.BindingEmail, "@") || !strings.Contains(req.BindingEmail, ".") {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error":   "invalid_email",
			"message": "Please provide a valid email address.",
		})
	}

	// Update the user's binding email
	_, err := config.DB.Exec(`
		UPDATE users
		SET binding_email = ?, updated_at = NOW()
		WHERE id = ?
	`, req.BindingEmail, userID)
	if err != nil {
		fmt.Println("Error updating binding email:", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error."})
	}

	return c.JSON(http.StatusOK, map[string]string{
		"message": "Binding email updated successfully.",
	})
}

// BulkCreateUserV2Request represents the v2 bulk create request
type BulkCreateUserV2Request struct {
	BaseName       string `json:"base_name"`
	Domain         string `json:"domain"`
	Quantity       int    `json:"quantity"`
	PasswordLength int    `json:"password_length"`
	SendTo         string `json:"send_to"`
}

// BulkCreateUserV2Handler creates users with auto-generated passwords
func BulkCreateUserV2Handler(c echo.Context) error {
	log := logger.Get().WithComponent("user_bulk_create_v2")
	userID := c.Get("user_id").(int64)
	log = log.WithUserID(userID)

	userName, err := getUserAdminByID(userID)
	if err != nil {
		log.Error("Failed to get admin user", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	req := new(BulkCreateUserV2Request)
	if err := c.Bind(req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	if req.BaseName == "" || req.Quantity == 0 {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "base_name and quantity are required."})
	}

	// Validate password length
	if req.PasswordLength < 8 || req.PasswordLength > 32 {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error":   "validation_error",
			"message": "password_length must be between 8 and 32.",
		})
	}

	log.Info("Starting bulk user creation v2",
		logger.Int("quantity", req.Quantity),
		logger.String("domain", req.Domain),
		logger.String("base_name", req.BaseName),
		logger.Int("password_length", req.PasswordLength),
	)

	// Load names if random mode
	var names [][]string
	if req.BaseName == "random" {
		file, err := os.Open("names.csv")
		if err != nil {
			log.Warn("Failed to open names.csv, using default list", logger.Err(err))
			names = ListOfNames
		} else {
			defer file.Close()
			reader := csv.NewReader(file)
			names, err = reader.ReadAll()
			if err != nil {
				log.Error("Failed to read names.csv", err)
				return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to read names.csv."})
			}
		}
		rand.Seed(uint64(time.Now().UnixNano()))
		rand.Shuffle(len(names), func(i, j int) { names[i], names[j] = names[j], names[i] })
	}

	// Step 1: Generate all base usernames
	baseUsernames, err := generateBaseUsernames(req.BaseName, req.Domain, req.Quantity, names)
	if err != nil {
		log.Error("Failed to generate usernames", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	// Step 2: Batch check existing emails (single query instead of N queries)
	existingMap, err := batchCheckExistingEmails(baseUsernames, req.Domain)
	if err != nil {
		log.Error("Failed to check existing emails", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	// Step 3: Resolve collisions and get final usernames
	finalUsernames := make([]string, 0, req.Quantity)
	for _, baseUsername := range baseUsernames {
		availableUsername := findAvailableUsername(baseUsername, req.Domain, existingMap)
		finalUsernames = append(finalUsernames, availableUsername)
	}

	// Step 4: Create users in a single transaction
	createdUsers := []map[string]string{}

	tx, err := config.DB.Begin()
	if err != nil {
		log.Error("Failed to start transaction", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	defer tx.Rollback()

	for _, username := range finalUsernames {
		// Generate secure password for each user
		password := generateSecurePassword(req.PasswordLength)
		hashedPassword, err := utils.HashPassword(password)
		if err != nil {
			log.Warn("Failed to hash password", logger.String("email", username), logger.Err(err))
			continue
		}

		_, err = tx.Exec(
			"INSERT INTO users (email, password, role_id, created_at, updated_at, last_login, created_by, updated_by, created_by_name, updated_by_name) VALUES (?, ?, 1, NOW(), NOW(), NOW(), ?, ?, ?, ?)",
			username, hashedPassword, userID, userID, userName, userName,
		)
		if err != nil {
			log.Warn("Failed to insert user", logger.String("email", username), logger.Err(err))
			continue
		}

		_, err = tx.Exec(
			"INSERT INTO generated_emails (username, created_at, updated_at, created_by, updated_by) VALUES (?, NOW(), NOW(), ?, ?)",
			username, userID, userID,
		)
		if err != nil {
			log.Warn("Failed to insert generated email", logger.String("email", username), logger.Err(err))
			continue
		}

		createdUsers = append(createdUsers, map[string]string{
			"email":    username,
			"password": password,
		})
	}

	if err := tx.Commit(); err != nil {
		log.Error("Failed to commit transaction", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	log.Info("Bulk user creation v2 completed",
		logger.Int("created", len(createdUsers)),
		logger.Int("requested", req.Quantity),
	)

	response := map[string]interface{}{
		"message":       fmt.Sprintf("Successfully created %d users", len(createdUsers)),
		"created_count": len(createdUsers),
	}

	// If send_to is provided, send email with credentials
	if req.SendTo != "" {
		var emailBody strings.Builder
		emailBody.WriteString(`
			<div style="font-family: Arial, sans-serif; padding: 20px;">
				<h2>Bulk User Creation Results</h2>
				<p>The following users have been created:</p>
				<table style="width: 100%; border-collapse: collapse; margin-top: 20px;">
					<tr style="background-color: #f2f2f2;">
						<th style="border: 1px solid #ddd; padding: 8px; width: 50px; text-align: center;">No</th>
						<th style="border: 1px solid #ddd; padding: 8px;">Email</th>
						<th style="border: 1px solid #ddd; padding: 8px;">Password</th>
					</tr>
		`)

		for i, user := range createdUsers {
			emailBody.WriteString(fmt.Sprintf(`
				<tr>
					<td style="border: 1px solid #ddd; padding: 8px; text-align: center;">%d</td>
					<td style="border: 1px solid #ddd; padding: 8px;">%s</td>
					<td style="border: 1px solid #ddd; padding: 8px; font-family: monospace;">%s</td>
				</tr>
			`, i+1, user["email"], user["password"]))
		}

		emailBody.WriteString(`
				</table>
			</div>
		`)

		emailFrom := viper.GetString("EMAIL_SUPPORT")
		err = pkg.SendEmailViaResend(emailFrom, req.SendTo, "Mailria Bulk User Creation", emailBody.String(), nil)
		if err != nil {
			log.Warn("Failed to send credentials email", logger.Err(err))
			response["email_error"] = "Failed to send credentials email"
		} else {
			response["credentials_sent_to"] = req.SendTo
		}

		// Don't include passwords in response if sent via email
		response["users"] = nil
	} else {
		// Include passwords in response if not sent via email
		response["users"] = createdUsers
	}

	return c.JSON(http.StatusCreated, response)
}

// generateSecurePassword generates a secure password with the specified length
func generateSecurePassword(length int) string {
	const (
		lowercase = "abcdefghijklmnopqrstuvwxyz"
		uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		digits    = "0123456789"
		special   = "!@#$%^&*"
	)

	password := make([]byte, length)

	// Ensure at least one of each required type
	password[0] = lowercase[rand.Intn(len(lowercase))]
	password[1] = uppercase[rand.Intn(len(uppercase))]
	password[2] = digits[rand.Intn(len(digits))]
	password[3] = special[rand.Intn(len(special))]

	// Fill rest with all characters
	all := lowercase + uppercase + digits + special
	for i := 4; i < length; i++ {
		password[i] = all[rand.Intn(len(all))]
	}

	// Shuffle
	rand.Shuffle(len(password), func(i, j int) {
		password[i], password[j] = password[j], password[i]
	})

	return string(password)
}
