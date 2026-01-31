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
	"github.com/Triaksa-Space/be-mail-platform/utils"
	"github.com/spf13/viper"

	"github.com/labstack/echo/v4"
	"golang.org/x/exp/rand"
)

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func LoginHandler(c echo.Context) error {
	req := new(LoginRequest)
	if err := c.Bind(req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	now := time.Now()

	// Get user attempts info
	type AttemptsInfo struct {
		FailedAttempts int          `db:"failed_attempts"`
		BlockedUntil   sql.NullTime `db:"blocked_until"`
	}
	var attempts AttemptsInfo

	err := config.DB.Get(&attempts, `
		SELECT failed_attempts, blocked_until 
		FROM user_login_attempts
		WHERE username = ?
	`, req.Email)

	if err != nil {
		if err == sql.ErrNoRows {
			// If no record found, create a default entry with zero attempts
			_, err = config.DB.Exec(`
				INSERT INTO user_login_attempts (username, failed_attempts, last_attempt_time)
				VALUES (?, 0, ?)
			`, req.Email, now)
			if err != nil {
				fmt.Println("Error inserting initial attempts record:", err)
				return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
			}

			// Refresh attempts info after insert
			err = config.DB.Get(&attempts, `
				SELECT failed_attempts, blocked_until 
				FROM user_login_attempts
				WHERE username = ?
			`, req.Email)
			if err != nil {
				fmt.Println("Error fetching attempts after insert:", err)
				return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
			}
		} else {
			fmt.Println("Error fetching attempts:", err)
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
		}
	}

	// Check if user is currently blocked
	if attempts.BlockedUntil.Valid && attempts.BlockedUntil.Time.After(now) {
		remaining := attempts.BlockedUntil.Time.Sub(now)
		return c.JSON(http.StatusTooManyRequests, map[string]string{
			"error": fmt.Sprintf("Account temporarily locked. Please try again in %d minutes and %d seconds.",
				int(remaining.Minutes()), int(remaining.Seconds())%60),
		})
	}

	// If block period has passed, reset attempts
	if attempts.BlockedUntil.Valid && attempts.BlockedUntil.Time.Before(now) {
		_, err = config.DB.Exec(`
			UPDATE user_login_attempts
			SET failed_attempts = 0, blocked_until = NULL
			WHERE username = ?
		`, req.Email)
		if err != nil {
			fmt.Println("Error resetting attempts after block:", err)
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
		}
		attempts.FailedAttempts = 0
		attempts.BlockedUntil.Valid = false
	}

	// Fetch user from the database
	var user User
	err = config.DB.Get(&user, "SELECT * FROM users WHERE email = ?", req.Email)
	if err != nil {
		fmt.Println("Error fetching user:", err)
		if err == sql.ErrNoRows {
			// User not found or password mismatch: increment failed attempts
			attempts.FailedAttempts++
			if attempts.FailedAttempts >= 4 {
				// Block user for 5 minutes
				blockedUntil := now.Add(5 * time.Minute)
				_, updateErr := config.DB.Exec(`
					UPDATE user_login_attempts
					SET failed_attempts = ?, last_attempt_time = ?, blocked_until = ?
					WHERE username = ?
				`, attempts.FailedAttempts, now, blockedUntil, req.Email)
				if updateErr != nil {
					fmt.Println("Error updating attempts on block:", updateErr)
				}
				return c.JSON(http.StatusTooManyRequests, map[string]string{
					"error": "Too many failed login attempts. Account locked for 5 minutes.",
				})
			} else {
				// Just update the count
				_, updateErr := config.DB.Exec(`
					UPDATE user_login_attempts
					SET failed_attempts = ?, last_attempt_time = ?
					WHERE username = ?
				`, attempts.FailedAttempts, now, req.Email)
				if updateErr != nil {
					fmt.Println("Error updating attempts on failure:", updateErr)
				}
			}
			return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Invalid email or password"})
		}
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
	}

	// Check password
	if !utils.CheckPasswordHash(req.Password, user.Password) {
		// Password mismatch: increment failed attempts
		attempts.FailedAttempts++
		if attempts.FailedAttempts >= 4 {
			// Block user for 5 minutes
			blockedUntil := now.Add(5 * time.Minute)
			_, updateErr := config.DB.Exec(`
				UPDATE user_login_attempts
				SET failed_attempts = ?, last_attempt_time = ?, blocked_until = ?
				WHERE username = ?
			`, attempts.FailedAttempts, now, blockedUntil, req.Email)
			if updateErr != nil {
				fmt.Println("Error updating attempts on block:", updateErr)
			}
			return c.JSON(http.StatusTooManyRequests, map[string]string{
				"error": "Too many failed login attempts. Account locked for 5 minutes.",
			})
		} else if attempts.FailedAttempts == 3 {
			// Just update the attempts count
			_, updateErr := config.DB.Exec(`
				UPDATE user_login_attempts
				SET failed_attempts = ?, last_attempt_time = ?
				WHERE username = ?
			`, attempts.FailedAttempts, now, req.Email)
			if updateErr != nil {
				fmt.Println("Error updating attempts on password mismatch:", updateErr)
			}
			return c.JSON(http.StatusTooManyRequests, map[string]string{
				"error": "Careful! One more failed attempt will disable login for 5 minutes.",
			})
		} else {
			// Just update the attempts count
			_, updateErr := config.DB.Exec(`
				UPDATE user_login_attempts
				SET failed_attempts = ?, last_attempt_time = ?
				WHERE username = ?
			`, attempts.FailedAttempts, now, req.Email)
			if updateErr != nil {
				fmt.Println("Error updating attempts on password mismatch:", updateErr)
			}
		}
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Invalid email or password"})
	}

	// Successful login - reset attempts
	_, err = config.DB.Exec(`
		UPDATE user_login_attempts
		SET failed_attempts = 0, blocked_until = NULL
		WHERE username = ?
	`, req.Email)
	if err != nil {
		fmt.Println("Error resetting attempts on success:", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
	}

	token, err := utils.GenerateJWT(user.ID, user.Email, user.RoleID)
	if err != nil {
		fmt.Println("GenerateJWT error:", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
	}

	// Update last login time
	err = updateLastLogin(user.ID)
	if err != nil {
		fmt.Println("error updateLastLogin:", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
	}

	return c.JSON(http.StatusOK, map[string]string{"token": token})
}

func LogoutHandler(c echo.Context) error {
	// Assuming JWT middleware has already validated the token
	return c.JSON(http.StatusOK, map[string]string{"message": "Logout successful"})
}

func ChangePasswordAdminHandler(c echo.Context) error {
	// Extract user ID from JWT (set by JWT middleware)
	superAdminID := c.Get("user_id").(int64)

	_, err := getUserAdminByID(superAdminID)
	if err != nil {
		fmt.Println("Access Denied")
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Access Denied."})
	}

	// Bind request body
	req := new(AdminChangePasswordRequest)
	if err := c.Bind(req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	if req.UserID == 0 {
		req.UserID = int(superAdminID)
	}

	// Fetch user data from the database
	var hashedPassword string
	err = config.DB.Get(&hashedPassword, "SELECT password FROM users WHERE id = ?", req.UserID)
	if err != nil {
		fmt.Println("error fetch user data", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	if req.UserID != 0 && req.OldPassword != "" {
		// Check if the old password is correct
		if !utils.CheckPasswordHash(req.OldPassword, hashedPassword) {
			return c.JSON(http.StatusUnauthorized, map[string]string{"error": "The password you entered is incorrect."})
		}

		// Check if the new password is the same as the old password
		if utils.CheckPasswordHash(req.NewPassword, hashedPassword) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "The new password cannot be the same as the old password."})
		}
	}

	// Hash the new password
	newHashedPassword, err := utils.HashPassword(req.NewPassword)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	// Update the user's password in the database
	_, err = config.DB.Exec("UPDATE users SET password = ?, updated_at = NOW() WHERE id = ?", newHashedPassword, req.UserID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	// Update last login
	err = updateLastLogin(superAdminID)
	if err != nil {
		fmt.Println("error updateLastLogin", err)
	}

	return c.JSON(http.StatusOK, map[string]string{"message": "Password updated successfully"})
}

func ChangePasswordHandler(c echo.Context) error {
	// Extract user ID from JWT (set by JWT middleware)
	userID := c.Get("user_id").(int64)

	// Bind request body
	req := new(ChangePasswordRequest)
	if err := c.Bind(req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	if req.UserID == 0 {
		req.UserID = int(userID)
	}

	// Fetch user data from the database
	var user struct {
		HashedPassword string     `db:"password"`
		FailedAttempts int        `db:"failed_attempts"`
		LastFailedAt   *time.Time `db:"last_failed_at"`
	}

	err := config.DB.Get(&user, `
        SELECT password, failed_attempts, last_failed_at 
        FROM users WHERE id = ?`, req.UserID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
	}

	maxAttempts := 5
	blockDuration := time.Hour
	// Check if account is temporarily blocked
	if user.FailedAttempts >= maxAttempts && user.LastFailedAt != nil {
		if time.Since(*user.LastFailedAt) < blockDuration {
			return c.JSON(http.StatusTooManyRequests, map[string]string{
				"error": "Account is temporarily locked. Please try again later.",
			})
		} else {
			// Reset failed attempts if blocking period has passed
			_, err = config.DB.Exec(`
                UPDATE users 
                SET failed_attempts = 0, 
                    last_failed_at = NULL 
                WHERE id = ?`, req.UserID)
			if err != nil {
				return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
			}
			user.FailedAttempts = 0
			user.LastFailedAt = nil
		}
	}

	if req.OldPassword != "" {
		// Check if the old password is correct
		if !utils.CheckPasswordHash(req.OldPassword, user.HashedPassword) {
			fmt.Println("error CheckPasswordHash", err)

			// Increment failed attempts
			_, err = config.DB.Exec(`
                UPDATE users 
                SET failed_attempts = failed_attempts + 1, 
                    last_failed_at = NOW() 
                WHERE id = ?`, req.UserID)
			if err != nil {
				return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
			}

			return c.JSON(http.StatusUnauthorized, map[string]string{"error": "The password you entered is incorrect."})
		}

		// Check if the new password is the same as the old password
		if utils.CheckPasswordHash(req.NewPassword, user.HashedPassword) {
			fmt.Println("error CheckPasswordHash", err)
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "The new password cannot be the same as the old password."})
		}
	}

	// Hash the new password
	newHashedPassword, err := utils.HashPassword(req.NewPassword)
	if err != nil {
		fmt.Println("error HashPassword", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
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
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
	}

	// Update last login
	err = updateLastLogin(userID)
	if err != nil {
		fmt.Println("error updateLastLogin", err)
	}

	return c.JSON(http.StatusOK, map[string]string{"message": "Password updated successfully"})
}

func CreateUserAdminHandler(c echo.Context) error {
	userID := c.Get("user_id").(int64)
	req := new(CreateAdminRequest)
	if err := c.Bind(req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	userName, err := getUserSuperAdminByID(userID)
	if err != nil {
		fmt.Println("error getUserSuperAdminByID", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	// if err := c.Validate(req); err != nil {
	// 	return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	// }

	// Hash the password
	hashedPassword, err := utils.HashPassword(req.Password)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	// Insert the user into the database
	_, err = config.DB.Exec(
		"INSERT INTO users (email, password, role_id, created_at, updated_at, last_login, created_by, updated_by, created_by_name, updated_by_name) VALUES (?, ?, ?, NOW(), NOW(), NOW(), ?, ?, ?, ?)",
		req.Username, hashedPassword, 2, userID, userID, userName, userName, // Hardcoded role ID for no, userName, userNamew
	)
	if err != nil {
		fmt.Println("ERROR", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	// // Initialize AWS session
	// sess, _ := pkg.InitAWS()

	// // Create S3 client
	// s3Client, _ := pkg.InitS3(sess)

	// err = pkg.CreateBucketFolderEmailUser(s3Client, req.Email)
	// if err != nil {
	// 	return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	// }

	return c.JSON(http.StatusCreated, map[string]string{"message": "User created successfully"})
}

func CreateUserHandler(c echo.Context) error {
	userID := c.Get("user_id").(int64)
	req := new(CreateUserRequest)
	if err := c.Bind(req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	userName, err := getUserAdminByID(userID)
	if err != nil {
		fmt.Println("error getUserAdminByID", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	// if err := c.Validate(req); err != nil {
	// 	return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	// }

	// Hash the password
	hashedPassword, err := utils.HashPassword(req.Password)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	// Insert the user into the database
	_, err = config.DB.Exec(
		"INSERT INTO users (email, password, role_id, created_at, updated_at, last_login, created_by, updated_by, created_by_name, updated_by_name) VALUES (?, ?, ?, NOW(), NOW(), NOW(), ?, ?, ?, ?)",
		req.Email, hashedPassword, 1, userID, userID, userName, userName, // Hardcoded role ID for no, userName, userNamew
	)
	if err != nil {
		fmt.Println("ERROR", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	// Insert into table generated_email
	_, err = config.DB.Exec(
		"INSERT INTO generated_emails (username, created_at, updated_at, created_by, updated_by) VALUES (?, NOW(), NOW(), ?, ?)",
		req.Email, userID, userID, // Hardcoded role ID for no, userName, userNamew
	)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	return c.JSON(http.StatusCreated, map[string]string{"message": "User created successfully"})
}

func BulkCreateUserHandler(c echo.Context) error {
	// Get user ID and email from context
	userID := c.Get("user_id").(int64)

	userName, err := getUserAdminByID(userID)
	if err != nil {
		fmt.Println("error getUserAdminByID", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	req := new(BulkCreateUserRequest)
	if err := c.Bind(req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	if req.BaseName == "" || req.Quantity == 0 {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "BaseName and Quantity are required"})
	}

	createdUsers := []map[string]string{}
	skippedUsers := []map[string]string{}

	var names [][]string
	if req.BaseName == "random" {
		// Load names from CSV file
		file, err := os.Open("names.csv")
		if err != nil {
			fmt.Println("Failed to open names.csv, using default list", err)
			names = ListOfNames
		} else {
			defer file.Close()

			reader := csv.NewReader(file)
			names, err = reader.ReadAll()
			if err != nil {
				fmt.Println("Failed to readAll names.csv", err)
				return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to read names.csv"})
			}
		}

		// Shuffle the names to ensure randomness
		rand.Seed(uint64(time.Now().UnixNano()))
		rand.Shuffle(len(names), func(i, j int) { names[i], names[j] = names[j], names[i] })
	}

	for i := 0; i < req.Quantity; i++ {
		var username string
		if req.BaseName == "random" {
			if len(names) == 0 {
				return c.JSON(http.StatusInternalServerError, map[string]string{"error": "No names available in names.csv"})
			}
			name := names[i%len(names)]
			username = fmt.Sprintf("%s%s@%s", name[0], name[1], req.Domain)
		} else {
			username = fmt.Sprintf("%s@%s", req.BaseName, req.Domain)
			if i > 0 {
				username = fmt.Sprintf("%s%d@%s", req.BaseName, i, req.Domain)
			}
		}
		username = strings.ToLower(username)

		// Check if the base username exists
		var exists bool
		err := config.DB.Get(&exists, "SELECT EXISTS(SELECT 1 FROM users WHERE email = ?)", username)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}

		// If the base username exists, find an available username with a number
		if exists {
			// Initialize counter
			counter := 1
			originalUsername := strings.Split(username, "@")[0]

			// Extract trailing digits from the original username
			re := regexp.MustCompile(`^(.*?)(\d+)$`)
			matches := re.FindStringSubmatch(originalUsername)
			if len(matches) == 3 {
				namePart := matches[1]
				numberPart := matches[2]
				counter, _ = strconv.Atoi(numberPart)
				counter++ // Start from the next number
				originalUsername = namePart
			}

			// Loop to find an available username
			exists = true
			for exists {
				username = fmt.Sprintf("%s%d@%s", originalUsername, counter, req.Domain)
				err := config.DB.Get(&exists, "SELECT EXISTS(SELECT 1 FROM users WHERE email = ?)", username)
				if err != nil {
					return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
				}
				counter++
			}
		}

		// Start transaction for this user
		tx, err := config.DB.Begin()
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}
		defer tx.Rollback()

		hashedPassword, err := utils.HashPassword(req.Password) // Use a default password or generate one
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}

		// Insert user
		_, err = tx.Exec(
			"INSERT INTO users (email, password, role_id, created_at, updated_at, last_login, created_by, updated_by, created_by_name, updated_by_name) VALUES (?, ?, 1, NOW(), NOW(), NOW(), ?, ?, ?, ?)",
			username, hashedPassword, userID, userID, userName, userName,
		)
		if err != nil {
			fmt.Println("Failed to insert user", err)
			continue
		}

		// Insert generated email
		_, err = tx.Exec(
			"INSERT INTO generated_emails (username, created_at, updated_at, created_by, updated_by) VALUES (?, NOW(), NOW(), ?, ?)",
			username, userID, userID,
		)
		if err != nil {
			fmt.Println("Failed to insert generated email", err)
			continue
		}

		createdUsers = append(createdUsers, map[string]string{
			"No":       fmt.Sprintf("%d", i+1),
			"Email":    username,
			"Password": req.Password, // Use the actual password if generated
		})

		tx.Commit()
	}

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
	// Send email via pkg/aws
	err = pkg.SendEmailViaResend(emailUser, req.SendTo, "Mailria Create Bulk User", emailBody.String(), nil)
	if err != nil {
		fmt.Println("Failed to send email", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": err.Error(),
		})
	}

	// Return the response
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
		return c.JSON(http.StatusNotFound, map[string]string{"error": "User not found"})
	}

	// Start transaction
	tx, err := config.DB.Begin()
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to start transaction"})
	}
	defer tx.Rollback()

	// Delete emails
	_, err = tx.Exec("DELETE FROM emails WHERE user_id = ?", userID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to delete emails"})
	}

	// Delete user
	result, err := tx.Exec("DELETE FROM users WHERE id = ?", userID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to delete user"})
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "User not found"})
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to commit transaction"})
	}

	return c.JSON(http.StatusOK, map[string]string{"message": "User and associated data deleted successfully"})
}

// ONLY ADMIN CAN DELETE USER EMAIL
func DeleteUserHandler(c echo.Context) error {
	userID := c.Param("id")

	// Get user email before deletion for S3
	var userEmail string
	err := config.DB.Get(&userEmail, "SELECT email FROM users WHERE id = ? and role_id=1", userID)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "User not found"})
	}

	// Start transaction
	tx, err := config.DB.Begin()
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to start transaction"})
	}
	defer tx.Rollback()

	// Delete emails
	_, err = tx.Exec("DELETE FROM emails WHERE user_id = ?", userID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to delete emails"})
	}

	// Delete user
	result, err := tx.Exec("DELETE FROM users WHERE id = ?", userID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to delete user"})
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "User not found"})
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to commit transaction"})
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
	// 	return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to delete user files"})
	// }

	return c.JSON(http.StatusOK, map[string]string{"message": "User and associated data deleted successfully"})
}

func GetUserHandler(c echo.Context) error {
	userID := c.Param("id")

	userIDDecode, err := utils.DecodeID(userID)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid user ID"})
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

	return c.JSON(http.StatusOK, user)
}

func ListAdminUsersHandler(c echo.Context) error {
	searchUsername := c.QueryParam("email")

	// Get sorting parameters
	sortFields := c.QueryParam("sort_fields")
	if sortFields == "" {
		sortFields = "last_login desc" // Default sort field
	}

	// Fetch paginated users
	var users []User
	query := "SELECT * FROM users WHERE role_id = 2 "
	if searchUsername != "" {
		query = query + " AND email LIKE '%" + searchUsername + "%' "
	}
	query = query + " ORDER BY " + sortFields
	err := config.DB.Select(&users,
		query)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
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
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Email search parameter too long"})
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
			"message": "Please provide a valid email address",
		})
	}

	// Basic email validation
	if !strings.Contains(req.BindingEmail, "@") || !strings.Contains(req.BindingEmail, ".") {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error":   "invalid_email",
			"message": "Please provide a valid email address",
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
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
	}

	return c.JSON(http.StatusOK, map[string]string{
		"message": "Binding email updated successfully",
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
	userID := c.Get("user_id").(int64)

	userName, err := getUserAdminByID(userID)
	if err != nil {
		fmt.Println("error getUserAdminByID", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	req := new(BulkCreateUserV2Request)
	if err := c.Bind(req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	if req.BaseName == "" || req.Quantity == 0 {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "base_name and quantity are required"})
	}

	// Validate password length
	if req.PasswordLength < 8 || req.PasswordLength > 32 {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error":   "validation_error",
			"message": "password_length must be between 8 and 32",
		})
	}

	createdUsers := []map[string]string{}

	var names [][]string
	if req.BaseName == "random" {
		file, err := os.Open("names.csv")
		if err != nil {
			fmt.Println("Failed to open names.csv, using default list", err)
			names = ListOfNames
		} else {
			defer file.Close()

			reader := csv.NewReader(file)
			names, err = reader.ReadAll()
			if err != nil {
				fmt.Println("Failed to readAll names.csv", err)
				return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to read names.csv"})
			}
		}

		rand.Seed(uint64(time.Now().UnixNano()))
		rand.Shuffle(len(names), func(i, j int) { names[i], names[j] = names[j], names[i] })
	}

	for i := 0; i < req.Quantity; i++ {
		var username string
		if req.BaseName == "random" {
			if len(names) == 0 {
				return c.JSON(http.StatusInternalServerError, map[string]string{"error": "No names available in names.csv"})
			}
			name := names[i%len(names)]
			username = fmt.Sprintf("%s%s@%s", name[0], name[1], req.Domain)
		} else {
			username = fmt.Sprintf("%s@%s", req.BaseName, req.Domain)
			if i > 0 {
				username = fmt.Sprintf("%s%d@%s", req.BaseName, i, req.Domain)
			}
		}
		username = strings.ToLower(username)

		// Check if username exists and find available one
		var exists bool
		err := config.DB.Get(&exists, "SELECT EXISTS(SELECT 1 FROM users WHERE email = ?)", username)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}

		if exists {
			counter := 1
			originalUsername := strings.Split(username, "@")[0]

			re := regexp.MustCompile(`^(.*?)(\d+)$`)
			matches := re.FindStringSubmatch(originalUsername)
			if len(matches) == 3 {
				namePart := matches[1]
				numberPart := matches[2]
				counter, _ = strconv.Atoi(numberPart)
				counter++
				originalUsername = namePart
			}

			exists = true
			for exists {
				username = fmt.Sprintf("%s%d@%s", originalUsername, counter, req.Domain)
				err := config.DB.Get(&exists, "SELECT EXISTS(SELECT 1 FROM users WHERE email = ?)", username)
				if err != nil {
					return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
				}
				counter++
			}
		}

		// Generate secure password
		password := generateSecurePassword(req.PasswordLength)

		tx, err := config.DB.Begin()
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}
		defer tx.Rollback()

		hashedPassword, err := utils.HashPassword(password)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}

		_, err = tx.Exec(
			"INSERT INTO users (email, password, role_id, created_at, updated_at, last_login, created_by, updated_by, created_by_name, updated_by_name) VALUES (?, ?, 1, NOW(), NOW(), NOW(), ?, ?, ?, ?)",
			username, hashedPassword, userID, userID, userName, userName,
		)
		if err != nil {
			fmt.Println("Failed to insert user", err)
			continue
		}

		_, err = tx.Exec(
			"INSERT INTO generated_emails (username, created_at, updated_at, created_by, updated_by) VALUES (?, NOW(), NOW(), ?, ?)",
			username, userID, userID,
		)
		if err != nil {
			fmt.Println("Failed to insert generated email", err)
			continue
		}

		createdUsers = append(createdUsers, map[string]string{
			"email":    username,
			"password": password,
		})

		tx.Commit()
	}

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
			fmt.Println("Failed to send email", err)
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
