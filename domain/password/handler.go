package password

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"math/big"
	"net/http"
	"time"

	"github.com/Triaksa-Space/be-mail-platform/config"
	"github.com/Triaksa-Space/be-mail-platform/pkg"
	"github.com/Triaksa-Space/be-mail-platform/utils"
	"github.com/labstack/echo/v4"
	"github.com/spf13/viper"
)

// User struct for database queries
type User struct {
	ID           int64          `db:"id"`
	Email        string         `db:"email"`
	BindingEmail sql.NullString `db:"binding_email"`
	RoleID       int            `db:"role_id"`
}

// ForgotPasswordHandler handles the forgot password request
func ForgotPasswordHandler(c echo.Context) error {
	req := new(ForgotPasswordRequest)
	if err := c.Bind(req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	// Always return the same response to prevent email enumeration
	genericResponse := map[string]string{
		"message": "If an account exists with this email, a verification code has been sent.",
	}

	// Find user by email
	var user User
	err := config.DB.Get(&user, "SELECT id, email, binding_email, role_id FROM users WHERE email = ?", req.Email)
	if err != nil {
		if err == sql.ErrNoRows {
			return c.JSON(http.StatusOK, genericResponse)
		}
		fmt.Println("Error fetching user:", err)
		return c.JSON(http.StatusOK, genericResponse)
	}

	// Only allow role_id = 1 (User) to use forgot password
	if user.RoleID != 1 {
		return c.JSON(http.StatusOK, genericResponse)
	}

	// Check if binding_email is set
	if !user.BindingEmail.Valid || user.BindingEmail.String == "" {
		return c.JSON(http.StatusOK, genericResponse)
	}

	// Invalidate any existing codes for this user
	_, err = config.DB.Exec(`
		UPDATE password_reset_codes
		SET used_at = NOW()
		WHERE user_id = ? AND used_at IS NULL
	`, user.ID)
	if err != nil {
		fmt.Println("Error invalidating existing codes:", err)
	}

	// Generate 4-digit code
	code, err := generateCode()
	if err != nil {
		fmt.Println("Error generating code:", err)
		return c.JSON(http.StatusOK, genericResponse)
	}

	// Hash the code
	codeHash := hashCode(code)
	expiresAt := time.Now().Add(CodeExpiry)

	// Store the code
	_, err = config.DB.Exec(`
		INSERT INTO password_reset_codes (user_id, code_hash, binding_email, expires_at, created_at)
		VALUES (?, ?, ?, ?, NOW())
	`, user.ID, codeHash, user.BindingEmail.String, expiresAt)
	if err != nil {
		fmt.Println("Error storing reset code:", err)
		return c.JSON(http.StatusOK, genericResponse)
	}

	// Send email with code
	emailBody := fmt.Sprintf(`
		<div style="font-family: Arial, sans-serif; padding: 20px;">
			<h2>Password Reset Code</h2>
			<p>You have requested to reset your password for your Mailria account.</p>
			<p>Your verification code is:</p>
			<div style="background-color: #f4f4f4; padding: 20px; text-align: center; font-size: 32px; font-weight: bold; letter-spacing: 8px; margin: 20px 0;">
				%s
			</div>
			<p>This code will expire in 30 minutes.</p>
			<p>If you did not request this password reset, please ignore this email.</p>
			<p>Best regards,<br>Mailria Team</p>
		</div>
	`, code)

	emailFrom := viper.GetString("EMAIL_SUPPORT")
	err = pkg.SendEmailViaResend(emailFrom, user.BindingEmail.String, "Mailria Password Reset Code", emailBody, nil)
	if err != nil {
		fmt.Println("Error sending email:", err)
		// Still return success to prevent enumeration
	}

	return c.JSON(http.StatusOK, genericResponse)
}

// VerifyCodeHandler handles the code verification request
func VerifyCodeHandler(c echo.Context) error {
	req := new(VerifyCodeRequest)
	if err := c.Bind(req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	if req.Email == "" || req.Code == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error":   "invalid_request",
			"message": "Email and code are required",
		})
	}

	// Find user by email
	var user User
	err := config.DB.Get(&user, "SELECT id, email, binding_email, role_id FROM users WHERE email = ?", req.Email)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]interface{}{
			"error":   "invalid_code",
			"message": "Invalid or expired verification code",
		})
	}

	// Only allow role_id = 1 (User)
	if user.RoleID != 1 {
		return c.JSON(http.StatusBadRequest, map[string]interface{}{
			"error":   "invalid_code",
			"message": "Invalid or expired verification code",
		})
	}

	now := time.Now()

	// Find the latest valid code for this user
	var resetCode PasswordResetCode
	err = config.DB.Get(&resetCode, `
		SELECT id, user_id, code_hash, binding_email, expires_at, failed_attempts, blocked_until, verified_at, used_at, reset_token, created_at
		FROM password_reset_codes
		WHERE user_id = ? AND used_at IS NULL AND verified_at IS NULL
		ORDER BY created_at DESC
		LIMIT 1
	`, user.ID)
	if err != nil {
		if err == sql.ErrNoRows {
			return c.JSON(http.StatusBadRequest, map[string]interface{}{
				"error":   "invalid_code",
				"message": "Invalid or expired verification code",
			})
		}
		fmt.Println("Error fetching reset code:", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
	}

	// Check if blocked
	if resetCode.BlockedUntil.Valid && resetCode.BlockedUntil.Time.After(now) {
		return c.JSON(http.StatusTooManyRequests, map[string]interface{}{
			"error":        "too_many_attempts",
			"message":      "Too many failed attempts. Try again in 5 minutes.",
			"blocked_until": resetCode.BlockedUntil.Time.Format(time.RFC3339),
		})
	}

	// Check if expired
	if resetCode.ExpiresAt.Before(now) {
		return c.JSON(http.StatusBadRequest, map[string]interface{}{
			"error":   "invalid_code",
			"message": "Invalid or expired verification code",
		})
	}

	// Verify the code
	codeHash := hashCode(req.Code)
	if codeHash != resetCode.CodeHash {
		// Increment failed attempts
		newAttempts := resetCode.FailedAttempts + 1

		if newAttempts >= MaxFailedAttempts {
			// Block for 5 minutes
			blockedUntil := now.Add(BlockDuration)
			_, err = config.DB.Exec(`
				UPDATE password_reset_codes
				SET failed_attempts = ?, blocked_until = ?
				WHERE id = ?
			`, newAttempts, blockedUntil, resetCode.ID)
			if err != nil {
				fmt.Println("Error updating failed attempts:", err)
			}
			return c.JSON(http.StatusTooManyRequests, map[string]interface{}{
				"error":        "too_many_attempts",
				"message":      "Too many failed attempts. Try again in 5 minutes.",
				"blocked_until": blockedUntil.Format(time.RFC3339),
			})
		}

		// Warning at 4th attempt
		if newAttempts == MaxFailedAttempts-1 {
			_, err = config.DB.Exec(`
				UPDATE password_reset_codes
				SET failed_attempts = ?
				WHERE id = ?
			`, newAttempts, resetCode.ID)
			if err != nil {
				fmt.Println("Error updating failed attempts:", err)
			}
			return c.JSON(http.StatusBadRequest, map[string]interface{}{
				"error":              "attempt_warning",
				"message":            "One more failed attempt will temporarily block access",
				"remaining_attempts": 1,
			})
		}

		// Update failed attempts
		_, err = config.DB.Exec(`
			UPDATE password_reset_codes
			SET failed_attempts = ?
			WHERE id = ?
		`, newAttempts, resetCode.ID)
		if err != nil {
			fmt.Println("Error updating failed attempts:", err)
		}

		return c.JSON(http.StatusBadRequest, map[string]interface{}{
			"error":   "invalid_code",
			"message": "Invalid or expired verification code",
		})
	}

	// Code is valid - generate reset token
	resetToken, err := generateResetToken()
	if err != nil {
		fmt.Println("Error generating reset token:", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
	}

	// Mark code as verified and store reset token
	_, err = config.DB.Exec(`
		UPDATE password_reset_codes
		SET verified_at = NOW(), reset_token = ?
		WHERE id = ?
	`, resetToken, resetCode.ID)
	if err != nil {
		fmt.Println("Error updating verified status:", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
	}

	return c.JSON(http.StatusOK, VerifyCodeResponse{
		Message:    "Code verified successfully",
		ResetToken: resetToken,
	})
}

// ResetPasswordHandler handles the password reset request
func ResetPasswordHandler(c echo.Context) error {
	req := new(ResetPasswordRequest)
	if err := c.Bind(req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	if req.Email == "" || req.ResetToken == "" || req.NewPassword == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error":   "invalid_request",
			"message": "Email, reset_token, and new_password are required",
		})
	}

	// Password validation
	if len(req.NewPassword) < 6 {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error":   "validation_error",
			"message": "Password must be at least 6 characters",
		})
	}

	// Find user by email
	var user User
	err := config.DB.Get(&user, "SELECT id, email, role_id FROM users WHERE email = ?", req.Email)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]interface{}{
			"error":   "invalid_token",
			"message": "Invalid or expired reset token",
		})
	}

	// Only allow role_id = 1 (User)
	if user.RoleID != 1 {
		return c.JSON(http.StatusBadRequest, map[string]interface{}{
			"error":   "invalid_token",
			"message": "Invalid or expired reset token",
		})
	}

	now := time.Now()

	// Find the verified code with this reset token
	var resetCode PasswordResetCode
	err = config.DB.Get(&resetCode, `
		SELECT id, user_id, verified_at, used_at, reset_token, created_at
		FROM password_reset_codes
		WHERE user_id = ? AND reset_token = ? AND verified_at IS NOT NULL AND used_at IS NULL
		ORDER BY created_at DESC
		LIMIT 1
	`, user.ID, req.ResetToken)
	if err != nil {
		if err == sql.ErrNoRows {
			return c.JSON(http.StatusBadRequest, map[string]interface{}{
				"error":   "invalid_token",
				"message": "Invalid or expired reset token",
			})
		}
		fmt.Println("Error fetching reset code:", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
	}

	// Check if reset token is expired (10 minutes after verification)
	if resetCode.VerifiedAt.Valid && now.Sub(resetCode.VerifiedAt.Time) > ResetTokenExpiry {
		return c.JSON(http.StatusBadRequest, map[string]interface{}{
			"error":   "invalid_token",
			"message": "Invalid or expired reset token",
		})
	}

	// Hash the new password
	hashedPassword, err := utils.HashPassword(req.NewPassword)
	if err != nil {
		fmt.Println("Error hashing password:", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
	}

	// Start transaction
	tx, err := config.DB.Begin()
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
	}
	defer tx.Rollback()

	// Update password
	_, err = tx.Exec(`
		UPDATE users
		SET password = ?, updated_at = NOW()
		WHERE id = ?
	`, hashedPassword, user.ID)
	if err != nil {
		fmt.Println("Error updating password:", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
	}

	// Mark reset code as used
	_, err = tx.Exec(`
		UPDATE password_reset_codes
		SET used_at = NOW()
		WHERE id = ?
	`, resetCode.ID)
	if err != nil {
		fmt.Println("Error marking code as used:", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
	}

	// Revoke all refresh tokens for security
	_, err = tx.Exec(`
		UPDATE refresh_tokens
		SET revoked_at = NOW()
		WHERE user_id = ? AND revoked_at IS NULL
	`, user.ID)
	if err != nil {
		fmt.Println("Error revoking refresh tokens:", err)
		// Don't fail the request, just log
	}

	if err := tx.Commit(); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
	}

	return c.JSON(http.StatusOK, map[string]string{
		"message": "Password reset successfully",
	})
}

// generateCode generates a 4-digit code
func generateCode() (string, error) {
	code := ""
	for i := 0; i < 4; i++ {
		n, err := rand.Int(rand.Reader, big.NewInt(10))
		if err != nil {
			return "", err
		}
		code += fmt.Sprintf("%d", n.Int64())
	}
	return code, nil
}

// hashCode creates a SHA256 hash of the code
func hashCode(code string) string {
	hash := sha256.Sum256([]byte(code))
	return hex.EncodeToString(hash[:])
}

// generateResetToken generates a secure reset token
func generateResetToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
