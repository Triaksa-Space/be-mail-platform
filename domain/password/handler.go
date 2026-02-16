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
	"github.com/Triaksa-Space/be-mail-platform/pkg/logger"
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
	log := logger.Get().WithComponent("password_reset")

	req := new(ForgotPasswordRequest)
	if err := c.Bind(req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	// Validate required fields
	if req.Email == "" || req.BindingEmail == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error":   "validation_error",
			"message": "Email and binding_email are required.",
		})
	}

	now := time.Now()

	// Check if this email is currently blocked due to too many attempts
	var attempt ForgotPasswordAttempt
	err := config.DB.Get(&attempt, `
		SELECT id, email, failed_attempts, blocked_until, last_attempt_at, created_at
		FROM forgot_password_attempts
		WHERE email = ?
	`, req.Email)

	if err == nil {
		// Check if currently blocked
		if attempt.BlockedUntil.Valid && attempt.BlockedUntil.Time.After(now) {
			log.Debug("Forgot password blocked due to too many attempts", logger.Email(req.Email))
			return c.JSON(http.StatusTooManyRequests, map[string]interface{}{
				"error":         "too_many_attempts",
				"message":       "Too many failed attempts. Try again in 5 minutes.",
				"blocked_until": attempt.BlockedUntil.Time.Format(time.RFC3339),
			})
		}

		// Reset attempts if block period has passed
		if attempt.BlockedUntil.Valid && attempt.BlockedUntil.Time.Before(now) {
			_, err = config.DB.Exec(`
				UPDATE forgot_password_attempts
				SET failed_attempts = 0, blocked_until = NULL
				WHERE email = ?
			`, req.Email)
			if err != nil {
				log.Warn("Error resetting forgot password attempts", logger.Err(err))
			}
			attempt.FailedAttempts = 0
		}
	}

	// Find user by email
	var user User
	err = config.DB.Get(&user, "SELECT id, email, binding_email, role_id FROM users WHERE email = ?", req.Email)
	if err != nil {
		if err == sql.ErrNoRows {
			log.Debug("Password reset requested for non-existent email", logger.Email(req.Email))
			// Return generic error to prevent email enumeration but still track attempts
			return handleFailedForgotPasswordAttempt(c, req.Email, log)
		}
		log.Error("Error fetching user for password reset", err, logger.Email(req.Email))
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
	}

	log = log.WithUserID(user.ID)

	// Only allow role_id = 1 (User) to use forgot password
	if user.RoleID != 1 {
		log.Debug("Password reset attempted by non-user role", logger.Int("role_id", user.RoleID))
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error":   "invalid_credentials",
			"message": "Invalid email or binding email.",
		})
	}

	// User must configure binding email before using forgot password.
	if !user.BindingEmail.Valid || user.BindingEmail.String == "" {
		log.Debug("Password reset attempted without binding email configured", logger.Email(req.Email))
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error":   "invalid_credentials",
			"message": "Invalid email or binding email. Please set binding email before using forgot password.",
		})
	}

	// Determine expected binding email
	expectedBindingEmail := user.BindingEmail.String

	// Validate binding email
	if req.BindingEmail != expectedBindingEmail {
		log.Debug("Invalid binding email provided",
			logger.String("provided", req.BindingEmail),
			logger.String("expected", expectedBindingEmail),
		)

		// Increment failed attempts and check for warnings/blocks
		return handleFailedForgotPasswordAttempt(c, req.Email, log)
	}

	// Binding email validated - reset attempts counter
	resetForgotPasswordAttempts(req.Email, log)

	// Invalidate any existing codes for this user
	_, err = config.DB.Exec(`
		UPDATE password_reset_codes
		SET used_at = NOW()
		WHERE user_id = ? AND used_at IS NULL
	`, user.ID)
	if err != nil {
		log.Warn("Error invalidating existing reset codes", logger.Err(err))
	}

	// Generate 4-digit code
	code, err := generateCode()
	if err != nil {
		log.Error("Error generating reset code", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
	}

	log.Debug("Generated password reset code")

	// Hash the code
	codeHash := hashCode(code)
	expiresAt := now.Add(CodeExpiry)

	// Determine where to send the email
	sendToEmail := expectedBindingEmail

	// Store the code
	_, err = config.DB.Exec(`
		INSERT INTO password_reset_codes (user_id, code_hash, binding_email, expires_at, created_at)
		VALUES (?, ?, ?, ?, NOW())
	`, user.ID, codeHash, sendToEmail, expiresAt)
	if err != nil {
		log.Error("Error storing reset code", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
	}

	emailBody := fmt.Sprintf(`
<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Mailria Password Reset</title>
    <style>
      a[x-apple-data-detectors],
      u + #body a,
      #MessageViewBody a {
        color: inherit !important;
        text-decoration: none !important;
        font: inherit !important;
      }
    </style>
  </head>
  <body id="body" style="margin:0; padding:0; background-color:#f3f4f6;">
    <table role="presentation" cellpadding="0" cellspacing="0" width="100%%" style="background-color:#f3f4f6; padding:32px 0;">
      <tr>
        <td align="center">
          <table role="presentation" cellpadding="0" cellspacing="0" width="100%%" style="max-width:420px; width:100%%; background-color:#ffffff; border-radius:8px; box-shadow:0 10px 25px -8px rgba(16,24,40,0.18); padding:16px; font-family:Roboto, Arial, sans-serif;box-shadow: 0 6px 15px -2px rgba(16, 24, 40, 0.08), 0 6px 15px -2px rgba(16, 24, 40, 0.08);">
            <tr>
              <td style="padding-bottom:20px;">
                <img src="https://image2url.com/r2/default/images/1771230290196-42620d10-b63b-46d7-8b1d-5879eb9c7830.png" width="112" height="40" alt="Mailria" style="display:block; border:0; outline:none; text-decoration:none;" />
              </td>
            </tr>
            <tr>
              <td style="color:#1F2937; font-family:Roboto, Arial, sans-serif; font-size:18px; font-style:normal; font-weight:600; line-height:24px; letter-spacing:-0.36px; padding-bottom:16px;">
                Hello <span style="color:#1F2937; text-decoration:none;">%s</span>,
              </td>
            </tr>
            <tr>
              <td style="color:#4B5563; font-family:Roboto, Arial, sans-serif; font-size:14px; font-style:normal; font-weight:400; line-height:20px; padding-bottom:16px;">
                You requested to reset your password. Use the verification code below to continue.
              </td>
            </tr>
            <tr>
              <td style="padding-bottom:16px;">
                <table role="presentation" cellpadding="0" cellspacing="0">
                  <tr>
                    <td style="color:#4B5563; font-family:Roboto, Arial, sans-serif; font-size:14px; font-style:normal; font-weight:400; line-height:20px; text-align:center;">
                      %s
                    </td>
                  </tr>
                </table>
              </td>
            </tr>
            <tr>
              <td style="color:#4B5563; font-family:Roboto, Arial, sans-serif; font-size:14px; font-style:normal; font-weight:400; line-height:20px; padding-bottom:16px;">
                This code will expire in <strong>30 minutes.</strong>
              </td>
            </tr>
            <tr>
              <td style="color:#4B5563; font-family:Roboto, Arial, sans-serif; font-size:14px; font-style:normal; font-weight:400; line-height:20px; padding-bottom:16px;">
                If you didn’t request this, please ignore this email.
              </td>
            </tr>
            <tr>
              <td style="color:#4b5563; font-size:14px; line-height:20px;">
                Thanks,<br />
                Mailria Team
              </td>
            </tr>
          </table>
        </td>
      </tr>
    </table>
  </body>
</html>
	`, req.Email, code)

	emailFrom := viper.GetString("EMAIL_SUPPORT")
	err = pkg.SendEmailViaResend(emailFrom, sendToEmail, "Mailria Password Reset Code", emailBody, nil)
	if err != nil {
		log.Error("Error sending password reset email", err)
		// Still return success
	} else {
		log.Info("Password reset code sent", logger.String("binding_email", sendToEmail))
	}

	return c.JSON(http.StatusOK, map[string]string{
		"message": "If the email and binding email are correct, a verification code has been sent.",
	})
}

// handleFailedForgotPasswordAttempt handles failed binding email validation
func handleFailedForgotPasswordAttempt(c echo.Context, email string, log logger.Logger) error {
	now := time.Now()

	// Get or create attempt record
	var attempt ForgotPasswordAttempt
	err := config.DB.Get(&attempt, `
		SELECT id, email, failed_attempts, blocked_until, last_attempt_at, created_at
		FROM forgot_password_attempts
		WHERE email = ?
	`, email)

	if err == sql.ErrNoRows {
		// Create new attempt record
		_, err = config.DB.Exec(`
			INSERT INTO forgot_password_attempts (email, failed_attempts, last_attempt_at, created_at)
			VALUES (?, 1, NOW(), NOW())
		`, email)
		if err != nil {
			log.Warn("Error creating forgot password attempt", logger.Err(err))
		}
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error":   "invalid_credentials",
			"message": "Invalid email or binding email.",
		})
	}

	if err != nil {
		log.Warn("Error fetching forgot password attempts", logger.Err(err))
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error":   "invalid_credentials",
			"message": "Invalid email or binding email.",
		})
	}

	// Increment failed attempts
	newAttempts := attempt.FailedAttempts + 1

	// 5th attempt - block for 5 minutes
	if newAttempts >= MaxFailedAttempts {
		blockedUntil := now.Add(BlockDuration)
		_, err = config.DB.Exec(`
			UPDATE forgot_password_attempts
			SET failed_attempts = ?, blocked_until = ?, last_attempt_at = NOW()
			WHERE email = ?
		`, newAttempts, blockedUntil, email)
		if err != nil {
			log.Warn("Error updating forgot password attempts", logger.Err(err))
		}
		log.Info("Forgot password blocked due to too many attempts", logger.Email(email))
		return c.JSON(http.StatusTooManyRequests, map[string]interface{}{
			"error":         "too_many_attempts",
			"message":       "Too many failed attempts. Try again in 5 minutes.",
			"blocked_until": blockedUntil.Format(time.RFC3339),
		})
	}

	// 4th attempt - warning
	if newAttempts == MaxFailedAttempts-1 {
		_, err = config.DB.Exec(`
			UPDATE forgot_password_attempts
			SET failed_attempts = ?, last_attempt_at = NOW()
			WHERE email = ?
		`, newAttempts, email)
		if err != nil {
			log.Warn("Error updating forgot password attempts", logger.Err(err))
		}
		return c.JSON(http.StatusBadRequest, map[string]interface{}{
			"error":              "attempt_warning",
			"message":            "One more attempt before access is blocked.",
			"remaining_attempts": 1,
		})
	}

	// Normal failed attempt
	_, err = config.DB.Exec(`
		UPDATE forgot_password_attempts
		SET failed_attempts = ?, last_attempt_at = NOW()
		WHERE email = ?
	`, newAttempts, email)
	if err != nil {
		log.Warn("Error updating forgot password attempts", logger.Err(err))
	}

	return c.JSON(http.StatusBadRequest, map[string]string{
		"error":   "invalid_credentials",
		"message": "Invalid email or binding email.",
	})
}

// resetForgotPasswordAttempts resets the attempt counter after successful validation
func resetForgotPasswordAttempts(email string, log logger.Logger) {
	_, err := config.DB.Exec(`
		UPDATE forgot_password_attempts
		SET failed_attempts = 0, blocked_until = NULL
		WHERE email = ?
	`, email)
	if err != nil {
		log.Warn("Error resetting forgot password attempts", logger.Err(err))
	}
}

// VerifyCodeHandler handles the code verification request
func VerifyCodeHandler(c echo.Context) error {
	log := logger.Get().WithComponent("password_verify")

	req := new(VerifyCodeRequest)
	if err := c.Bind(req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	if req.Email == "" || req.Code == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error":   "invalid_request",
			"message": "Email and code are required.",
		})
	}

	// Find user by email
	var user User
	err := config.DB.Get(&user, "SELECT id, email, binding_email, role_id FROM users WHERE email = ?", req.Email)
	if err != nil {
		log.Debug("Verify code attempted for unknown user", logger.Email(req.Email))
		return c.JSON(http.StatusBadRequest, map[string]interface{}{
			"error":   "invalid_code",
			"message": "Invalid code.",
		})
	}

	log = log.WithUserID(user.ID)

	// Only allow role_id = 1 (User)
	if user.RoleID != 1 {
		log.Debug("Verify code attempted by non-user role", logger.Int("role_id", user.RoleID))
		return c.JSON(http.StatusBadRequest, map[string]interface{}{
			"error":   "invalid_code",
			"message": "Invalid code.",
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
			log.Debug("No valid reset code found")
			return c.JSON(http.StatusBadRequest, map[string]interface{}{
				"error":   "invalid_code",
				"message": "Invalid code.",
			})
		}
		log.Error("Error fetching reset code", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
	}

	// Check if blocked
	if resetCode.BlockedUntil.Valid && resetCode.BlockedUntil.Time.After(now) {
		return c.JSON(http.StatusTooManyRequests, map[string]interface{}{
			"error":         "too_many_attempts",
			"message":       "Too many failed attempts. Try again in 5 minutes.",
			"blocked_until": resetCode.BlockedUntil.Time.Format(time.RFC3339),
		})
	}

	// Check if expired
	if resetCode.ExpiresAt.Before(now) {
		return c.JSON(http.StatusBadRequest, map[string]interface{}{
			"error":   "invalid_code",
			"message": "Invalid code.",
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
				log.Warn("Error updating failed attempts", logger.Err(err))
			}
			return c.JSON(http.StatusTooManyRequests, map[string]interface{}{
				"error":         "too_many_attempts",
				"message":       "Too many failed attempts. Try again in 5 minutes.",
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
				log.Warn("Error updating failed attempts", logger.Err(err))
			}
			return c.JSON(http.StatusBadRequest, map[string]interface{}{
				"error":              "attempt_warning",
				"message":            "One more attempt before access is blocked.",
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
			log.Warn("Error updating failed attempts", logger.Err(err))
		}

		return c.JSON(http.StatusBadRequest, map[string]interface{}{
			"error":   "invalid_code",
			"message": "Invalid code.",
		})
	}

	// Code is valid - generate reset token
	resetToken, err := generateResetToken()
	if err != nil {
		log.Error("Error generating reset token", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
	}

	// Mark code as verified and store reset token
	_, err = config.DB.Exec(`
		UPDATE password_reset_codes
		SET verified_at = NOW(), reset_token = ?
		WHERE id = ?
	`, resetToken, resetCode.ID)
	if err != nil {
		log.Error("Error updating verified status", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
	}

	log.Info("Password reset code verified successfully")
	return c.JSON(http.StatusOK, VerifyCodeResponse{
		Message:    "Code verified successfully",
		ResetToken: resetToken,
	})
}

// ResetPasswordHandler handles the password reset request
func ResetPasswordHandler(c echo.Context) error {
	log := logger.Get().WithComponent("password_reset")

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
		log.Debug("Password reset attempted for unknown user", logger.Email(req.Email))
		return c.JSON(http.StatusBadRequest, map[string]interface{}{
			"error":   "invalid_token",
			"message": "Invalid or expired reset token",
		})
	}

	log = log.WithUserID(user.ID)

	// Only allow role_id = 1 (User)
	if user.RoleID != 1 {
		log.Debug("Password reset attempted by non-user role", logger.Int("role_id", user.RoleID))
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
			log.Debug("Invalid or expired reset token")
			return c.JSON(http.StatusBadRequest, map[string]interface{}{
				"error":   "invalid_token",
				"message": "Invalid or expired reset token",
			})
		}
		log.Error("Error fetching reset code", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
	}

	// Check if reset token is expired (10 minutes after verification)
	if resetCode.VerifiedAt.Valid && now.Sub(resetCode.VerifiedAt.Time) > ResetTokenExpiry {
		log.Debug("Reset token expired")
		return c.JSON(http.StatusBadRequest, map[string]interface{}{
			"error":   "invalid_token",
			"message": "Invalid or expired reset token",
		})
	}

	// Hash the new password
	hashedPassword, err := utils.HashPassword(req.NewPassword)
	if err != nil {
		log.Error("Error hashing password", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
	}

	// Start transaction
	tx, err := config.DB.Begin()
	if err != nil {
		log.Error("Error starting transaction", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
	}
	defer tx.Rollback()

	// Update password
	_, err = tx.Exec(`
		UPDATE users
		SET password = ?, token_version = token_version + 1, updated_at = NOW()
		WHERE id = ?
	`, hashedPassword, user.ID)
	if err != nil {
		log.Error("Error updating password", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
	}

	// Mark reset code as used
	_, err = tx.Exec(`
		UPDATE password_reset_codes
		SET used_at = NOW()
		WHERE id = ?
	`, resetCode.ID)
	if err != nil {
		log.Error("Error marking code as used", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
	}

	// Revoke all refresh tokens for security
	_, err = tx.Exec(`
		UPDATE refresh_tokens
		SET revoked_at = NOW()
		WHERE user_id = ? AND revoked_at IS NULL
	`, user.ID)
	if err != nil {
		log.Warn("Error revoking refresh tokens", logger.Err(err))
		// Don't fail the request, just log
	}

	if err := tx.Commit(); err != nil {
		log.Error("Error committing transaction", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
	}

	log.Info("Password reset completed successfully")
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
