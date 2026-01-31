package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

	"github.com/Triaksa-Space/be-mail-platform/config"
	"github.com/Triaksa-Space/be-mail-platform/utils"
	"github.com/labstack/echo/v4"
)

// User struct for database queries
type User struct {
	ID       int64  `db:"id"`
	Email    string `db:"email"`
	Password string `db:"password"`
	RoleID   int    `db:"role_id"`
}

// LoginHandler handles user login with refresh token support
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
			_, err = config.DB.Exec(`
				INSERT INTO user_login_attempts (username, failed_attempts, last_attempt_time)
				VALUES (?, 0, ?)
			`, req.Email, now)
			if err != nil {
				fmt.Println("Error inserting initial attempts record:", err)
				return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
			}

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
	err = config.DB.Get(&user, "SELECT id, email, password, role_id FROM users WHERE email = ?", req.Email)
	if err != nil {
		if err == sql.ErrNoRows {
			return handleFailedAttempt(c, req.Email, attempts.FailedAttempts, now)
		}
		fmt.Println("Error fetching user:", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
	}

	// Check password
	if !utils.CheckPasswordHash(req.Password, user.Password) {
		return handleFailedAttempt(c, req.Email, attempts.FailedAttempts, now)
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

	// Generate access token
	accessToken, err := utils.GenerateAccessToken(user.ID, user.Email, user.RoleID)
	if err != nil {
		fmt.Println("GenerateAccessToken error:", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
	}

	// Generate refresh token
	refreshToken, err := generateRefreshToken()
	if err != nil {
		fmt.Println("GenerateRefreshToken error:", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
	}

	// Calculate expiry based on remember_me
	var expiresAt time.Time
	if req.RememberMe {
		expiresAt = now.Add(RefreshTokenExpiryRememberMe)
	} else {
		expiresAt = now.Add(RefreshTokenExpiry)
	}

	// Store refresh token hash in database
	tokenHash := hashToken(refreshToken)
	userAgent := c.Request().UserAgent()
	ipAddress := c.RealIP()

	_, err = config.DB.Exec(`
		INSERT INTO refresh_tokens (user_id, token_hash, remember_me, expires_at, created_at, user_agent, ip_address)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, user.ID, tokenHash, req.RememberMe, expiresAt, now, userAgent, ipAddress)
	if err != nil {
		fmt.Println("Error storing refresh token:", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
	}

	// Update last login time
	_, err = config.DB.Exec("UPDATE users SET last_login = ? WHERE id = ?", now, user.ID)
	if err != nil {
		fmt.Println("Error updating last login:", err)
	}

	response := LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    AccessTokenExpirySeconds,
		TokenType:    "Bearer",
		User: UserResponse{
			ID:     utils.EncodeID(int(user.ID)),
			Email:  user.Email,
			RoleID: user.RoleID,
		},
	}

	return c.JSON(http.StatusOK, response)
}

// RefreshTokenHandler handles token refresh requests
func RefreshTokenHandler(c echo.Context) error {
	req := new(RefreshTokenRequest)
	if err := c.Bind(req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	if req.RefreshToken == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "refresh_token is required"})
	}

	tokenHash := hashToken(req.RefreshToken)
	now := time.Now()

	// Find the refresh token
	var storedToken RefreshToken
	err := config.DB.Get(&storedToken, `
		SELECT id, user_id, token_hash, remember_me, expires_at, created_at, revoked_at, replaced_by
		FROM refresh_tokens
		WHERE token_hash = ?
	`, tokenHash)

	if err != nil {
		if err == sql.ErrNoRows {
			return c.JSON(http.StatusUnauthorized, map[string]interface{}{
				"error":   "refresh_token_invalid",
				"message": "Invalid refresh token. Please login again.",
			})
		}
		fmt.Println("Error fetching refresh token:", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
	}

	// Check if token is revoked
	if storedToken.RevokedAt.Valid {
		// Token reuse detected - this could be a theft attempt
		// Revoke all tokens for this user for security
		_, err = config.DB.Exec(`
			UPDATE refresh_tokens
			SET revoked_at = ?
			WHERE user_id = ? AND revoked_at IS NULL
		`, now, storedToken.UserID)
		if err != nil {
			fmt.Println("Error revoking all tokens:", err)
		}
		return c.JSON(http.StatusUnauthorized, map[string]interface{}{
			"error":   "refresh_token_reused",
			"message": "Token reuse detected. All sessions have been revoked. Please login again.",
		})
	}

	// Check if token is expired
	if storedToken.ExpiresAt.Before(now) {
		return c.JSON(http.StatusUnauthorized, map[string]interface{}{
			"error":   "refresh_token_expired",
			"message": "Your session has expired. Please login again.",
		})
	}

	// Get user information
	var user User
	err = config.DB.Get(&user, "SELECT id, email, role_id FROM users WHERE id = ?", storedToken.UserID)
	if err != nil {
		fmt.Println("Error fetching user:", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
	}

	// Generate new access token
	accessToken, err := utils.GenerateAccessToken(user.ID, user.Email, user.RoleID)
	if err != nil {
		fmt.Println("GenerateAccessToken error:", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
	}

	// Generate new refresh token (rotation)
	newRefreshToken, err := generateRefreshToken()
	if err != nil {
		fmt.Println("GenerateRefreshToken error:", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
	}

	// Calculate new expiry - sliding expiration for remember_me
	var newExpiresAt time.Time
	if storedToken.RememberMe {
		newExpiresAt = now.Add(RefreshTokenExpiryRememberMe)
	} else {
		// For non-remember_me, keep the original expiry (no extension)
		newExpiresAt = storedToken.ExpiresAt
	}

	newTokenHash := hashToken(newRefreshToken)
	userAgent := c.Request().UserAgent()
	ipAddress := c.RealIP()

	// Start transaction for token rotation
	tx, err := config.DB.Begin()
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
	}
	defer tx.Rollback()

	// Insert new refresh token
	result, err := tx.Exec(`
		INSERT INTO refresh_tokens (user_id, token_hash, remember_me, expires_at, created_at, user_agent, ip_address)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, user.ID, newTokenHash, storedToken.RememberMe, newExpiresAt, now, userAgent, ipAddress)
	if err != nil {
		fmt.Println("Error inserting new refresh token:", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
	}

	newTokenID, _ := result.LastInsertId()

	// Revoke old token and set replaced_by
	_, err = tx.Exec(`
		UPDATE refresh_tokens
		SET revoked_at = ?, replaced_by = ?
		WHERE id = ?
	`, now, newTokenID, storedToken.ID)
	if err != nil {
		fmt.Println("Error revoking old refresh token:", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
	}

	if err := tx.Commit(); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
	}

	response := RefreshTokenResponse{
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken,
		ExpiresIn:    AccessTokenExpirySeconds,
		TokenType:    "Bearer",
	}

	return c.JSON(http.StatusOK, response)
}

// LogoutHandler handles user logout
func LogoutHandler(c echo.Context) error {
	userID := c.Get("user_id").(int64)

	req := new(LogoutRequest)
	if err := c.Bind(req); err != nil {
		// If no body provided, just revoke all tokens for the user
		req = &LogoutRequest{}
	}

	now := time.Now()

	if req.RefreshToken != "" {
		// Revoke specific refresh token
		tokenHash := hashToken(req.RefreshToken)
		_, err := config.DB.Exec(`
			UPDATE refresh_tokens
			SET revoked_at = ?
			WHERE token_hash = ? AND user_id = ?
		`, now, tokenHash, userID)
		if err != nil {
			fmt.Println("Error revoking refresh token:", err)
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
		}
	} else {
		// Revoke all refresh tokens for this user
		_, err := config.DB.Exec(`
			UPDATE refresh_tokens
			SET revoked_at = ?
			WHERE user_id = ? AND revoked_at IS NULL
		`, now, userID)
		if err != nil {
			fmt.Println("Error revoking all refresh tokens:", err)
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
		}
	}

	return c.JSON(http.StatusOK, map[string]string{"message": "Successfully logged out"})
}

// generateRefreshToken generates a cryptographically secure random token
func generateRefreshToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// hashToken creates a SHA256 hash of the token for storage
func hashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

// handleFailedAttempt handles failed login attempts
func handleFailedAttempt(c echo.Context, email string, currentAttempts int, now time.Time) error {
	newAttempts := currentAttempts + 1

	if newAttempts >= 4 {
		blockedUntil := now.Add(5 * time.Minute)
		_, err := config.DB.Exec(`
			UPDATE user_login_attempts
			SET failed_attempts = ?, last_attempt_time = ?, blocked_until = ?
			WHERE username = ?
		`, newAttempts, now, blockedUntil, email)
		if err != nil {
			fmt.Println("Error updating attempts on block:", err)
		}
		return c.JSON(http.StatusTooManyRequests, map[string]string{
			"error": "Too many failed login attempts. Account locked for 5 minutes.",
		})
	} else if newAttempts == 3 {
		_, err := config.DB.Exec(`
			UPDATE user_login_attempts
			SET failed_attempts = ?, last_attempt_time = ?
			WHERE username = ?
		`, newAttempts, now, email)
		if err != nil {
			fmt.Println("Error updating attempts on password mismatch:", err)
		}
		return c.JSON(http.StatusTooManyRequests, map[string]string{
			"error": "Careful! One more failed attempt will disable login for 5 minutes.",
		})
	} else {
		_, err := config.DB.Exec(`
			UPDATE user_login_attempts
			SET failed_attempts = ?, last_attempt_time = ?
			WHERE username = ?
		`, newAttempts, now, email)
		if err != nil {
			fmt.Println("Error updating attempts on password mismatch:", err)
		}
	}
	return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Invalid email or password"})
}

// CleanupExpiredTokens removes expired refresh tokens (call via cron job)
func CleanupExpiredTokens() error {
	_, err := config.DB.Exec(`
		DELETE FROM refresh_tokens
		WHERE expires_at < NOW() OR revoked_at IS NOT NULL
	`)
	return err
}
