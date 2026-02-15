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
	"github.com/Triaksa-Space/be-mail-platform/pkg/apperrors"
	"github.com/Triaksa-Space/be-mail-platform/pkg/logger"
	"github.com/Triaksa-Space/be-mail-platform/utils"
	"github.com/labstack/echo/v4"
)

// User struct for database queries
type User struct {
	ID           int64  `db:"id"`
	Email        string `db:"email"`
	Password     string `db:"password"`
	RoleID       int    `db:"role_id"`
	TokenVersion int64  `db:"token_version"`
}

// LoginHandler handles user login with refresh token support
func LoginHandler(c echo.Context) error {
	log := logger.Get().WithComponent("auth")
	requestID := logger.GetRequestIDFromContext(c)
	log = log.WithRequestID(requestID)

	req := new(LoginRequest)
	if err := c.Bind(req); err != nil {
		log.Warn("Invalid login request payload", logger.Err(err))
		return apperrors.RespondWithError(c, apperrors.NewBadRequest(
			apperrors.ErrCodeValidationFailed,
			"Invalid request payload.",
		))
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
				log.Error("Failed to insert initial login attempts record", err, logger.Email(req.Email))
				return apperrors.RespondWithError(c, apperrors.NewInternal(
					apperrors.ErrCodeDatabaseError,
					"Internal server error.",
					err,
				))
			}

			err = config.DB.Get(&attempts, `
				SELECT failed_attempts, blocked_until
				FROM user_login_attempts
				WHERE username = ?
			`, req.Email)
			if err != nil {
				log.Error("Failed to fetch login attempts after insert", err, logger.Email(req.Email))
				return apperrors.RespondWithError(c, apperrors.NewInternal(
					apperrors.ErrCodeDatabaseError,
					"Internal server error.",
					err,
				))
			}
		} else {
			log.Error("Failed to fetch login attempts", err, logger.Email(req.Email))
			return apperrors.RespondWithError(c, apperrors.NewInternal(
				apperrors.ErrCodeDatabaseError,
				"Internal server error.",
				err,
			))
		}
	}

	// Check if user is currently blocked
	if attempts.BlockedUntil.Valid && attempts.BlockedUntil.Time.After(now) {
		remaining := attempts.BlockedUntil.Time.Sub(now)
		log.Warn("Login attempt while account locked", logger.Email(req.Email))
		return apperrors.RespondWithError(c, apperrors.NewTooManyRequests(
			apperrors.ErrCodeAccountLocked,
			fmt.Sprintf("Account temporarily locked. Please try again in %d minutes and %d seconds.",
				int(remaining.Minutes()), int(remaining.Seconds())%60),
		))
	}

	// If block period has passed, reset attempts
	if attempts.BlockedUntil.Valid && attempts.BlockedUntil.Time.Before(now) {
		_, err = config.DB.Exec(`
			UPDATE user_login_attempts
			SET failed_attempts = 0, blocked_until = NULL
			WHERE username = ?
		`, req.Email)
		if err != nil {
			log.Error("Failed to reset login attempts after block period", err, logger.Email(req.Email))
			return apperrors.RespondWithError(c, apperrors.NewInternal(
				apperrors.ErrCodeDatabaseError,
				"Internal server error.",
				err,
			))
		}
		attempts.FailedAttempts = 0
		attempts.BlockedUntil.Valid = false
	}

	// Fetch user from the database
	var user User
	err = config.DB.Get(&user, "SELECT id, email, password, role_id, token_version FROM users WHERE email = ?", req.Email)
	if err != nil {
		if err == sql.ErrNoRows {
			return handleFailedAttempt(c, log, req.Email, attempts.FailedAttempts, now)
		}
		log.Error("Failed to fetch user", err, logger.Email(req.Email))
		return apperrors.RespondWithError(c, apperrors.NewInternal(
			apperrors.ErrCodeDatabaseError,
			"Internal server error.",
			err,
		))
	}

	// Check password
	if !utils.CheckPasswordHash(req.Password, user.Password) {
		return handleFailedAttempt(c, log, req.Email, attempts.FailedAttempts, now)
	}

	// Successful login - reset attempts
	_, err = config.DB.Exec(`
		UPDATE user_login_attempts
		SET failed_attempts = 0, blocked_until = NULL
		WHERE username = ?
	`, req.Email)
	if err != nil {
		log.Error("Failed to reset login attempts on success", err, logger.Email(req.Email))
		return apperrors.RespondWithError(c, apperrors.NewInternal(
			apperrors.ErrCodeDatabaseError,
			"Internal server error.",
			err,
		))
	}

	// Generate access token
	accessToken, err := utils.GenerateAccessToken(user.ID, user.Email, user.RoleID, user.TokenVersion)
	if err != nil {
		log.Error("Failed to generate access token", err, logger.UserID(user.ID))
		return apperrors.RespondWithError(c, apperrors.NewInternal(
			apperrors.ErrCodeUnexpectedError,
			"Internal server error.",
			err,
		))
	}

	// Generate refresh token
	refreshToken, err := generateRefreshToken()
	if err != nil {
		log.Error("Failed to generate refresh token", err, logger.UserID(user.ID))
		return apperrors.RespondWithError(c, apperrors.NewInternal(
			apperrors.ErrCodeUnexpectedError,
			"Internal server error.",
			err,
		))
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
		log.Error("Failed to store refresh token", err, logger.UserID(user.ID))
		return apperrors.RespondWithError(c, apperrors.NewInternal(
			apperrors.ErrCodeDatabaseError,
			"Internal server error.",
			err,
		))
	}

	// Update last login time
	_, err = config.DB.Exec("UPDATE users SET last_login = ? WHERE id = ?", now, user.ID)
	if err != nil {
		log.Warn("Failed to update last login time", logger.UserID(user.ID), logger.Err(err))
	}

	log.Info("User logged in successfully",
		logger.UserID(user.ID),
		logger.Email(user.Email),
		logger.Bool("remember_me", req.RememberMe),
	)

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
	log := logger.Get().WithComponent("auth")
	requestID := logger.GetRequestIDFromContext(c)
	log = log.WithRequestID(requestID)

	req := new(RefreshTokenRequest)
	if err := c.Bind(req); err != nil {
		return apperrors.RespondWithError(c, apperrors.NewBadRequest(
			apperrors.ErrCodeValidationFailed,
			"Invalid request payload.",
		))
	}

	if req.RefreshToken == "" {
		return apperrors.RespondWithError(c, apperrors.NewBadRequest(
			apperrors.ErrCodeMissingField,
			"refresh_token is required.",
		))
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
			log.Warn("Invalid refresh token used")
			return apperrors.RespondWithError(c, apperrors.NewUnauthorized(
				apperrors.ErrCodeRefreshTokenInvalid,
				"Invalid refresh token. Please login again.",
			))
		}
		log.Error("Failed to fetch refresh token", err)
		return apperrors.RespondWithError(c, apperrors.NewInternal(
			apperrors.ErrCodeDatabaseError,
			"Internal server error.",
			err,
		))
	}

	// Check if token is revoked
	if storedToken.RevokedAt.Valid {
		// Token reuse detected - this could be a theft attempt
		// Revoke all tokens for this user for security
		log.Warn("Refresh token reuse detected - possible token theft",
			logger.UserID(storedToken.UserID),
		)

		_, err = config.DB.Exec(`
			UPDATE refresh_tokens
			SET revoked_at = ?
			WHERE user_id = ? AND revoked_at IS NULL
		`, now, storedToken.UserID)
		if err != nil {
			log.Error("Failed to revoke all tokens after reuse detection", err, logger.UserID(storedToken.UserID))
		}

		return apperrors.RespondWithError(c, apperrors.NewUnauthorized(
			apperrors.ErrCodeRefreshTokenReused,
			"Token reuse detected. All sessions have been revoked. Please login again.",
		))
	}

	// Check if token is expired
	if storedToken.ExpiresAt.Before(now) {
		log.Debug("Refresh token expired", logger.UserID(storedToken.UserID))
		return apperrors.RespondWithError(c, apperrors.NewUnauthorized(
			apperrors.ErrCodeRefreshTokenExpired,
			"Your session has expired. Please login again.",
		))
	}

	// Get user information
	var user User
	err = config.DB.Get(&user, "SELECT id, email, role_id, token_version FROM users WHERE id = ?", storedToken.UserID)
	if err != nil {
		log.Error("Failed to fetch user for token refresh", err, logger.UserID(storedToken.UserID))
		return apperrors.RespondWithError(c, apperrors.NewInternal(
			apperrors.ErrCodeDatabaseError,
			"Internal server error.",
			err,
		))
	}

	// Generate new access token
	accessToken, err := utils.GenerateAccessToken(user.ID, user.Email, user.RoleID, user.TokenVersion)
	if err != nil {
		log.Error("Failed to generate access token", err, logger.UserID(user.ID))
		return apperrors.RespondWithError(c, apperrors.NewInternal(
			apperrors.ErrCodeUnexpectedError,
			"Internal server error.",
			err,
		))
	}

	// Generate new refresh token (rotation)
	newRefreshToken, err := generateRefreshToken()
	if err != nil {
		log.Error("Failed to generate refresh token", err, logger.UserID(user.ID))
		return apperrors.RespondWithError(c, apperrors.NewInternal(
			apperrors.ErrCodeUnexpectedError,
			"Internal server error.",
			err,
		))
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
		log.Error("Failed to start transaction for token rotation", err)
		return apperrors.RespondWithError(c, apperrors.NewInternal(
			apperrors.ErrCodeDatabaseError,
			"Internal server error.",
			err,
		))
	}
	defer tx.Rollback()

	// Insert new refresh token
	result, err := tx.Exec(`
		INSERT INTO refresh_tokens (user_id, token_hash, remember_me, expires_at, created_at, user_agent, ip_address)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, user.ID, newTokenHash, storedToken.RememberMe, newExpiresAt, now, userAgent, ipAddress)
	if err != nil {
		log.Error("Failed to insert new refresh token", err, logger.UserID(user.ID))
		return apperrors.RespondWithError(c, apperrors.NewInternal(
			apperrors.ErrCodeDatabaseError,
			"Internal server error.",
			err,
		))
	}

	newTokenID, _ := result.LastInsertId()

	// Revoke old token and set replaced_by
	_, err = tx.Exec(`
		UPDATE refresh_tokens
		SET revoked_at = ?, replaced_by = ?
		WHERE id = ?
	`, now, newTokenID, storedToken.ID)
	if err != nil {
		log.Error("Failed to revoke old refresh token", err, logger.UserID(user.ID))
		return apperrors.RespondWithError(c, apperrors.NewInternal(
			apperrors.ErrCodeDatabaseError,
			"Internal server error.",
			err,
		))
	}

	if err := tx.Commit(); err != nil {
		log.Error("Failed to commit token rotation transaction", err)
		return apperrors.RespondWithError(c, apperrors.NewInternal(
			apperrors.ErrCodeDatabaseError,
			"Internal server error.",
			err,
		))
	}

	log.Debug("Token refreshed successfully", logger.UserID(user.ID))

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
	log := logger.Get().WithComponent("auth")
	requestID := logger.GetRequestIDFromContext(c)
	log = log.WithRequestID(requestID)

	userID := c.Get("user_id").(int64)
	log = log.WithUserID(userID)

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
			log.Error("Failed to revoke refresh token", err)
			return apperrors.RespondWithError(c, apperrors.NewInternal(
				apperrors.ErrCodeDatabaseError,
				"Internal server error.",
				err,
			))
		}
		log.Info("Single session logout")
	} else {
		// Revoke all refresh tokens for this user
		_, err := config.DB.Exec(`
			UPDATE refresh_tokens
			SET revoked_at = ?
			WHERE user_id = ? AND revoked_at IS NULL
		`, now, userID)
		if err != nil {
			log.Error("Failed to revoke all refresh tokens", err)
			return apperrors.RespondWithError(c, apperrors.NewInternal(
				apperrors.ErrCodeDatabaseError,
				"Internal server error.",
				err,
			))
		}
		log.Info("All sessions logout")
	}

	return c.JSON(http.StatusOK, map[string]string{"message": "Successfully logged out."})
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
func handleFailedAttempt(c echo.Context, log logger.Logger, email string, currentAttempts int, now time.Time) error {
	newAttempts := currentAttempts + 1

	if newAttempts >= 4 {
		blockedUntil := now.Add(5 * time.Minute)
		_, err := config.DB.Exec(`
			UPDATE user_login_attempts
			SET failed_attempts = ?, last_attempt_time = ?, blocked_until = ?
			WHERE username = ?
		`, newAttempts, now, blockedUntil, email)
		if err != nil {
			log.Error("Failed to update login attempts on block", err, logger.Email(email))
		}

		log.Warn("Account locked due to too many failed attempts",
			logger.Email(email),
			logger.Int("attempts", newAttempts),
		)

		return apperrors.RespondWithError(c, apperrors.NewTooManyRequests(
			apperrors.ErrCodeLoginLimitExceeded,
			"Too many failed login attempts. Account locked for 5 minutes.",
		))
	} else if newAttempts == 3 {
		_, err := config.DB.Exec(`
			UPDATE user_login_attempts
			SET failed_attempts = ?, last_attempt_time = ?
			WHERE username = ?
		`, newAttempts, now, email)
		if err != nil {
			log.Error("Failed to update login attempts", err, logger.Email(email))
		}

		log.Warn("Login attempt warning - one more will lock account",
			logger.Email(email),
			logger.Int("attempts", newAttempts),
		)

		return apperrors.RespondWithError(c, apperrors.NewTooManyRequests(
			apperrors.ErrCodeRateLimitExceeded,
			"One more failed attempt will disable login for 5 minutes.",
		))
	} else {
		_, err := config.DB.Exec(`
			UPDATE user_login_attempts
			SET failed_attempts = ?, last_attempt_time = ?
			WHERE username = ?
		`, newAttempts, now, email)
		if err != nil {
			log.Error("Failed to update login attempts", err, logger.Email(email))
		}

		log.Debug("Failed login attempt",
			logger.Email(email),
			logger.Int("attempts", newAttempts),
		)
	}

	return apperrors.RespondWithError(c, apperrors.NewUnauthorized(
		apperrors.ErrCodeInvalidCredentials,
		"Invalid email or password.",
	))
}

// CleanupExpiredTokens removes expired refresh tokens (call via cron job)
func CleanupExpiredTokens() error {
	log := logger.Get().WithComponent("auth")

	result, err := config.DB.Exec(`
		DELETE FROM refresh_tokens
		WHERE expires_at < NOW() OR revoked_at IS NOT NULL
	`)
	if err != nil {
		log.Error("Failed to cleanup expired tokens", err)
		return err
	}

	rowsDeleted, _ := result.RowsAffected()
	if rowsDeleted > 0 {
		log.Info("Cleaned up expired tokens", logger.Int64("deleted_count", rowsDeleted))
	}

	return nil
}
