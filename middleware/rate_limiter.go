package middleware

import (
	"database/sql"
	"fmt"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/gommon/log"
)

// RateLimiterConfig holds the configuration for rate limiting
type RateLimiterConfig struct {
	MaxAttempts   int           // Maximum number of failed login attempts allowed
	BlockDuration time.Duration // Duration to block the user after exceeding limits
	DB            *sql.DB       // Database connection
}

// RateLimiterMiddleware returns a middleware that blocks users after too many failed login attempts
func LoginAttemptMiddleware(config RateLimiterConfig) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// Extract username from request
			username := c.FormValue("username") // Adjust based on your login payload structure
			if username == "" {
				return next(c)
			}

			tx, err := config.DB.Begin()
			if err != nil {
				log.Error("Failed to begin transaction:", err)
				return c.JSON(http.StatusInternalServerError, map[string]string{
					"error": "Internal server error",
				})
			}
			defer tx.Rollback()

			var blockedUntil sql.NullTime
			err = tx.QueryRow("SELECT blocked_until FROM user_login_attempts WHERE username = ?", username).Scan(&blockedUntil)
			if err != nil && err != sql.ErrNoRows {
				log.Error("Failed to fetch blocked_until:", err)
				return c.JSON(http.StatusInternalServerError, map[string]string{
					"error": "Internal server error",
				})
			}

			now := time.Now()

			// Check if user is currently blocked
			if blockedUntil.Valid && blockedUntil.Time.After(now) {
				remaining := blockedUntil.Time.Sub(now)
				return c.JSON(http.StatusTooManyRequests, map[string]string{
					"error": fmt.Sprintf("Account temporarily locked. Please try again in %d minutes and %d seconds.",
						int(remaining.Minutes()), int(remaining.Seconds())%60),
				})
			}

			// Store the context for the next handler to check login success/failure
			c.Set("loginAttemptTx", tx)

			// Process the request
			err = next(c)

			// Get the login result from context (should be set by your login handler)
			loginSuccess, _ := c.Get("loginSuccess").(bool)

			if !loginSuccess {
				var attemptCount int
				err = tx.QueryRow("SELECT failed_attempts FROM user_login_attempts WHERE username = ?", username).Scan(&attemptCount)
				if err == sql.ErrNoRows {
					// First failed attempt
					_, err = tx.Exec(`
						INSERT INTO user_login_attempts (username, failed_attempts, last_attempt_time)
						VALUES (?, 1, ?)
					`, username, now)
				} else if err == nil {
					attemptCount++
					if attemptCount >= config.MaxAttempts {
						// Block the user
						blockedUntilTime := now.Add(config.BlockDuration)
						_, err = tx.Exec(`
							UPDATE user_login_attempts
							SET failed_attempts = ?, last_attempt_time = ?, blocked_until = ?
							WHERE username = ?
						`, attemptCount, now, blockedUntilTime, username)

						if err == nil {
							tx.Commit()
							return c.JSON(http.StatusTooManyRequests, map[string]string{
								"error": fmt.Sprintf("Too many failed login attempts. Account locked for %d minutes.",
									int(config.BlockDuration.Minutes())),
							})
						}
					} else {
						// Update attempt count
						_, err = tx.Exec(`
							UPDATE user_login_attempts
							SET failed_attempts = ?, last_attempt_time = ?
							WHERE username = ?
						`, attemptCount, now, username)
					}
				}
			} else {
				// Successful login - reset the counter
				_, err = tx.Exec(`
					UPDATE user_login_attempts
					SET failed_attempts = 0, blocked_until = NULL
					WHERE username = ?
				`, username)
			}

			if err != nil {
				log.Error("Failed to update login attempts:", err)
				return c.JSON(http.StatusInternalServerError, map[string]string{
					"error": "Internal server error",
				})
			}

			tx.Commit()
			return err
		}
	}
}
