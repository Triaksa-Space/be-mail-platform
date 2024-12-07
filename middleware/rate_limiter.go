package middleware

import (
	"database/sql"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/gommon/log"
)

// RateLimiterConfig holds the configuration for rate limiting
type RateLimiterConfig struct {
	MaxRequests   int           // Maximum number of requests allowed
	Window        time.Duration // Time window for rate limiting
	BlockDuration time.Duration // Duration to block the IP after exceeding limits
	DB            *sql.DB       // Database connection
}

// RateLimiterMiddleware returns a middleware that limits the number of requests per IP using a database table.
func RateLimiterMiddleware(config RateLimiterConfig) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			ip := c.RealIP()
			now := time.Now()

			tx, err := config.DB.Begin()
			if err != nil {
				log.Error("Failed to begin transaction:", err)
				return c.JSON(http.StatusInternalServerError, map[string]string{
					"error": "Internal server error",
				})
			}
			defer tx.Rollback()

			var blockedUntil sql.NullTime
			err = tx.QueryRow("SELECT blocked_until FROM ip_rate_limits WHERE ip_address = ?", ip).Scan(&blockedUntil)
			if err != nil && err != sql.ErrNoRows {
				log.Error("Failed to fetch blocked_until:", err)
				return c.JSON(http.StatusInternalServerError, map[string]string{
					"error": "Internal server error",
				})
			}

			// Check if IP is currently blocked
			if blockedUntil.Valid && blockedUntil.Time.After(now) {
				tx.Commit()
				return c.JSON(http.StatusTooManyRequests, map[string]string{
					"error": "Too many requests from this IP, please try again later.",
				})
			}

			var requestCount int
			var firstRequestTime time.Time
			err = tx.QueryRow("SELECT request_count, first_request_time FROM ip_rate_limits WHERE ip_address = ?", ip).Scan(&requestCount, &firstRequestTime)
			if err != nil && err != sql.ErrNoRows {
				log.Error("Failed to fetch rate limit data:", err)
				return c.JSON(http.StatusInternalServerError, map[string]string{
					"error": "Internal server error",
				})
			}

			if err == sql.ErrNoRows {
				// First request from this IP
				_, err = tx.Exec(`
                    INSERT INTO ip_rate_limits (ip_address, request_count, first_request_time, last_request_time)
                    VALUES (?, 1, ?, ?)
                `, ip, now, now)
				if err != nil {
					log.Error("Failed to insert rate limit data:", err)
					return c.JSON(http.StatusInternalServerError, map[string]string{
						"error": "Internal server error",
					})
				}
			} else {
				// Calculate if the current window has expired
				if now.Sub(firstRequestTime) > config.Window {
					// Reset the window
					_, err = tx.Exec(`
                        UPDATE ip_rate_limits
                        SET request_count = 1, first_request_time = ?, last_request_time = ?, blocked_until = NULL
                        WHERE ip_address = ?
                    `, now, now, ip)
					if err != nil {
						log.Error("Failed to reset rate limit data:", err)
						return c.JSON(http.StatusInternalServerError, map[string]string{
							"error": "Internal server error",
						})
					}
				} else {
					if requestCount >= config.MaxRequests {
						// Block the IP
						blockedUntilTime := now.Add(config.BlockDuration)
						_, err = tx.Exec(`
                            UPDATE ip_rate_limits
                            SET blocked_until = ?
                            WHERE ip_address = ?
                        `, blockedUntilTime, ip)
						if err != nil {
							log.Error("Failed to block IP:", err)
							return c.JSON(http.StatusInternalServerError, map[string]string{
								"error": "Internal server error",
							})
						}
						tx.Commit()
						return c.JSON(http.StatusTooManyRequests, map[string]string{
							"error": "Too many requests from this IP, please try again later.",
						})
					}

					// Increment the request count
					_, err = tx.Exec(`
                        UPDATE ip_rate_limits
                        SET request_count = request_count + 1, last_request_time = ?
                        WHERE ip_address = ?
                    `, now, ip)
					if err != nil {
						log.Error("Failed to update rate limit data:", err)
						return c.JSON(http.StatusInternalServerError, map[string]string{
							"error": "Internal server error",
						})
					}
				}
			}

			// Commit the transaction
			if err := tx.Commit(); err != nil {
				log.Error("Failed to commit transaction:", err)
				return c.JSON(http.StatusInternalServerError, map[string]string{
					"error": "Internal server error",
				})
			}

			// Proceed to the next handler
			return next(c)
		}
	}
}
