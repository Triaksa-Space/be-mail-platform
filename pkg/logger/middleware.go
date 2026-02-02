package logger

import (
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

// RequestIDHeader is the HTTP header for request ID
const RequestIDHeader = "X-Request-ID"

// RequestLoggerMiddleware creates a middleware that logs HTTP requests
func RequestLoggerMiddleware(log Logger) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			start := time.Now()
			req := c.Request()

			// Generate or extract request ID
			requestID := req.Header.Get(RequestIDHeader)
			if requestID == "" {
				requestID = uuid.New().String()
			}

			// Set request ID in context and response header
			c.Set(string(ContextKeyRequestID), requestID)
			c.Response().Header().Set(RequestIDHeader, requestID)

			// Create request-scoped logger
			reqLog := log.WithRequestID(requestID).WithFields(
				Method(req.Method),
				Path(req.URL.Path),
				RemoteIP(c.RealIP()),
				String("user_agent", req.UserAgent()),
			)

			// Log request start (debug level to reduce noise)
			reqLog.Debug("Request started")

			// Process request
			err := next(c)

			// Calculate duration
			duration := time.Since(start)

			// Get response status
			status := c.Response().Status

			// Build log fields
			logFields := []Field{
				Status(status),
				Duration("duration_ms", duration),
				Int64("bytes_out", c.Response().Size),
			}

			// Add user ID if available
			if userID, ok := c.Get("user_id").(int64); ok {
				logFields = append(logFields, UserID(userID))
			}

			// Log based on status and error
			if err != nil {
				logFields = append(logFields, Err(err))
				reqLog.Error("Request failed", err, logFields...)
			} else if status >= 500 {
				reqLog.Error("Server error response", nil, logFields...)
			} else if status >= 400 {
				reqLog.Warn("Client error response", logFields...)
			} else {
				reqLog.Info("Request completed", logFields...)
			}

			return err
		}
	}
}

// RecoveryMiddleware creates a middleware that recovers from panics and logs them
func RecoveryMiddleware(log Logger) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			defer func() {
				if r := recover(); r != nil {
					// Get request ID
					requestID, _ := c.Get(string(ContextKeyRequestID)).(string)
					reqLog := log.WithRequestID(requestID)

					// Log panic
					reqLog.Error("Panic recovered",
						nil,
						Any("panic", r),
						Method(c.Request().Method),
						Path(c.Request().URL.Path),
					)

					// Return 500 error
					c.JSON(500, map[string]interface{}{
						"error":      "INTERNAL_ERROR",
						"message":    "An unexpected error occurred",
						"request_id": requestID,
					})
				}
			}()
			return next(c)
		}
	}
}

// GetRequestIDFromContext gets request ID from echo context
func GetRequestIDFromContext(c echo.Context) string {
	if requestID, ok := c.Get(string(ContextKeyRequestID)).(string); ok {
		return requestID
	}
	return ""
}
