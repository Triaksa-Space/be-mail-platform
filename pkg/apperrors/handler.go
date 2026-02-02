package apperrors

import (
	"net/http"

	"github.com/Triaksa-Space/be-mail-platform/pkg/logger"
	"github.com/labstack/echo/v4"
)

// ErrorResponse is the standard error response structure
type ErrorResponse struct {
	Error     string `json:"error"`               // Error code
	Message   string `json:"message"`             // Human-readable message
	Detail    string `json:"detail,omitempty"`    // Additional details
	RequestID string `json:"request_id,omitempty"` // Request ID for tracing
}

// HTTPErrorHandler returns an Echo error handler that uses structured logging
func HTTPErrorHandler(log logger.Logger) echo.HTTPErrorHandler {
	return func(err error, c echo.Context) {
		// Don't handle if already committed
		if c.Response().Committed {
			return
		}

		// Get request ID from context
		requestID := logger.GetRequestIDFromContext(c)
		reqLog := log.WithRequestID(requestID)

		var response ErrorResponse
		var status int

		switch e := err.(type) {
		case *AppError:
			// Our application error
			status = e.HTTPStatus
			response = ErrorResponse{
				Error:     e.Code,
				Message:   e.Message,
				Detail:    e.Detail,
				RequestID: requestID,
			}

			// Log with appropriate level
			if status >= 500 {
				reqLog.Error("Internal error",
					e.Err,
					logger.String("error_code", e.Code),
					logger.String("message", e.Message),
				)
			} else if status >= 400 {
				reqLog.Warn("Client error",
					logger.String("error_code", e.Code),
					logger.String("message", e.Message),
				)
			}

		case *echo.HTTPError:
			// Echo HTTP error
			status = e.Code
			msg, ok := e.Message.(string)
			if !ok {
				msg = "An error occurred"
			}
			response = ErrorResponse{
				Error:     "HTTP_ERROR",
				Message:   msg,
				RequestID: requestID,
			}

			if status >= 500 {
				reqLog.Error("HTTP error", nil, logger.Status(status), logger.String("message", msg))
			}

		default:
			// Unknown error - treat as internal server error
			status = http.StatusInternalServerError
			response = ErrorResponse{
				Error:     ErrCodeUnexpectedError,
				Message:   "An unexpected error occurred",
				RequestID: requestID,
			}
			reqLog.Error("Unhandled error", err)
		}

		// Send response
		if c.Request().Method == http.MethodHead {
			c.NoContent(status)
		} else {
			c.JSON(status, response)
		}
	}
}

// RespondWithError is a helper to return an AppError response
func RespondWithError(c echo.Context, err *AppError) error {
	requestID := logger.GetRequestIDFromContext(c)
	return c.JSON(err.HTTPStatus, ErrorResponse{
		Error:     err.Code,
		Message:   err.Message,
		Detail:    err.Detail,
		RequestID: requestID,
	})
}

// RespondWithSuccess is a helper to return a success response
func RespondWithSuccess(c echo.Context, data interface{}) error {
	return c.JSON(http.StatusOK, data)
}

// RespondWithCreated is a helper to return a 201 Created response
func RespondWithCreated(c echo.Context, data interface{}) error {
	return c.JSON(http.StatusCreated, data)
}
