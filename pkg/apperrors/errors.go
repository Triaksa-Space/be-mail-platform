package apperrors

import (
	"fmt"
	"net/http"
	"runtime"
)

// AppError represents a structured application error
type AppError struct {
	Code       string `json:"code"`             // Machine-readable error code
	Message    string `json:"message"`          // Human-readable message
	Detail     string `json:"detail,omitempty"` // Additional details
	HTTPStatus int    `json:"-"`                // HTTP status code
	Err        error  `json:"-"`                // Original error
	Stack      string `json:"-"`                // Stack trace
}

// Error implements the error interface
func (e *AppError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}
	return e.Message
}

// Unwrap returns the underlying error
func (e *AppError) Unwrap() error {
	return e.Err
}

// WithDetail adds detail to the error
func (e *AppError) WithDetail(detail string) *AppError {
	e.Detail = detail
	return e
}

// --- Error constructors ---

// NewBadRequest creates a 400 Bad Request error
func NewBadRequest(code, message string) *AppError {
	return &AppError{
		Code:       code,
		Message:    message,
		HTTPStatus: http.StatusBadRequest,
		Stack:      getStack(),
	}
}

// NewUnauthorized creates a 401 Unauthorized error
func NewUnauthorized(code, message string) *AppError {
	return &AppError{
		Code:       code,
		Message:    message,
		HTTPStatus: http.StatusUnauthorized,
		Stack:      getStack(),
	}
}

// NewForbidden creates a 403 Forbidden error
func NewForbidden(code, message string) *AppError {
	return &AppError{
		Code:       code,
		Message:    message,
		HTTPStatus: http.StatusForbidden,
		Stack:      getStack(),
	}
}

// NewNotFound creates a 404 Not Found error
func NewNotFound(code, message string) *AppError {
	return &AppError{
		Code:       code,
		Message:    message,
		HTTPStatus: http.StatusNotFound,
		Stack:      getStack(),
	}
}

// NewTooManyRequests creates a 429 Too Many Requests error
func NewTooManyRequests(code, message string) *AppError {
	return &AppError{
		Code:       code,
		Message:    message,
		HTTPStatus: http.StatusTooManyRequests,
		Stack:      getStack(),
	}
}

// NewInternal creates a 500 Internal Server Error
func NewInternal(code, message string, err error) *AppError {
	return &AppError{
		Code:       code,
		Message:    message,
		Err:        err,
		HTTPStatus: http.StatusInternalServerError,
		Stack:      getStack(),
	}
}

// NewConflict creates a 409 Conflict error
func NewConflict(code, message string) *AppError {
	return &AppError{
		Code:       code,
		Message:    message,
		HTTPStatus: http.StatusConflict,
		Stack:      getStack(),
	}
}

// NewServiceUnavailable creates a 503 Service Unavailable error
func NewServiceUnavailable(code, message string, err error) *AppError {
	return &AppError{
		Code:       code,
		Message:    message,
		Err:        err,
		HTTPStatus: http.StatusServiceUnavailable,
		Stack:      getStack(),
	}
}

// getStack captures the current stack trace
func getStack() string {
	buf := make([]byte, 4096)
	n := runtime.Stack(buf, false)
	return string(buf[:n])
}

// IsAppError checks if an error is an AppError
func IsAppError(err error) bool {
	_, ok := err.(*AppError)
	return ok
}

// AsAppError attempts to convert an error to AppError
func AsAppError(err error) (*AppError, bool) {
	if appErr, ok := err.(*AppError); ok {
		return appErr, true
	}
	return nil, false
}
