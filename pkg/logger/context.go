package logger

import (
	"context"
)

// Context keys for storing values
type contextKey string

const (
	// ContextKeyRequestID is the context key for request ID
	ContextKeyRequestID contextKey = "request_id"
	// ContextKeyUserID is the context key for user ID
	ContextKeyUserID contextKey = "user_id"
	// ContextKeyLogger is the context key for logger
	ContextKeyLogger contextKey = "logger"
)

// WithRequestIDContext adds request ID to context
func WithRequestIDContext(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, ContextKeyRequestID, requestID)
}

// WithUserIDContext adds user ID to context
func WithUserIDContext(ctx context.Context, userID int64) context.Context {
	return context.WithValue(ctx, ContextKeyUserID, userID)
}

// WithLoggerContext adds logger to context
func WithLoggerContext(ctx context.Context, log Logger) context.Context {
	return context.WithValue(ctx, ContextKeyLogger, log)
}

// GetRequestID gets request ID from context
func GetRequestID(ctx context.Context) string {
	if requestID, ok := ctx.Value(ContextKeyRequestID).(string); ok {
		return requestID
	}
	return ""
}

// GetUserID gets user ID from context
func GetUserID(ctx context.Context) int64 {
	if userID, ok := ctx.Value(ContextKeyUserID).(int64); ok {
		return userID
	}
	return 0
}

// FromContext gets logger from context or returns global logger
func FromContext(ctx context.Context) Logger {
	if log, ok := ctx.Value(ContextKeyLogger).(Logger); ok {
		return log
	}
	return Get()
}
