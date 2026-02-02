package logger

import "time"

// Common field constructors for structured logging

// String creates a string field
func String(key, value string) Field {
	return Field{Key: key, Value: value}
}

// Int creates an int field
func Int(key string, value int) Field {
	return Field{Key: key, Value: value}
}

// Int64 creates an int64 field
func Int64(key string, value int64) Field {
	return Field{Key: key, Value: value}
}

// Bool creates a bool field
func Bool(key string, value bool) Field {
	return Field{Key: key, Value: value}
}

// Err creates an error field
func Err(err error) Field {
	if err == nil {
		return Field{Key: "error", Value: nil}
	}
	return Field{Key: "error", Value: err.Error()}
}

// Duration creates a duration field in milliseconds
func Duration(key string, d time.Duration) Field {
	return Field{Key: key, Value: d.Milliseconds()}
}

// DurationMs creates a duration field from milliseconds
func DurationMs(key string, ms int64) Field {
	return Field{Key: key, Value: ms}
}

// Any creates a field with any value
func Any(key string, value interface{}) Field {
	return Field{Key: key, Value: value}
}

// --- Domain-specific field helpers ---

// UserID creates a user_id field
func UserID(id int64) Field {
	return Field{Key: "user_id", Value: id}
}

// Email creates an email field
func Email(email string) Field {
	return Field{Key: "email", Value: email}
}

// EmailID creates an email_id field
func EmailID(id int64) Field {
	return Field{Key: "email_id", Value: id}
}

// Component creates a component field
func Component(name string) Field {
	return Field{Key: "component", Value: name}
}

// WorkerID creates a worker_id field
func WorkerID(id int) Field {
	return Field{Key: "worker_id", Value: id}
}

// BatchSize creates a batch_size field
func BatchSize(size int) Field {
	return Field{Key: "batch_size", Value: size}
}

// ProcessedCount creates a processed_count field
func ProcessedCount(count int) Field {
	return Field{Key: "processed_count", Value: count}
}

// FailedCount creates a failed_count field
func FailedCount(count int) Field {
	return Field{Key: "failed_count", Value: count}
}

// Status creates a status field
func Status(status int) Field {
	return Field{Key: "status", Value: status}
}

// Method creates an HTTP method field
func Method(method string) Field {
	return Field{Key: "method", Value: method}
}

// Path creates an HTTP path field
func Path(path string) Field {
	return Field{Key: "path", Value: path}
}

// RemoteIP creates a remote_ip field
func RemoteIP(ip string) Field {
	return Field{Key: "remote_ip", Value: ip}
}

// Provider creates a provider field
func Provider(provider string) Field {
	return Field{Key: "provider", Value: provider}
}

// MessageID creates a message_id field
func MessageID(id string) Field {
	return Field{Key: "message_id", Value: id}
}

// Operation creates an operation field
func Operation(op string) Field {
	return Field{Key: "operation", Value: op}
}

// Count creates a count field
func Count(count int) Field {
	return Field{Key: "count", Value: count}
}
