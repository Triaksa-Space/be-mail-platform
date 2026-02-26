package logger

import (
	"context"
	"io"
	"os"
	"time"

	"github.com/rs/zerolog"
)

// Level represents log levels
type Level string

const (
	LevelDebug Level = "debug"
	LevelInfo  Level = "info"
	LevelWarn  Level = "warn"
	LevelError Level = "error"
	LevelFatal Level = "fatal"
)

// Logger is the main logging interface
type Logger interface {
	Debug(msg string, fields ...Field)
	Info(msg string, fields ...Field)
	Warn(msg string, fields ...Field)
	Error(msg string, err error, fields ...Field)
	Fatal(msg string, err error, fields ...Field)

	WithContext(ctx context.Context) Logger
	WithFields(fields ...Field) Logger
	WithRequestID(requestID string) Logger
	WithUserID(userID int64) Logger
	WithComponent(component string) Logger
}

// Field represents a structured log field
type Field struct {
	Key   string
	Value interface{}
}

// ZerologLogger implements Logger using zerolog
type ZerologLogger struct {
	logger zerolog.Logger
}

// Config holds logger configuration
type Config struct {
	Level       Level
	Environment string // "development" or "production"
	ServiceName string
	Version     string
	Output      io.Writer
}

var globalLogger *ZerologLogger

// Init initializes the global logger
func Init(cfg Config) {
	var output io.Writer = os.Stdout

	if cfg.Output != nil {
		output = cfg.Output
	}

	// Set service name default
	if cfg.ServiceName == "" {
		cfg.ServiceName = "mail-platform"
	}

	// Production: JSON format for log aggregation
	// Development: Pretty console output
	if cfg.Environment == "production" {
		zerolog.TimeFieldFormat = time.RFC3339Nano
		logger := zerolog.New(output).
			With().
			Timestamp().
			Str("service", cfg.ServiceName).
			Str("version", cfg.Version).
			Logger()

		globalLogger = &ZerologLogger{logger: logger}
	} else {
		output = zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: "15:04:05"}
		logger := zerolog.New(output).
			With().
			Timestamp().
			Logger()

		globalLogger = &ZerologLogger{logger: logger}
	}

	// Set log level
	switch cfg.Level {
	case LevelDebug:
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	case LevelInfo:
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	case LevelWarn:
		zerolog.SetGlobalLevel(zerolog.WarnLevel)
	case LevelError:
		zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	default:
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}
}

// Get returns the global logger instance
func Get() Logger {
	if globalLogger == nil {
		Init(Config{
			Level:       LevelInfo,
			Environment: "development",
			ServiceName: "mail-platform",
		})
	}
	return globalLogger
}

// Debug logs a debug message
func (l *ZerologLogger) Debug(msg string, fields ...Field) {
	event := l.logger.Debug()
	for _, f := range fields {
		event = event.Interface(f.Key, f.Value)
	}
	event.Msg(msg)
}

// Info logs an info message
func (l *ZerologLogger) Info(msg string, fields ...Field) {
	event := l.logger.Info()
	for _, f := range fields {
		event = event.Interface(f.Key, f.Value)
	}
	event.Msg(msg)
}

// Warn logs a warning message
func (l *ZerologLogger) Warn(msg string, fields ...Field) {
	event := l.logger.Warn()
	for _, f := range fields {
		event = event.Interface(f.Key, f.Value)
	}
	event.Msg(msg)
}

// Error logs an error message
func (l *ZerologLogger) Error(msg string, err error, fields ...Field) {
	event := l.logger.Error()
	if err != nil {
		event = event.Err(err)
	}
	for _, f := range fields {
		event = event.Interface(f.Key, f.Value)
	}
	event.Msg(msg)
}

// Fatal logs a fatal message and exits
func (l *ZerologLogger) Fatal(msg string, err error, fields ...Field) {
	event := l.logger.Fatal()
	if err != nil {
		event = event.Err(err)
	}
	for _, f := range fields {
		event = event.Interface(f.Key, f.Value)
	}
	event.Msg(msg)
}

// WithContext creates a new logger with context values
func (l *ZerologLogger) WithContext(ctx context.Context) Logger {
	newLogger := l.logger.With().Logger()

	if requestID, ok := ctx.Value(ContextKeyRequestID).(string); ok {
		newLogger = newLogger.With().Str("request_id", requestID).Logger()
	}
	if userID, ok := ctx.Value(ContextKeyUserID).(int64); ok {
		newLogger = newLogger.With().Int64("user_id", userID).Logger()
	}

	return &ZerologLogger{logger: newLogger}
}

// WithFields creates a new logger with additional fields
func (l *ZerologLogger) WithFields(fields ...Field) Logger {
	ctx := l.logger.With()
	for _, f := range fields {
		ctx = ctx.Interface(f.Key, f.Value)
	}
	return &ZerologLogger{logger: ctx.Logger()}
}

// WithRequestID creates a new logger with request ID
func (l *ZerologLogger) WithRequestID(requestID string) Logger {
	return &ZerologLogger{
		logger: l.logger.With().Str("request_id", requestID).Logger(),
	}
}

// WithUserID creates a new logger with user ID
func (l *ZerologLogger) WithUserID(userID int64) Logger {
	return &ZerologLogger{
		logger: l.logger.With().Int64("user_id", userID).Logger(),
	}
}

// WithComponent creates a new logger with component name
func (l *ZerologLogger) WithComponent(component string) Logger {
	return &ZerologLogger{
		logger: l.logger.With().Str("component", component).Logger(),
	}
}
