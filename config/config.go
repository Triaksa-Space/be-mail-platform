package config

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"
	"github.com/spf13/viper"
)

var DB *sqlx.DB

func InitDB() {
	// Replace with your MySQL DSN
	dsn := viper.GetString("DATABASE_URL") // Example: "user:password@tcp(localhost:3306)/simple_api"
	var err error
	DB, err = sqlx.Connect("mysql", dsn)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	log.Println("Connected to the database")

	// More aggressive connection pool settings to handle high load
	DB.SetMaxOpenConns(100)                // ~33% of RDS capacity
	DB.SetMaxIdleConns(20)                 // idle buffer for spikes
	DB.SetConnMaxIdleTime(1 * time.Minute) // Shorter idle time
	DB.SetConnMaxLifetime(3 * time.Minute) // Even shorter lifetime to prevent stale connections

	// Test the connection with a timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := DB.PingContext(ctx); err != nil {
		log.Fatalf("Failed to ping database: %v", err)
	}

	log.Println("Database connection pool configured with improved settings")
}

// GetDBWithTimeout returns a database connection with context timeout
func GetDBWithTimeout(timeout time.Duration) (*sqlx.DB, context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	return DB, ctx, cancel
}

// ExecuteWithTimeout executes a query with timeout context and explicit connection management
func ExecuteWithTimeout(query string, timeout time.Duration, args ...interface{}) (sql.Result, error) {
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Get explicit connection from pool
	conn, err := DB.Connx(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get database connection: %v", err)
	}
	defer func() {
		if closeErr := conn.Close(); closeErr != nil {
			log.Printf("Warning: failed to close database connection: %v", closeErr)
		}
	}()

	result, err := conn.ExecContext(ctx, query, args...)
	duration := time.Since(start)

	// Log slow queries (> 1 second)
	if duration > time.Second {
		log.Printf("SLOW QUERY DETECTED - Duration: %v, Query: %s, Args: %v", duration, query, args)
	}

	if err != nil {
		log.Printf("QUERY ERROR - Duration: %v, Error: %v, Query: %s, Args: %v", duration, err, query, args)
	}

	return result, err
}

// SelectWithTimeout executes a select query with timeout context and explicit connection management
func SelectWithTimeout(dest interface{}, query string, timeout time.Duration, args ...interface{}) error {
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Get explicit connection from pool
	conn, err := DB.Connx(ctx)
	if err != nil {
		return fmt.Errorf("failed to get database connection: %v", err)
	}
	defer func() {
		if closeErr := conn.Close(); closeErr != nil {
			log.Printf("Warning: failed to close database connection: %v", closeErr)
		}
	}()

	err = conn.SelectContext(ctx, dest, query, args...)
	duration := time.Since(start)

	// Log slow queries (> 1 second)
	if duration > time.Second {
		log.Printf("SLOW SELECT DETECTED - Duration: %v, Query: %s, Args: %v", duration, query, args)
	}

	if err != nil {
		log.Printf("SELECT ERROR - Duration: %v, Error: %v, Query: %s, Args: %v", duration, err, query, args)
	}

	return err
}

// GetWithTimeout executes a get query with timeout context and explicit connection management
func GetWithTimeout(dest interface{}, query string, timeout time.Duration, args ...interface{}) error {
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Get explicit connection from pool
	conn, err := DB.Connx(ctx)
	if err != nil {
		return fmt.Errorf("failed to get database connection: %v", err)
	}
	defer func() {
		if closeErr := conn.Close(); closeErr != nil {
			log.Printf("Warning: failed to close database connection: %v", closeErr)
		}
	}()

	err = conn.GetContext(ctx, dest, query, args...)
	duration := time.Since(start)

	// Log slow queries (> 500ms since Get should be very fast)
	if duration > 500*time.Millisecond {
		log.Printf("SLOW GET DETECTED - Duration: %v, Query: %s, Args: %v", duration, query, args)
	}

	if err != nil {
		log.Printf("GET ERROR - Duration: %v, Error: %v, Query: %s, Args: %v", duration, err, query, args)
	}

	return err
}

// BeginTxWithTimeout starts a transaction with timeout context
func BeginTxWithTimeout(timeout time.Duration) (*sqlx.Tx, context.Context, context.CancelFunc, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	tx, err := DB.BeginTxx(ctx, nil)
	if err != nil {
		cancel()
		return nil, nil, nil, err
	}
	return tx, ctx, cancel, nil
}

// DatabaseHealthCheck checks the database connection health and returns pool stats
func DatabaseHealthCheck() (map[string]interface{}, error) {

	// Get database stats
	stats := DB.Stats()

	healthInfo := map[string]interface{}{
		"status":               "healthy",
		"max_open_conns":       stats.MaxOpenConnections,
		"open_connections":     stats.OpenConnections,
		"in_use":               stats.InUse,
		"idle":                 stats.Idle,
		"wait_count":           stats.WaitCount,
		"wait_duration":        stats.WaitDuration.String(),
		"max_idle_closed":      stats.MaxIdleClosed,
		"max_idle_time_closed": stats.MaxIdleTimeClosed,
		"max_lifetime_closed":  stats.MaxLifetimeClosed,
	}

	// Check for potential issues
	warnings := []string{}

	if stats.WaitCount > 0 {
		warnings = append(warnings, "Connections are waiting - consider increasing pool size")
	}

	if float64(stats.InUse)/float64(stats.MaxOpenConnections) > 0.8 {
		warnings = append(warnings, "High connection usage - approaching pool limit")
	}

	if len(warnings) > 0 {
		healthInfo["warnings"] = warnings
	}

	return healthInfo, nil
}

// CloseDB closes the database connection gracefully
func CloseDB() error {
	if DB != nil {
		log.Println("Closing database connections...")
		return DB.Close()
	}
	return nil
}

func InitConfig() {
	viper.SetConfigName(".env") // name of config file (without extension)
	viper.SetConfigType("env")  // set the config type to "env"
	viper.AddConfigPath(".")    // optionally look for config in the working directory
	viper.AutomaticEnv()        // read in environment variables that match

	if err := viper.ReadInConfig(); err != nil {
		log.Fatalf("Error reading config file, %s", err)
	}
}