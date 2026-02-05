package config

import (
	"context"
	"log"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"
	"github.com/spf13/viper"
)

var DB *sqlx.DB

func InitDB() {
	dsn := viper.GetString("DATABASE_URL")

	// Add connection parameters for better reliability
	if !strings.Contains(dsn, "?") {
		dsn += "?"
	} else if !strings.HasSuffix(dsn, "&") && !strings.HasSuffix(dsn, "?") {
		dsn += "&"
	}

	// Add recommended MySQL connection parameters
	if !strings.Contains(dsn, "parseTime") {
		dsn += "parseTime=true&"
	}
	if !strings.Contains(dsn, "loc=") {
		dsn += "loc=UTC&"
	}
	if !strings.Contains(dsn, "timeout=") {
		dsn += "timeout=10s&"
	}
	if !strings.Contains(dsn, "readTimeout=") {
		dsn += "readTimeout=30s&"
	}
	if !strings.Contains(dsn, "writeTimeout=") {
		dsn += "writeTimeout=30s"
	}

	// Clean up trailing ampersand
	dsn = strings.TrimSuffix(dsn, "&")

	var err error
	DB, err = sqlx.Connect("mysql", dsn)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	// Configure connection pool settings (tuned for production)
	// Adjust these values based on your expected load
	maxOpenConns := viper.GetInt("DB_MAX_OPEN_CONNS")
	if maxOpenConns == 0 {
		maxOpenConns = 25 // Default: increased from 10
	}

	maxIdleConns := viper.GetInt("DB_MAX_IDLE_CONNS")
	if maxIdleConns == 0 {
		maxIdleConns = 10 // Default: increased from 5
	}

	connMaxLifetime := viper.GetDuration("DB_CONN_MAX_LIFETIME")
	if connMaxLifetime == 0 {
		connMaxLifetime = 5 * time.Minute // Default: reduced from 1 hour
	}

	connMaxIdleTime := viper.GetDuration("DB_CONN_MAX_IDLE_TIME")
	if connMaxIdleTime == 0 {
		connMaxIdleTime = 1 * time.Minute // New: idle timeout
	}

	DB.SetMaxOpenConns(maxOpenConns)
	DB.SetMaxIdleConns(maxIdleConns)
	DB.SetConnMaxLifetime(connMaxLifetime)
	DB.SetConnMaxIdleTime(connMaxIdleTime)

	// Verify connection with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := DB.PingContext(ctx); err != nil {
		log.Fatalf("Database ping failed: %v", err)
	}

	log.Printf("Database connected (max_open=%d, max_idle=%d, max_lifetime=%s)",
		maxOpenConns, maxIdleConns, connMaxLifetime)
}

func InitConfig() {
	viper.SetConfigName(".env")
	viper.SetConfigType("env")
	viper.AddConfigPath(".")
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		log.Fatalf("Error reading config file: %v", err)
	}
}

// CloseDB closes the database connection gracefully
func CloseDB() error {
	if DB != nil {
		return DB.Close()
	}
	return nil
}
