package config

import (
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

	// Configure connection pool settings
	DB.SetMaxOpenConns(10)           // Limit maximum open connections
	DB.SetMaxIdleConns(5)            // Set the maximum number of idle connections
	DB.SetConnMaxLifetime(time.Hour) // Set max connection lifetime
	log.Println("Database connection pool configured")
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
