package main

import (
	"email-platform/config"
	"log"
	"os"

	_ "github.com/lib/pq"
	"github.com/pressly/goose/v3"
)

func main() {
	// Initialize database connection
	config.InitDB()

	// Path to the migrations folder
	migrationsDir := "./db/migrations"

	// Extract the raw *sql.DB from *sqlx.DB
	db := config.DB.DB

	// Ensure the database connection is closed after the program exits
	defer db.Close()

	// Command-line arguments
	args := os.Args
	if len(args) < 2 {
		log.Fatal("Please specify a migration command (up, down, status, etc.)")
	}

	command := args[1]

	// Run Goose command
	if err := goose.Run(command, db, migrationsDir); err != nil {
		log.Fatalf("Failed to execute goose command: %v", err)
	}
}
