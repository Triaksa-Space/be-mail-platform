package utils

import (
	"log"

	"os"

	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
)

var DB *sqlx.DB

func InitDB() {
	dsn := os.Getenv("DATABASE_URL") // Example: postgres://user:password@localhost/dbname?sslmode=disable
	var err error
	DB, err = sqlx.Connect("postgres", dsn)
	if err != nil {
		log.Fatalf("Failed to connect to the database: %v", err)
	}

	log.Println("Database connection established")
}
