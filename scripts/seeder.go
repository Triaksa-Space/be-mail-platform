package main

import (
	"email-platform/config"
	"email-platform/domain/email"
	"email-platform/domain/user"
	"email-platform/utils"
	"log"
	"time"
)

func main() {
	config.InitConfig()
	config.InitDB()

	// Seed users
	users := []user.User{
		{Email: "person1@mailria.com", Password: "password1", RoleID: 1, LastLogin: time.Now(), CreatedAt: parseDate("10 Sep 2024")},
		{Email: "person2@mailria.com", Password: "password2", RoleID: 1, LastLogin: time.Now().Add(-1 * time.Hour), CreatedAt: parseDate("10 Sep 2024")},
		{Email: "person3@mailria.com", Password: "password3", RoleID: 1, LastLogin: time.Now().Add(-2 * time.Hour), CreatedAt: parseDate("10 Sep 2024")},
		{Email: "person4@mailria.com", Password: "password4", RoleID: 1, LastLogin: time.Now().Add(-24 * time.Hour), CreatedAt: parseDate("10 Sep 2024")},
		{Email: "person5@mailria.com", Password: "password5", RoleID: 1, LastLogin: time.Now().Add(-48 * time.Hour), CreatedAt: parseDate("10 Sep 2024")},
		{Email: "person6@mailria.com", Password: "password6", RoleID: 1, LastLogin: time.Now().Add(-30 * 24 * time.Hour), CreatedAt: parseDate("10 Sep 2024")},
		{Email: "person7@mailria.com", Password: "password7", RoleID: 1, LastLogin: time.Now().Add(-100 * 24 * time.Hour), CreatedAt: parseDate("10 Sep 2024")},
		{Email: "person8@mailria.com", Password: "password8", RoleID: 1, LastLogin: time.Now().Add(-200 * 24 * time.Hour), CreatedAt: parseDate("10 Sep 2024")},
		{Email: "person9@mailria.com", Password: "password9", RoleID: 1, LastLogin: time.Now().Add(-1000 * 24 * time.Hour), CreatedAt: parseDate("10 Sep 2024")},
		{Email: "person10@mailria.com", Password: "password10", RoleID: 1, LastLogin: time.Now().Add(-1000 * 24 * time.Hour), CreatedAt: parseDate("10 Sep 2024")},
	}

	for _, user := range users {
		// Check if user exists
		var exists bool
		err := config.DB.Get(&exists, "SELECT EXISTS(SELECT 1 FROM users WHERE email = ?)", user.Email)
		if err != nil {
			log.Fatalf("Failed to check existing user %s: %v", user.Email, err)
		}

		if exists {
			log.Printf("Skipping existing user: %s", user.Email)
			continue
		}

		hashedPassword, err := utils.HashPassword(user.Password)
		if err != nil {
			log.Fatalf("Failed to hash password for user %s: %v", user.Email, err)
		}

		_, err = config.DB.Exec(
			"INSERT INTO users (email, password, role_id, last_login, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
			user.Email, hashedPassword, user.RoleID, user.LastLogin, user.CreatedAt, user.CreatedAt,
		)
		if err != nil {
			log.Fatalf("Failed to seed user %s: %v", user.Email, err)
		}
		log.Printf("Seeded user: %s", user.Email)
	}

	// Seed emails
	emails := []email.Email{
		{UserID: 1, EmailType: "inbox", Sender: "Google Gemini", Subject: "Welcome to Gemini", Body: "Learn more about what you can do with Gemini", Timestamp: time.Now()},
		{UserID: 2, EmailType: "inbox", Sender: "Google Play", Subject: "You Google Play Order Receipt from Nov 11, 20...", Body: "Learn more about what you can do with Gemini", Timestamp: time.Now().Add(-2 * time.Minute)},
		{UserID: 3, EmailType: "inbox", Sender: "Netflix", Subject: "Selamat datang di Netflix, johny", Body: "Kamu siap untuk menikmati acara TV & film terbaru kami...", Timestamp: time.Now().Add(-1 * time.Hour)},
		{UserID: 4, EmailType: "inbox", Sender: "DigitalOcean Support", Subject: "[DigitalOcean] Your 2024-10 invoice for team: ...", Body: "Your 2024-10 invoice is now available for team: GameMar...", Timestamp: time.Now().Add(-24 * time.Hour)},
		{UserID: 5, EmailType: "inbox", Sender: "Google Play", Subject: "You Google Play Order Receipt from Nov 11, 20...", Body: "Learn more about what you can do with Gemini", Timestamp: parseDate("10 Sep 2024")},
		{UserID: 6, EmailType: "inbox", Sender: "Google Gemini", Subject: "Welcome to Gemini", Body: "Learn more about what you can do with Gemini", Timestamp: time.Now()},
		{UserID: 7, EmailType: "inbox", Sender: "Google Play", Subject: "You Google Play Order Receipt from Nov 11, 20...", Body: "Learn more about what you can do with Gemini", Timestamp: time.Now().Add(-2 * time.Minute)},
		{UserID: 8, EmailType: "inbox", Sender: "Netflix", Subject: "Selamat datang di Netflix, johny", Body: "Kamu siap untuk menikmati acara TV & film terbaru kami...", Timestamp: time.Now().Add(-1 * time.Hour)},
		{UserID: 9, EmailType: "inbox", Sender: "DigitalOcean Support", Subject: "[DigitalOcean] Your 2024-10 invoice for team: ...", Body: "Your 2024-10 invoice is now available for team: GameMar...", Timestamp: time.Now().Add(-24 * time.Hour)},
		{UserID: 10, EmailType: "inbox", Sender: "Google Play", Subject: "You Google Play Order Receipt from Nov 11, 20...", Body: "Learn more about what you can do with Gemini", Timestamp: parseDate("10 Sep 2024")},
	}

	for _, email := range emails {
		// Check if email exists
		var exists bool
		err := config.DB.Get(&exists, `
            SELECT EXISTS(
                SELECT 1 FROM emails 
                WHERE user_id = ? 
                AND subject = ? 
                AND timestamp = ?
            )`, email.UserID, email.Subject, email.Timestamp)
		if err != nil {
			log.Fatalf("Failed to check existing email for user %d: %v", email.UserID, err)
		}

		if exists {
			log.Printf("Skipping existing email for user ID %d: %s", email.UserID, email.Subject)
			continue
		}

		_, err = config.DB.Exec(
			"INSERT INTO emails (user_id, email_type, sender, subject, body, timestamp, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, NOW(), NOW())",
			email.UserID, email.EmailType, email.Sender, email.Subject, email.Body, email.Timestamp,
		)
		if err != nil {
			log.Fatalf("Failed to seed email for user %d: %v", email.UserID, err)
		}
		log.Printf("Seeded email for user ID: %d", email.UserID)
	}

	log.Println("Seeding completed!")
}

func parseDate(dateStr string) time.Time {
	layout := "02 Jan 2006"
	t, err := time.Parse(layout, dateStr)
	if err != nil {
		log.Fatalf("Failed to parse date %s: %v", dateStr, err)
	}
	return t
}
