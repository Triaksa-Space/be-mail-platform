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
		{Email: "surya1@mailria.com", Password: "password1", RoleID: 1, LastLogin: time.Now(), CreatedAt: parseDate("10 Sep 2024")},
		{Email: "surya2@mailria.com", Password: "password2", RoleID: 1, LastLogin: time.Now().Add(-1 * time.Hour), CreatedAt: parseDate("10 Sep 2024")},
		{Email: "surya3@mailria.com", Password: "password3", RoleID: 1, LastLogin: time.Now().Add(-2 * time.Hour), CreatedAt: parseDate("10 Sep 2024")},
		{Email: "surya4@mailria.com", Password: "password4", RoleID: 1, LastLogin: time.Now().Add(-24 * time.Hour), CreatedAt: parseDate("10 Sep 2024")},
		{Email: "surya5@mailria.com", Password: "password5", RoleID: 1, LastLogin: time.Now().Add(-48 * time.Hour), CreatedAt: parseDate("10 Sep 2024")},
		{Email: "surya6@mailria.com", Password: "password6", RoleID: 1, LastLogin: time.Now().Add(-30 * 24 * time.Hour), CreatedAt: parseDate("10 Sep 2024")},
		{Email: "surya7@mailria.com", Password: "password7", RoleID: 1, LastLogin: time.Now().Add(-100 * 24 * time.Hour), CreatedAt: parseDate("10 Sep 2024")},
		{Email: "surya8@mailria.com", Password: "password8", RoleID: 1, LastLogin: time.Now().Add(-200 * 24 * time.Hour), CreatedAt: parseDate("10 Sep 2024")},
		{Email: "surya9@mailria.com", Password: "password9", RoleID: 1, LastLogin: time.Now().Add(-1000 * 24 * time.Hour), CreatedAt: parseDate("10 Sep 2024")},
		{Email: "surya10@mailria.com", Password: "password10", RoleID: 1, LastLogin: time.Now().Add(-1000 * 24 * time.Hour), CreatedAt: parseDate("10 Sep 2024")},
	}

	for _, user := range users {
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
		{UserID: 1, Sender: "Google Gemini", Subject: "Welcome to Gemini", Body: "Learn more about what you can do with Gemini", Timestamp: time.Now()},
		{UserID: 2, Sender: "Google Play", Subject: "You Google Play Order Receipt from Nov 11, 20...", Body: "Learn more about what you can do with Gemini", Timestamp: time.Now().Add(-2 * time.Minute)},
		{UserID: 3, Sender: "Netflix", Subject: "Selamat datang di Netflix, johny", Body: "Kamu siap untuk menikmati acara TV & film terbaru kami...", Timestamp: time.Now().Add(-1 * time.Hour)},
		{UserID: 4, Sender: "DigitalOcean Support", Subject: "[DigitalOcean] Your 2024-10 invoice for team: ...", Body: "Your 2024-10 invoice is now available for team: GameMar...", Timestamp: time.Now().Add(-24 * time.Hour)},
		{UserID: 5, Sender: "Google Play", Subject: "You Google Play Order Receipt from Nov 11, 20...", Body: "Learn more about what you can do with Gemini", Timestamp: parseDate("10 Sep 2024")},
		{UserID: 6, Sender: "Google Gemini", Subject: "Welcome to Gemini", Body: "Learn more about what you can do with Gemini", Timestamp: time.Now()},
		{UserID: 7, Sender: "Google Play", Subject: "You Google Play Order Receipt from Nov 11, 20...", Body: "Learn more about what you can do with Gemini", Timestamp: time.Now().Add(-2 * time.Minute)},
		{UserID: 8, Sender: "Netflix", Subject: "Selamat datang di Netflix, johny", Body: "Kamu siap untuk menikmati acara TV & film terbaru kami...", Timestamp: time.Now().Add(-1 * time.Hour)},
		{UserID: 9, Sender: "DigitalOcean Support", Subject: "[DigitalOcean] Your 2024-10 invoice for team: ...", Body: "Your 2024-10 invoice is now available for team: GameMar...", Timestamp: time.Now().Add(-24 * time.Hour)},
		{UserID: 10, Sender: "Google Play", Subject: "You Google Play Order Receipt from Nov 11, 20...", Body: "Learn more about what you can do with Gemini", Timestamp: parseDate("10 Sep 2024")},
	}

	for _, email := range emails {
		_, err := config.DB.Exec(
			"INSERT INTO emails (user_id, sender, subject, body, timestamp, created_at, updated_at) VALUES (?, ?, ?, ?, ?, NOW(), NOW())",
			email.UserID, email.Sender, email.Subject, email.Body, email.Timestamp,
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
