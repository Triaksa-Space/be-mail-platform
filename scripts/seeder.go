package main

import (
	"fmt"
	"log"
	"time"

	"github.com/Triaksa-Space/be-mail-platform/config"
	domain "github.com/Triaksa-Space/be-mail-platform/domain/domain_email"
	"github.com/Triaksa-Space/be-mail-platform/domain/email"
	"github.com/Triaksa-Space/be-mail-platform/domain/user"
	"github.com/Triaksa-Space/be-mail-platform/utils"
)

func main() {
	config.InitConfig()
	config.InitDB()

	// Seed Domain
	domains := generateDomains()

	for _, domain := range domains {
		// Check if domain exists
		var exists bool
		err := config.DB.Get(&exists, "SELECT EXISTS(SELECT 1 FROM domains WHERE domain = ?)", domain.Domain)
		if err != nil {
			log.Fatalf("Failed to check existing domain %s: %v", domain.Domain, err)
		}

		if exists {
			log.Printf("Skipping existing domain: %s", domain.Domain)
			continue
		}

		_, err = config.DB.Exec(
			"INSERT INTO domains (domain, created_at, updated_at) VALUES (?, NOW(), NOW())",
			domain.Domain,
		)
		if err != nil {
			log.Fatalf("Failed to seed domain %s: %v", domain.Domain, err)
		}
		log.Printf("Seeded domain: %s", domain.Domain)
	}

	log.Println("Domain seeding completed!")

	// Seed users
	users := generateUsers(5)

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
	emails := generateEmails(5, 10)

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
			"INSERT INTO emails (user_id, email_type, sender_email, sender_name, subject, body, timestamp, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, NOW(), NOW())",
			email.UserID, email.EmailType, email.SenderEmail, email.SenderName, email.Subject, email.Body, email.Timestamp,
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

func generateDomains() []domain.DomainEmail {
	domains := []domain.DomainEmail{
		{Domain: "mailria.com"},
		// {Domain: "gmail.com"},
		// {Domain: "yahoo.com"},
		// {Domain: "outlook.com"},
		// {Domain: "hotmail.com"},
		// {Domain: "aol.com"},
		// {Domain: "protonmail.com"},
		// {Domain: "icloud.com"},
		// {Domain: "zoho.com"},
		// {Domain: "yandex.com"},
	}
	return domains
}

func generateUsers(count int) []user.User {
	users := make([]user.User, count)
	timeIntervals := []time.Duration{
		0,
		-1 * time.Hour,
		-2 * time.Hour,
		-24 * time.Hour,
		-48 * time.Hour,
		-30 * 24 * time.Hour,
		-100 * 24 * time.Hour,
		-200 * 24 * time.Hour,
		-1000 * 24 * time.Hour,
	}

	for i := 0; i < count; i++ {
		timeIndex := i % len(timeIntervals)
		t := time.Now().Add(timeIntervals[timeIndex])
		users[i] = user.User{
			Email:     fmt.Sprintf("person%d@mailria.com", i+1),
			Password:  fmt.Sprintf("password%d", i+1),
			RoleID:    1,
			LastLogin: &t,
			CreatedAt: parseDate("10 Sep 2024"),
		}
	}
	return users
}

func generateEmails(userCount int, emailsPerUser int) []email.Email {
	// Email templates
	templates := []struct {
		SenderEmail string
		SenderName  string
		Subject     string
		Body        string
	}{
		{"google@gmail.com", "Google Gemini", "Welcome to Gemini", "Learn more about what you can do with Gemini"},
		{"google@gmail.com", "Google Play", "You Google Play Order Receipt", "Your order details..."},
		{"support@netflix.com", "Netflix", "Welcome to Netflix", "Start watching your favorite shows..."},
		{"support@digitalocean.com", "DigitalOcean", "Your Invoice", "Your invoice is now available..."},
		{"no-reply@github.com", "GitHub", "Security Alert", "We noticed a new sign-in to your account..."},
	}

	// Time intervals for realistic distribution
	timeIntervals := []time.Duration{
		0,
		-2 * time.Minute,
		-1 * time.Hour,
		-24 * time.Hour,
		-48 * time.Hour,
		-7 * 24 * time.Hour,
		-30 * 24 * time.Hour,
	}

	totalEmails := userCount * emailsPerUser
	emails := make([]email.Email, totalEmails)
	emailIndex := 0

	for userID := 1; userID <= userCount; userID++ {
		for i := 0; i < emailsPerUser; i++ {
			template := templates[i%len(templates)]
			timeOffset := timeIntervals[i%len(timeIntervals)]

			emails[emailIndex] = email.Email{
				UserID:      int64(userID),
				EmailType:   "inbox",
				SenderEmail: template.SenderEmail,
				SenderName:  template.SenderName,
				Subject:     fmt.Sprintf("%s #%d", template.Subject, i+1),
				Body:        template.Body,
				Timestamp:   time.Now().Add(timeOffset),
			}
			emailIndex++
		}
	}

	return emails
}
