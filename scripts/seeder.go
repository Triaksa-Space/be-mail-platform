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
		{UserID: 1, EmailType: "inbox", SenderEmail: "google@gmail.com", SenderName: "Google Gemini", Subject: "Welcome to Gemini", Body: "Hi Bamas, If you're a Java enthusiast, you probably already know today's guest author: Javin Paul. Javin is a prolific writer on everything Java, but he also writes regularly about the SWE interview process. Today he breaks down 7 essential System Design concepts you can't afford to miss in your interview prep. Stay tuned for tried and true tips from his own experience navigating interview loops at Facebook, Google, and Amazon. Over to Javin!Hello, Javin here. If you don’t know me, I am a Java developer and share my thoughts over on javarevisited.blogspot.com. I have been writing since 2010 and have written multiple articles on Java, Programming, and Coding interviews.  I’m also the creator of the Javarevisited newsletter, where I share interview tips, questions, in-depth articles and resources to 32,001+ engineers from Infosys, Google, Meta, Amazon, investment banks, and startups. If you are preparing for Java developer interviews, you can also check out my books on Java interviews on Gumroad.  I'm thrilled to partner with Educative this week to share 7 essential System Design concepts for tech interviews. Let’s start.In the Software Engineering world, if you are applying for a Senior Engineer / Lead / Architect / or a more senior role, System Design is the most sought-after skill. That makes the System Design Interview one of the most important rounds in the whole process.  If you mess this up, nothing else would matter. If you get it right though, you’re looking at a raise of at least tens of thousands of dollars annually.  If you have prepared for Software Engineer Interviews in the past, then you may know how difficult it is to prepare for System Design interviews, given their open ended nature and vastness. But at the same time you cannot ignore it.  So how do you ace your System Design round? Well, here’s what I did while preparing for my interviews with Facebook, Google, and Amazon, and it worked out rather well. I did end up creating a checklist for myself which got me through most of my rounds. So if you follow a similar path you should be able to come up with something that works for you as well. Before we get into the details though, we need to answer an important question: What do interviewers really expect from candidates in System Design Interviews?", Timestamp: time.Now()},
		{UserID: 2, EmailType: "inbox", SenderEmail: "google@gmail.com", SenderName: "Google Play", Subject: "You Google Play Order Receipt from Nov 11, 20...", Body: "Learn more about what you can do with Gemini", Timestamp: time.Now().Add(-2 * time.Minute)},
		{UserID: 3, EmailType: "inbox", SenderEmail: "google@gmail.com", SenderName: "Netflix", Subject: "Selamat datang di Netflix, johny", Body: "Kamu siap untuk menikmati acara TV & film terbaru kami...", Timestamp: time.Now().Add(-1 * time.Hour)},
		{UserID: 4, EmailType: "inbox", SenderEmail: "google@gmail.com", SenderName: "DigitalOcean Support", Subject: "[DigitalOcean] Your 2024-10 invoice for team: ...", Body: "Your 2024-10 invoice is now available for team: GameMar...", Timestamp: time.Now().Add(-24 * time.Hour)},
		{UserID: 5, EmailType: "inbox", SenderEmail: "google@gmail.com", SenderName: "Google Play", Subject: "You Google Play Order Receipt from Nov 11, 20...", Body: "Learn more about what you can do with Gemini", Timestamp: parseDate("10 Sep 2024")},
		{UserID: 6, EmailType: "inbox", SenderEmail: "google@gmail.com", SenderName: "Google Gemini", Subject: "Welcome to Gemini", Body: "Learn more about what you can do with Gemini", Timestamp: time.Now()},
		{UserID: 7, EmailType: "inbox", SenderEmail: "google@gmail.com", SenderName: "Google Play", Subject: "You Google Play Order Receipt from Nov 11, 20...", Body: "Learn more about what you can do with Gemini", Timestamp: time.Now().Add(-2 * time.Minute)},
		{UserID: 8, EmailType: "inbox", SenderEmail: "google@gmail.com", SenderName: "Netflix", Subject: "Selamat datang di Netflix, johny", Body: "Kamu siap untuk menikmati acara TV & film terbaru kami...", Timestamp: time.Now().Add(-1 * time.Hour)},
		{UserID: 9, EmailType: "inbox", SenderEmail: "google@gmail.com", SenderName: "DigitalOcean Support", Subject: "[DigitalOcean] Your 2024-10 invoice for team: ...", Body: "Your 2024-10 invoice is now available for team: GameMar...", Timestamp: time.Now().Add(-24 * time.Hour)},
		{UserID: 10, EmailType: "inbox", SenderEmail: "google@gmail.com", SenderName: "Google Play", Subject: "You Google Play Order Receipt from Nov 11, 20...", Body: "Learn more about what you can do with Gemini", Timestamp: parseDate("10 Sep 2024")},
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
