package main

import (
	"fmt"
	"log"
	"regexp"
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

	// Seed users (3 role-based users + 5 additional regular users)
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

	// Seed emails (5 additional users + 3 role-based users = 8 users total)
	emails := generateEmails(5, 0) // userCount=5 means 5 additional regular users

	for _, email := range emails {
		// Check if email exists
		var exists bool
		err := config.DB.Get(&exists, `
            SELECT EXISTS(
                SELECT 1 FROM emails
                WHERE user_id = ?
                AND subject = ?
                AND email_type = ?
                AND timestamp = ?
            )`, email.UserID, email.Subject, email.EmailType, email.Timestamp)
		if err != nil {
			log.Fatalf("Failed to check existing email for user %d: %v", email.UserID, err)
		}

		if exists {
			log.Printf("Skipping existing email for user ID %d: %s (%s)", email.UserID, email.Subject, email.EmailType)
			continue
		}

		// Generate preview from body (strip HTML and limit to 100 chars)
		preview := generatePreview(email.Body)

		_, err = config.DB.Exec(
			"INSERT INTO emails (user_id, email_type, is_read, sender_email, sender_name, subject, preview, body, timestamp, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())",
			email.UserID, email.EmailType, email.IsRead, email.SenderEmail, email.SenderName, email.Subject, preview, email.Body, email.Timestamp,
		)
		if err != nil {
			log.Fatalf("Failed to seed email for user %d: %v", email.UserID, err)
		}
		log.Printf("Seeded %s email for user ID: %d - %s", email.EmailType, email.UserID, email.Subject)
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

func stripHTML(html string) string {
	re := regexp.MustCompile(`<[^>]*>`)
	return re.ReplaceAllString(html, "")
}

func generatePreview(body string) string {
	preview := stripHTML(body)
	if len(preview) > 100 {
		preview = preview[:100] + "..."
	}
	return preview
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
	// Create specific role-based users first
	roleUsers := []user.User{
		{
			Email:     "superadmin@mailria.com",
			Password:  "superadmin123",
			RoleID:    0, // SuperAdmin
			CreatedAt: parseDate("01 Jan 2024"),
		},
		{
			Email:     "admin@mailria.com",
			Password:  "admin123",
			RoleID:    2, // Admin
			CreatedAt: parseDate("15 Jan 2024"),
		},
		{
			Email:     "user@mailria.com",
			Password:  "user123",
			RoleID:    1, // Regular User
			CreatedAt: parseDate("01 Feb 2024"),
		},
	}

	// Set last login times for role users
	now := time.Now()
	t1 := now.Add(-30 * time.Minute)
	t2 := now.Add(-2 * time.Hour)
	t3 := now.Add(-24 * time.Hour)
	roleUsers[0].LastLogin = &t1
	roleUsers[1].LastLogin = &t2
	roleUsers[2].LastLogin = &t3

	// Generate additional regular users
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

	additionalUsers := make([]user.User, count)
	for i := 0; i < count; i++ {
		timeIndex := i % len(timeIntervals)
		t := time.Now().Add(timeIntervals[timeIndex])
		additionalUsers[i] = user.User{
			Email:     fmt.Sprintf("person%d@mailria.com", i+1),
			Password:  fmt.Sprintf("password%d", i+1),
			RoleID:    1, // Regular User
			LastLogin: &t,
			CreatedAt: parseDate("10 Sep 2024"),
		}
	}

	// Combine role users with additional users
	allUsers := append(roleUsers, additionalUsers...)
	return allUsers
}

func generateEmails(userCount int, emailsPerUser int) []email.Email {
	// Inbox email templates (received emails)
	inboxTemplates := []struct {
		SenderEmail string
		SenderName  string
		Subject     string
		Body        string
	}{
		{"google@gmail.com", "Google Gemini", "Welcome to Gemini", "<p>Learn more about what you can do with Gemini. Explore AI-powered assistance for your daily tasks.</p>"},
		{"google@gmail.com", "Google Play", "Your Google Play Order Receipt", "<p>Thank you for your purchase. Your order details are attached below.</p>"},
		{"support@netflix.com", "Netflix", "Welcome to Netflix", "<p>Start watching your favorite shows and movies. Your entertainment journey begins now!</p>"},
		{"support@digitalocean.com", "DigitalOcean", "Your Invoice is Ready", "<p>Your invoice for this month is now available. Please review the details.</p>"},
		{"no-reply@github.com", "GitHub", "Security Alert", "<p>We noticed a new sign-in to your account from a new device. If this was you, no action is needed.</p>"},
		{"noreply@medium.com", "Medium Daily Digest", "Your Daily Reading List", "<p>Here are today's top stories curated just for you based on your interests.</p>"},
		{"hello@slack.com", "Slack", "New Message in #general", "<p>You have new messages waiting for you in your Slack workspace.</p>"},
		{"no-reply@linkedin.com", "LinkedIn", "You have 5 new connection requests", "<p>Expand your professional network by accepting these connection requests.</p>"},
		{"support@spotify.com", "Spotify", "Your Weekly Discovery", "<p>Check out your personalized weekly playlist with new music recommendations.</p>"},
		{"noreply@twitter.com", "X (Twitter)", "New follower alert", "<p>Someone new is following you! Check out their profile.</p>"},
		{"billing@aws.amazon.com", "Amazon Web Services", "AWS Billing Alert", "<p>Your estimated charges for this billing period have exceeded the threshold.</p>"},
		{"no-reply@notion.so", "Notion", "Weekly workspace summary", "<p>Here's a summary of your team's activity in Notion this week.</p>"},
		{"support@stripe.com", "Stripe", "Payment Received", "<p>You've received a new payment of $150.00 from a customer.</p>"},
		{"hello@figma.com", "Figma", "Someone commented on your design", "<p>A team member left feedback on your latest design file.</p>"},
		{"no-reply@vercel.com", "Vercel", "Deployment Successful", "<p>Your latest deployment to production was successful. Preview it now.</p>"},
		{"team@dropbox.com", "Dropbox", "File shared with you", "<p>Someone has shared a file with you. Click to view and download.</p>"},
		{"noreply@zoom.us", "Zoom", "Meeting Recording Available", "<p>The recording for your recent meeting is now available to view.</p>"},
		{"hello@calendly.com", "Calendly", "New Meeting Scheduled", "<p>A new meeting has been booked on your calendar for tomorrow at 2 PM.</p>"},
		{"support@heroku.com", "Heroku", "Dyno Restart Alert", "<p>Your application dyno has been restarted due to a memory quota exceeded.</p>"},
		{"no-reply@atlassian.com", "Jira", "Issue Assigned to You", "<p>A new issue has been assigned to you: PROJ-1234 - Fix login bug.</p>"},
		{"security@google.com", "Google Security", "Suspicious Activity Detected", "<p>We detected unusual activity on your account. Please verify your recent actions.</p>"},
		{"newsletter@dev.to", "DEV Community", "This Week's Top Posts", "<p>Catch up on the most popular articles from the developer community this week.</p>"},
		{"no-reply@cloudflare.com", "Cloudflare", "SSL Certificate Renewed", "<p>Your SSL certificate has been automatically renewed for another year.</p>"},
		{"billing@openai.com", "OpenAI", "API Usage Report", "<p>Your monthly API usage report is ready. You've used 50,000 tokens this month.</p>"},
		{"hello@mailchimp.com", "Mailchimp", "Campaign Sent Successfully", "<p>Your email campaign has been sent to 1,500 subscribers.</p>"},
	}

	// Sent email templates (outgoing emails)
	sentTemplates := []struct {
		RecipientEmail string
		RecipientName  string
		Subject        string
		Body           string
		MessageID      int
		Attachments    string
	}{
		{"john.doe@example.com", "John Doe", "Meeting Follow-up", "<p>Hi John, Thanks for meeting with me today. Here are the action items we discussed.</p>", 0, ""},
		{"hr@company.com", "HR Department", "Leave Request", "<p>Dear HR, I would like to request leave from March 15-20, 2025. Please let me know if approved.</p>", 0, ""},
		{"support@vendor.com", "Vendor Support", "Invoice Query", "<p>Hello, I have a question regarding invoice #12345. Could you please clarify the charges?</p>", 0, ""},
		{"team@project.com", "Project Team", "Weekly Status Update", "<p>Hi Team, Here's our weekly status update. All tasks are on track for the deadline.</p>", 0, ""},
		{"client@business.com", "Client Name", "Proposal Submission", "<p>Dear Client, Please find attached our proposal for the upcoming project. Looking forward to your feedback.</p>", 0, ""},
		{"partner@company.org", "Business Partner", "Partnership Discussion", "<p>Hello, I wanted to follow up on our partnership discussion. Let's schedule a call this week.</p>", 0, ""},
		{"recruiter@tech.com", "Tech Recruiter", "Application Follow-up", "<p>Hi, I wanted to follow up on my application for the Senior Developer position.</p>", 0, ""},
		{"manager@work.com", "Manager", "Project Completion Report", "<p>Dear Manager, I'm pleased to report that the project has been completed successfully.</p>", 0, ""},
		{"finance@company.com", "Finance Team", "Expense Report Submission", "<p>Hi Finance, Please find my expense report for Q1 2025 attached.</p>", 0, ""},
		{"vendor@supplies.com", "Supplies Vendor", "Order Confirmation Request", "<p>Hello, Could you please confirm our order #98765 has been processed?</p>", 0, ""},
		{"legal@firm.com", "Legal Team", "Contract Review Request", "<p>Dear Legal, Please review the attached contract and provide your feedback.</p>", 0, ""},
		{"it@company.com", "IT Support", "VPN Access Request", "<p>Hi IT, I need VPN access for remote work. Please assist with the setup.</p>", 0, ""},
		{"marketing@agency.com", "Marketing Agency", "Campaign Assets", "<p>Hello, Here are the campaign assets we discussed. Please review and confirm.</p>", 0, ""},
		{"sales@partner.com", "Sales Team", "Lead Referral", "<p>Hi Sales, I'm referring a potential customer who expressed interest in our services.</p>", 0, ""},
		{"ceo@startup.com", "CEO", "Quarterly Report", "<p>Dear CEO, Please find attached the quarterly performance report for your review.</p>", 0, ""},
		{"developer@contractor.com", "Contractor", "Code Review Feedback", "<p>Hi, I've reviewed your code submission. Here are my comments and suggestions.</p>", 0, ""},
		{"design@agency.com", "Design Agency", "Logo Revision Request", "<p>Hello, Could you please make the following revisions to the logo design?</p>", 0, ""},
		{"investor@fund.com", "Investor", "Monthly Update", "<p>Dear Investor, Here's our monthly progress update including key metrics.</p>", 0, ""},
		{"qa@company.com", "QA Team", "Bug Report", "<p>Hi QA, I found a bug in the checkout process. Steps to reproduce are attached.</p>", 0, ""},
		{"devops@team.com", "DevOps Team", "Deployment Request", "<p>Hi DevOps, Please deploy the latest release to production at 6 PM today.</p>", 0, ""},
		{"data@analytics.com", "Data Team", "Report Request", "<p>Hello, Could you generate a custom report for user engagement metrics?</p>", 0, ""},
		{"security@company.com", "Security Team", "Access Audit Request", "<p>Hi Security, Please conduct an access audit for the production servers.</p>", 0, ""},
		{"cto@company.com", "CTO", "Technical Proposal", "<p>Dear CTO, I'd like to propose a new architecture for our microservices.</p>", 0, ""},
		{"intern@company.com", "Intern", "Onboarding Materials", "<p>Hi, Welcome to the team! Here are your onboarding materials and first tasks.</p>", 0, ""},
		{"mentor@industry.com", "Industry Mentor", "Mentorship Session Request", "<p>Hello, I would love to schedule our next mentorship session this week.</p>", 0, ""},
	}

	// Time intervals for realistic distribution
	timeIntervals := []time.Duration{
		0,
		-5 * time.Minute,
		-15 * time.Minute,
		-30 * time.Minute,
		-1 * time.Hour,
		-2 * time.Hour,
		-4 * time.Hour,
		-8 * time.Hour,
		-12 * time.Hour,
		-24 * time.Hour,
		-36 * time.Hour,
		-48 * time.Hour,
		-3 * 24 * time.Hour,
		-5 * 24 * time.Hour,
		-7 * 24 * time.Hour,
		-10 * 24 * time.Hour,
		-14 * 24 * time.Hour,
		-21 * 24 * time.Hour,
		-30 * 24 * time.Hour,
		-45 * 24 * time.Hour,
	}

	var emails []email.Email

	// Generate inbox and sent emails for each user
	// User IDs: 1=superadmin, 2=admin, 3=user, 4+=person1,person2...
	for userID := 1; userID <= userCount+3; userID++ {
		// Generate inbox emails (25 per user from different templates)
		for i := 0; i < 25; i++ {
			template := inboxTemplates[i%len(inboxTemplates)]
			timeOffset := timeIntervals[i%len(timeIntervals)]

			emails = append(emails, email.Email{
				UserID:      int64(userID),
				EmailType:   "inbox",
				SenderEmail: template.SenderEmail,
				SenderName:  template.SenderName,
				Subject:     fmt.Sprintf("%s", template.Subject),
				Body:        template.Body,
				IsRead:      i%3 == 0, // Every 3rd email is read
				Timestamp:   time.Now().Add(timeOffset - time.Duration(userID)*time.Hour),
				Attachments: "",
				MessageID:   "0",
			})
		}

		// Generate sent emails (25 per user from different templates)
		for i := 0; i < 25; i++ {
			template := sentTemplates[i%len(sentTemplates)]
			timeOffset := timeIntervals[i%len(timeIntervals)]

			emails = append(emails, email.Email{
				UserID:      int64(userID),
				EmailType:   "sent",
				SenderEmail: template.RecipientEmail, // For sent emails, this represents the recipient
				SenderName:  template.RecipientName,
				Subject:     fmt.Sprintf("%s", template.Subject),
				Body:        template.Body,
				IsRead:      true, // Sent emails are always "read"
				Timestamp:   time.Now().Add(timeOffset - time.Duration(userID)*time.Hour),
			})
		}
	}

	return emails
}
