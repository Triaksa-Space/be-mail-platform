package main

import (
	"fmt"
	"os"
	"time"

	"github.com/Triaksa-Space/be-mail-platform/config"
	"github.com/Triaksa-Space/be-mail-platform/domain/email"
	"github.com/Triaksa-Space/be-mail-platform/routes"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run cmd/main.go [server|sync|sync_process|sync_sent]")
		os.Exit(1)
	}

	config.InitConfig()
	config.InitDB()

	switch os.Args[1] {
	case "server":
		runServer()
	case "sync":
		runSync()
	case "sync_process":
		runSyncWithProcess() // New: Sync + Process in one
	case "sync_sent":
		runSyncSent()
	case "process":
		runProcess() // New: Process only
	default:
		fmt.Println("Invalid command. Usage: go run cmd/main.go [server|sync|sync_process|sync_sent|process]")
		os.Exit(1)
	}
}

func runServer() {
	e := echo.New()

	// Hide server information
	e.HideBanner = true
	e.HidePort = true

	// Security middleware
	e.Use(middleware.SecureWithConfig(middleware.SecureConfig{
		XSSProtection:         "1; mode=block",
		ContentTypeNosniff:    "nosniff",
		XFrameOptions:         "SAMEORIGIN",
		HSTSMaxAge:            3600,
		ContentSecurityPolicy: "default-src 'self'",
	}))

	// Custom HTTP headers middleware
	e.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// Remove or replace default headers
			c.Response().Header().Set("Server", "")
			c.Response().Header().Set("X-Powered-By", "")
			return next(c)
		}
	})

	// Middleware and CORS configuration
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{echo.GET, echo.POST, echo.PUT, echo.DELETE},
		AllowHeaders:     []string{echo.HeaderOrigin, echo.HeaderContentType, echo.HeaderAccept, "Authorization"},
		ExposeHeaders:    []string{echo.HeaderContentLength},
		AllowCredentials: true,
		MaxAge:           86400,
	}))

	// Register routes
	routes.RegisterRoutes(e)

	// Start the server
	e.Logger.Fatal(e.Start(":8000"))
}

func runSyncSent() {
	fmt.Println("init delete sync sent emails")

	// Start the periodic task in a separate goroutine
	go func() {
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()

		for {
			<-ticker.C
			// Call the SyncEmails function
			fmt.Println("sync sent emails", time.Now())
			err := email.SyncSentEmails()
			if err != nil {
				fmt.Println("Error syncing sent emails:", err)
			}
			fmt.Println("finish sync sent emails", time.Now())
		}
	}()

	// Block the main goroutine to keep the application running
	select {}
}

func runSync() {
	fmt.Println("init sync emails")

	// Start the periodic task in a separate goroutine
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()

		for {
			<-ticker.C
			// Call the SyncEmails function
			fmt.Println("sync emails", time.Now())
			err := email.SyncEmails()
			if err != nil {
				fmt.Println("Error syncing emails:", err)
			}
			fmt.Println("finish sync emails", time.Now())
		}
	}()

	// Block the main goroutine to keep the application running
	select {}
}

// runSyncWithProcess runs both sync and process in one cron
// Recommended for most use cases - handles 200+ emails/minute
func runSyncWithProcess() {
	fmt.Println("==============================================")
	fmt.Println("  STARTING SYNC + PROCESS CRON")
	fmt.Println("  - Sync interval: 10 seconds")
	fmt.Println("  - Process interval: 5 seconds")
	fmt.Println("  - Batch size: 50 emails")
	fmt.Println("  - Workers: 10 parallel")
	fmt.Println("==============================================")

	// Sync cron: Pull from S3 every 10 seconds
	go func() {
		// Run immediately on start
		fmt.Println("[Sync] Initial sync starting...")
		if err := email.SyncEmails(); err != nil {
			fmt.Println("[Sync] Initial sync error:", err)
		}

		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()

		for {
			<-ticker.C
			fmt.Println("[Sync] Starting S3 sync...", time.Now())
			err := email.SyncEmails()
			if err != nil {
				fmt.Println("[Sync] Error:", err)
			}
			fmt.Println("[Sync] Completed", time.Now())
		}
	}()

	// Process cron: Parse emails every 5 seconds
	go func() {
		// Small delay to let sync run first
		time.Sleep(3 * time.Second)

		// Run immediately
		fmt.Println("[Process] Initial process starting...")
		if err := email.ProcessAllPendingEmails(); err != nil {
			fmt.Println("[Process] Initial process error:", err)
		}

		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()

		for {
			<-ticker.C
			fmt.Println("[Process] Starting email processing...", time.Now())
			err := email.ProcessAllPendingEmails()
			if err != nil {
				fmt.Println("[Process] Error:", err)
			}
		}
	}()

	// Block the main goroutine
	select {}
}

// runProcess runs only the process cron (useful if sync is separate)
func runProcess() {
	fmt.Println("==============================================")
	fmt.Println("  STARTING PROCESS-ONLY CRON")
	fmt.Println("  - Process interval: 5 seconds")
	fmt.Println("  - Batch size: 50 emails")
	fmt.Println("  - Workers: 10 parallel")
	fmt.Println("==============================================")

	// Run immediately
	fmt.Println("[Process] Initial process starting...")
	if err := email.ProcessAllPendingEmails(); err != nil {
		fmt.Println("[Process] Initial process error:", err)
	}

	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()

		for {
			<-ticker.C
			fmt.Println("[Process] Starting email processing...", time.Now())
			err := email.ProcessAllPendingEmails()
			if err != nil {
				fmt.Println("[Process] Error:", err)
			}
		}
	}()

	// Block the main goroutine
	select {}
}
