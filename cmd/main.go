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
		fmt.Println("Usage: go run cmd/main.go [server|sync]")
		os.Exit(1)
	}

	config.InitConfig()
	config.InitDB()

	switch os.Args[1] {
	case "server":
		runServer()
	case "sync":
		runSync()
	case "sync_sent":
		runSyncSent()
	default:
		fmt.Println("Invalid command. Usage: go run cmd/main.go [server|sync]")
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
