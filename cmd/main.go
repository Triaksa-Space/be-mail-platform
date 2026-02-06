package main

import (
	"context"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/Triaksa-Space/be-mail-platform/config"
	"github.com/Triaksa-Space/be-mail-platform/domain/email"
	"github.com/Triaksa-Space/be-mail-platform/pkg/apperrors"
	"github.com/Triaksa-Space/be-mail-platform/pkg/logger"
	"github.com/Triaksa-Space/be-mail-platform/routes"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/spf13/viper"
)

func main() {
	if len(os.Args) < 2 {
		println("Usage: go run cmd/main.go [server|sync|sync_process|sync_sent|process]")
		os.Exit(1)
	}

	// Initialize configuration
	config.InitConfig()

	// Initialize logger
	initLogger()
	log := logger.Get()

	// Initialize database
	config.InitDB()
	log.Info("Application initialized", logger.String("command", os.Args[1]))

	switch os.Args[1] {
	case "server":
		runServer()
	case "sync":
		runSyncWithProcess() // runSync()
	case "sync_process":
		runSyncWithProcess()
	case "sync_sent":
		runSyncSent()
	case "process":
		runProcess()
	default:
		log.Fatal("Invalid command", nil, logger.String("command", os.Args[1]))
	}
}

// initLogger initializes the structured logger
func initLogger() {
	env := viper.GetString("APP_ENV")
	if env == "" {
		env = "development"
	}

	logLevel := viper.GetString("LOG_LEVEL")
	if logLevel == "" {
		logLevel = "info"
	}

	logger.Init(logger.Config{
		Level:       logger.Level(logLevel),
		Environment: env,
		ServiceName: "mail-platform",
		Version:     viper.GetString("APP_VERSION"),
	})
}

func runServer() {
	log := logger.Get().WithComponent("server")
	e := echo.New()

	// Hide server information
	e.HideBanner = true
	e.HidePort = true

	// Custom error handler
	e.HTTPErrorHandler = apperrors.HTTPErrorHandler(log)

	// Recovery middleware with logging
	e.Use(logger.RecoveryMiddleware(log))

	// Request logging middleware
	e.Use(logger.RequestLoggerMiddleware(log))

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
			c.Response().Header().Set("Server", "")
			c.Response().Header().Set("X-Powered-By", "")
			return next(c)
		}
	})

	// CORS configuration
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{echo.GET, echo.POST, echo.PUT, echo.DELETE},
		AllowHeaders:     []string{echo.HeaderOrigin, echo.HeaderContentType, echo.HeaderAccept, "Authorization"},
		ExposeHeaders:    []string{echo.HeaderContentLength, "X-Request-ID"},
		AllowCredentials: true,
		MaxAge:           86400,
	}))

	// Register routes
	routes.RegisterRoutes(e)

	// Start server with graceful shutdown
	go func() {
		log.Info("Starting HTTP server", logger.String("port", ":8000"))
		if err := e.Start(":8000"); err != nil {
			log.Info("Server stopped", logger.Err(err))
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info("Shutting down server...")

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := e.Shutdown(ctx); err != nil {
		log.Error("Server shutdown error", err)
	}

	log.Info("Server stopped gracefully")
}

func runSyncSent() {
	log := logger.Get().WithComponent("sync_sent")
	log.Info("Starting sync sent emails cron", logger.Duration("interval", 24*time.Hour))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				log.Info("Sync sent worker stopping")
				return
			case <-ticker.C:
				log.Info("Starting sync sent emails...")
				if err := email.SyncSentEmails(); err != nil {
					log.Error("Sync sent emails failed", err)
				} else {
					log.Info("Sync sent emails completed")
				}
			}
		}
	}()

	// Wait for shutdown signal
	sig := <-sigChan
	log.Info("Received shutdown signal", logger.String("signal", sig.String()))
	cancel()
	log.Info("Sync sent stopped gracefully")
}

func runSync() {
	log := logger.Get().WithComponent("sync")
	log.Info("Starting sync emails cron", logger.Duration("interval", 10*time.Second))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				log.Info("Sync worker stopping")
				return
			case <-ticker.C:
				log.Debug("Starting S3 sync...")
				if err := email.SyncEmails(); err != nil {
					log.Error("Sync emails failed", err)
				}
			}
		}
	}()

	// Wait for shutdown signal
	sig := <-sigChan
	log.Info("Received shutdown signal", logger.String("signal", sig.String()))
	cancel()
	log.Info("Sync stopped gracefully")
}

// runSyncWithProcess runs both sync and process in one cron
// Recommended for most use cases - handles 200+ emails/minute
func runSyncWithProcess() {
	log := logger.Get().WithComponent("cron")

	log.Info("Starting sync + process cron",
		logger.Int("sync_interval_sec", 10),
		logger.Int("process_interval_sec", 5),
		logger.Int("batch_size", 50),
		logger.Int("workers", 10),
	)

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())

	// Handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	var wg sync.WaitGroup

	// Sync goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		syncWorker(ctx, log)
	}()

	// Process goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(3 * time.Second) // Initial delay to let sync run first
		processWorker(ctx, log)
	}()

	// Wait for shutdown signal
	sig := <-sigChan
	log.Info("Received shutdown signal", logger.String("signal", sig.String()))

	// Cancel context to stop workers
	cancel()

	// Wait for workers to finish with timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		log.Info("All workers stopped gracefully")
	case <-time.After(30 * time.Second):
		log.Warn("Timeout waiting for workers, forcing shutdown")
	}
}

func syncWorker(ctx context.Context, log logger.Logger) {
	log = log.WithComponent("sync_worker")
	log.Info("Sync worker started")

	// Run immediately on start
	if err := email.SyncEmails(); err != nil {
		log.Error("Initial sync failed", err)
	}

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Info("Sync worker stopping")
			return
		case <-ticker.C:
			log.Debug("Starting S3 sync...")
			if err := email.SyncEmails(); err != nil {
				log.Error("Sync failed", err)
			}
		}
	}
}

func processWorker(ctx context.Context, log logger.Logger) {
	log = log.WithComponent("process_worker")
	log.Info("Process worker started")

	// Run immediately
	if err := email.ProcessAllPendingEmails(); err != nil {
		log.Error("Initial process failed", err)
	}

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Info("Process worker stopping")
			return
		case <-ticker.C:
			log.Debug("Starting email processing...")
			if err := email.ProcessAllPendingEmails(); err != nil {
				log.Error("Process failed", err)
			}
		}
	}
}

// runProcess runs only the process cron (useful if sync is separate)
func runProcess() {
	log := logger.Get().WithComponent("process")

	log.Info("Starting process-only cron",
		logger.Int("interval_sec", 5),
		logger.Int("batch_size", 50),
		logger.Int("workers", 10),
	)

	ctx, cancel := context.WithCancel(context.Background())

	// Handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Run immediately
	if err := email.ProcessAllPendingEmails(); err != nil {
		log.Error("Initial process failed", err)
	}

	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				log.Info("Process worker stopping")
				return
			case <-ticker.C:
				log.Debug("Starting email processing...")
				if err := email.ProcessAllPendingEmails(); err != nil {
					log.Error("Process failed", err)
				}
			}
		}
	}()

	// Wait for shutdown signal
	sig := <-sigChan
	log.Info("Received shutdown signal", logger.String("signal", sig.String()))
	cancel()

	// Give worker time to finish current batch
	time.Sleep(2 * time.Second)
	log.Info("Process stopped gracefully")
}
