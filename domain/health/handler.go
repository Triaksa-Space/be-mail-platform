package health

import (
	"context"
	"net/http"
	"runtime"
	"time"

	"github.com/Triaksa-Space/be-mail-platform/config"
	"github.com/labstack/echo/v4"
)

// HealthResponse represents the health check response
type HealthResponse struct {
	Status    string            `json:"status"`
	Timestamp string            `json:"timestamp"`
	Version   string            `json:"version,omitempty"`
	Checks    map[string]Check  `json:"checks,omitempty"`
}

// Check represents an individual health check result
type Check struct {
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
	Latency string `json:"latency,omitempty"`
}

// ReadinessResponse represents the readiness check response
type ReadinessResponse struct {
	Status    string           `json:"status"`
	Timestamp string           `json:"timestamp"`
	Checks    map[string]Check `json:"checks"`
}

// StatsResponse represents system statistics
type StatsResponse struct {
	GoVersion    string `json:"go_version"`
	NumCPU       int    `json:"num_cpu"`
	NumGoroutine int    `json:"num_goroutine"`
	MemAlloc     uint64 `json:"mem_alloc_bytes"`
	MemSys       uint64 `json:"mem_sys_bytes"`
	Uptime       string `json:"uptime,omitempty"`
}

var startTime = time.Now()

// LivenessHandler handles the /health/live endpoint
// Returns 200 if the service is running (for Kubernetes liveness probe)
func LivenessHandler(c echo.Context) error {
	return c.JSON(http.StatusOK, HealthResponse{
		Status:    "ok",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	})
}

// ReadinessHandler handles the /health/ready endpoint
// Returns 200 if the service is ready to accept traffic (for Kubernetes readiness probe)
func ReadinessHandler(c echo.Context) error {
	checks := make(map[string]Check)
	allHealthy := true

	// Check database connection
	dbCheck := checkDatabase()
	checks["database"] = dbCheck
	if dbCheck.Status != "ok" {
		allHealthy = false
	}

	status := "ok"
	httpStatus := http.StatusOK
	if !allHealthy {
		status = "unhealthy"
		httpStatus = http.StatusServiceUnavailable
	}

	return c.JSON(httpStatus, ReadinessResponse{
		Status:    status,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Checks:    checks,
	})
}

// HealthHandler handles the /health endpoint
// Returns comprehensive health information
func HealthHandler(c echo.Context) error {
	checks := make(map[string]Check)
	allHealthy := true

	// Check database
	dbCheck := checkDatabase()
	checks["database"] = dbCheck
	if dbCheck.Status != "ok" {
		allHealthy = false
	}

	status := "ok"
	httpStatus := http.StatusOK
	if !allHealthy {
		status = "degraded"
		httpStatus = http.StatusServiceUnavailable
	}

	return c.JSON(httpStatus, HealthResponse{
		Status:    status,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Checks:    checks,
	})
}

// StatsHandler handles the /health/stats endpoint
// Returns system statistics for monitoring
func StatsHandler(c echo.Context) error {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	uptime := time.Since(startTime)

	return c.JSON(http.StatusOK, StatsResponse{
		GoVersion:    runtime.Version(),
		NumCPU:       runtime.NumCPU(),
		NumGoroutine: runtime.NumGoroutine(),
		MemAlloc:     m.Alloc,
		MemSys:       m.Sys,
		Uptime:       uptime.Round(time.Second).String(),
	})
}

// checkDatabase checks if the database is responsive
func checkDatabase() Check {
	start := time.Now()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	err := config.DB.PingContext(ctx)
	latency := time.Since(start)

	if err != nil {
		return Check{
			Status:  "error",
			Message: "Database connection failed",
			Latency: latency.String(),
		}
	}

	return Check{
		Status:  "ok",
		Latency: latency.String(),
	}
}
