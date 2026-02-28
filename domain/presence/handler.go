package presence

import (
	"net/http"

	"github.com/Triaksa-Space/be-mail-platform/config"
	"github.com/labstack/echo/v4"
)

// HeartbeatHandler updates the last active timestamp for the authenticated user in Redis.
// POST /heartbeat
func HeartbeatHandler(c echo.Context) error {
	userID := c.Get("user_id").(int64)

	if err := config.SetLastActive(userID); err != nil {
		// Redis write failed — log silently, don't break the client
		return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
	}

	return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
}
