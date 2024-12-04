package middleware

import (
	"net/http"

	"github.com/Triaksa-Space/be-mail-platform/config"

	"github.com/labstack/echo/v4"
)

func RoleMiddleware(requiredRoleID int) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			userID := c.Get("user_id").(int64) // Extract user_id from context

			// Fetch the user's role ID from the database
			var roleID int
			err := config.DB.Get(&roleID, "SELECT role_id FROM users WHERE id = ?", userID)
			if err != nil || roleID != requiredRoleID {
				return c.JSON(http.StatusForbidden, map[string]string{"error": "Access denied"})
			}

			// Continue to the next handler
			return next(c)
		}
	}
}
