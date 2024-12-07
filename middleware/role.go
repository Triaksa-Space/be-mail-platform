package middleware

import (
	"fmt"
	"net/http"

	"github.com/Triaksa-Space/be-mail-platform/config"
	"github.com/labstack/echo/v4"
)

// RoleMiddleware checks if the user's role ID is in the list of required role IDs
func RoleMiddleware(requiredRoleIDs []int) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			userID := c.Get("user_id").(int64) // Extract user_id from context

			// Fetch the user's role ID from the database
			var roleID int
			err := config.DB.Get(&roleID, "SELECT role_id FROM users WHERE id = ?", userID)
			if err != nil {
				fmt.Println("Failed to fetch user's role ID:", err)
				return c.JSON(http.StatusForbidden, map[string]string{"error": "Access denied"})
			}

			// Check if the user's role ID is in the list of required role IDs
			roleAllowed := false
			for _, requiredRoleID := range requiredRoleIDs {
				if roleID == requiredRoleID {
					roleAllowed = true
					break
				}
			}

			if !roleAllowed {
				return c.JSON(http.StatusForbidden, map[string]string{"error": "Access denied"})
			}

			// Continue to the next handler
			return next(c)
		}
	}
}
