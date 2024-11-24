package middleware

import (
	"net/http"
	"strconv"

	"github.com/labstack/echo/v4"
)

func RoleMiddleware(requiredRole string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// userID := c.Get("user_id").(string) // Assuming JWT middleware sets "user_id" in the context
			roleID := c.Get("role_id").(string) // Assuming JWT middleware sets "role_id" in the context

			var requiredRoleID int
			if requiredRole == "admin" {
				requiredRoleID = 0
			} else if requiredRole == "user" {
				requiredRoleID = 1
			} else {
				return c.JSON(http.StatusForbidden, map[string]string{"error": "invalid role"})
			}

			userRoleID, err := strconv.Atoi(roleID)
			if err != nil || userRoleID != requiredRoleID {
				return c.JSON(http.StatusForbidden, map[string]string{"error": "access denied"})
			}

			return next(c)
		}
	}
}
