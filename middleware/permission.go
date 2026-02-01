package middleware

import (
	"fmt"
	"net/http"

	"github.com/Triaksa-Space/be-mail-platform/config"
	"github.com/labstack/echo/v4"
)

// PermissionMiddleware checks if the user has permission to access the requested endpoint
func PermissionMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			roleID := c.Get("role_id").(int64)

			// SuperAdmin bypasses all checks
			if roleID == 0 {
				return next(c)
			}

			method := c.Request().Method
			path := c.Path() // e.g., "/user/:id"

			// Query: Check if this role has permission for this endpoint
			var hasPermission bool
			err := config.DB.Get(&hasPermission, `
				SELECT EXISTS(
					SELECT 1 FROM role_menu_permissions rmp
					JOIN menu_api_permissions map ON rmp.menu_id = map.menu_id
					WHERE rmp.role_id = ?
					  AND map.http_method = ?
					  AND map.api_pattern = ?
					  AND CASE
						  WHEN ? = 'GET' THEN rmp.can_view
						  WHEN ? = 'POST' THEN rmp.can_create
						  WHEN ? = 'PUT' THEN rmp.can_edit
						  WHEN ? = 'DELETE' THEN rmp.can_delete
						  ELSE FALSE
					  END = TRUE
				)
			`, roleID, method, path, method, method, method, method)

			if err != nil || !hasPermission {
				return c.JSON(http.StatusForbidden, map[string]string{
					"error": "You don't have permission to access this resource",
				})
			}

			return next(c)
		}
	}
}

// CheckPermission is a helper function to check permission programmatically
func CheckPermission(roleID int64, method, path string) bool {
	// SuperAdmin bypasses all checks
	if roleID == 0 {
		return true
	}

	var hasPermission bool
	err := config.DB.Get(&hasPermission, `
		SELECT EXISTS(
			SELECT 1 FROM role_menu_permissions rmp
			JOIN menu_api_permissions map ON rmp.menu_id = map.menu_id
			WHERE rmp.role_id = ?
			  AND map.http_method = ?
			  AND map.api_pattern = ?
			  AND CASE
				  WHEN ? = 'GET' THEN rmp.can_view
				  WHEN ? = 'POST' THEN rmp.can_create
				  WHEN ? = 'PUT' THEN rmp.can_edit
				  WHEN ? = 'DELETE' THEN rmp.can_delete
				  ELSE FALSE
			  END = TRUE
		)
	`, roleID, method, path, method, method, method, method)

	return err == nil && hasPermission
}

// AdminPermissionMiddleware checks if an admin user has the required permission
// This uses the admin_permissions table for per-user permission control
// SuperAdmin (role_id=0) bypasses all checks
// Regular users (role_id=1) are denied
// Admin users (role_id=2) are checked against admin_permissions table
func AdminPermissionMiddleware(requiredPermission string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			roleID := c.Get("role_id").(int64)
			userID := c.Get("user_id").(int64)

			// SuperAdmin bypasses all permission checks
			if roleID == 0 {
				return next(c)
			}

			// Regular users don't have admin permissions
			if roleID == 1 {
				return c.JSON(http.StatusForbidden, map[string]string{
					"error": "Access denied. Admin privileges required.",
				})
			}

			// Check if admin has the required permission
			var hasPermission bool
			err := config.DB.Get(&hasPermission, `
				SELECT EXISTS(
					SELECT 1 FROM admin_permissions
					WHERE user_id = ? AND permission_key = ?
				)
			`, userID, requiredPermission)

			if err != nil {
				fmt.Println("Error checking admin permission:", err)
				return c.JSON(http.StatusInternalServerError, map[string]string{
					"error": "Internal server error",
				})
			}

			if !hasPermission {
				return c.JSON(http.StatusForbidden, map[string]string{
					"error":      "You don't have permission to access this resource",
					"permission": requiredPermission,
				})
			}

			return next(c)
		}
	}
}

// HasAdminPermission checks if an admin user has a specific permission
func HasAdminPermission(userID int64, permission string) bool {
	var exists bool
	err := config.DB.Get(&exists, `
		SELECT EXISTS(
			SELECT 1 FROM admin_permissions
			WHERE user_id = ? AND permission_key = ?
		)
	`, userID, permission)

	return err == nil && exists
}
