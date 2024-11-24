package routes

import (
	"email-platform/domain/email"
	"email-platform/domain/user"
	"email-platform/middleware"

	"github.com/labstack/echo/v4"
	"github.com/spf13/viper"
)

func RegisterRoutes(e *echo.Echo) {
	jwtSecret := viper.GetString("JWT_SECRET")

	// User routes
	e.POST("/login", user.LoginHandler)
	e.POST("/logout", user.LogoutHandler, middleware.JWTMiddleware(jwtSecret))

	e.PUT("/user/change_password", user.ChangePasswordHandler, middleware.JWTMiddleware(jwtSecret))
	e.POST("/user", user.CreateUserHandler, middleware.JWTMiddleware(jwtSecret), middleware.RoleMiddleware(1))          // Admin-only
	e.POST("/user/bulk", user.BulkCreateUserHandler, middleware.JWTMiddleware(jwtSecret), middleware.RoleMiddleware(1)) // Admin-only
	e.DELETE("/user/:id", user.DeleteUserHandler, middleware.JWTMiddleware(jwtSecret), middleware.RoleMiddleware(1))    // Admin-only

	// Email routes
	emailGroup := e.Group("/email", middleware.JWTMiddleware(jwtSecret))
	emailGroup.GET("/:id", email.GetEmailHandler)
	emailGroup.GET("/", email.ListEmailsHandler)
	emailGroup.DELETE("/:id", email.DeleteEmailHandler, middleware.RoleMiddleware(1)) // Admin-only
}
