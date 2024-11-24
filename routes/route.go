package routes

import (
	"email-platform/domain/email"
	"email-platform/domain/user"
	"email-platform/middleware"

	"github.com/labstack/echo/v4"
)

func RegisterRoutes(e *echo.Echo) {
	// User routes
	e.POST("/login", user.LoginHandler)
	e.POST("/logout", user.LogoutHandler, middleware.JWTMiddleware)

	userGroup := e.Group("/user")
	userGroup.Use(middleware.JWTMiddleware)
	userGroup.PUT("/user/change_password", user.ChangePasswordHandler)
	userGroup.POST("/user", user.CreateUserHandler, middleware.RoleMiddleware(1))          // Admin-only
	userGroup.POST("/user/bulk", user.BulkCreateUserHandler, middleware.RoleMiddleware(1)) // Admin-only
	userGroup.DELETE("/user/:id", user.DeleteUserHandler, middleware.RoleMiddleware(1))    // Admin-only

	// Email routes
	emailGroup := e.Group("/email", middleware.JWTMiddleware)
	emailGroup.GET("/:id", email.GetEmailHandler)
	emailGroup.GET("/user/:user_id", email.ListEmailByIDHandler)
	emailGroup.GET("/", email.ListEmailsHandler, middleware.RoleMiddleware(1))
	emailGroup.DELETE("/:id", email.DeleteEmailHandler, middleware.RoleMiddleware(1)) // Admin-only
}
