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
	userGroup.PUT("/change_password", user.ChangePasswordHandler)
	userGroup.POST("/", user.CreateUserHandler, middleware.RoleMiddleware(0))         // Admin-only
	userGroup.POST("/bulk", user.BulkCreateUserHandler, middleware.RoleMiddleware(0)) // Admin-only
	userGroup.GET("/:id", user.GetUserHandler, middleware.RoleMiddleware(0))
	userGroup.GET("/get_user_me", user.GetUserMeHandler)
	userGroup.GET("/", user.ListUsersHandler, middleware.RoleMiddleware(0))
	userGroup.DELETE("/:id", user.DeleteUserHandler, middleware.RoleMiddleware(0)) // Admin-only

	// Email routes
	emailGroup := e.Group("/email", middleware.JWTMiddleware)
	emailGroup.GET("/:id", email.GetEmailHandler)
	emailGroup.GET("/by_user", email.ListEmailByIDHandler)
	emailGroup.GET("/sent/by_user", email.SentEmailByIDHandler)
	emailGroup.POST("/send", email.SendEmailHandler)
	emailGroup.GET("/", email.ListEmailsHandler, middleware.RoleMiddleware(0))
	emailGroup.DELETE("/:id", email.DeleteEmailHandler, middleware.RoleMiddleware(0)) // Admin-only
}
