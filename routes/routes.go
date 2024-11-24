package routes

import (
	"email-platform/domain/email"
	"email-platform/domain/user"
	"email-platform/middleware"

	"github.com/labstack/echo/v4"
)

func RegisterRoutes(e *echo.Echo) {
	// User routes
	e.POST("/user/login", user.LoginHandler)
	e.POST("/user/logout", user.LogoutHandler, middleware.JWTMiddleware)
	e.PUT("/user/change_password", user.ChangePasswordHandler, middleware.JWTMiddleware)
	e.POST("/user", user.CreateUserHandler, middleware.JWTMiddleware, middleware.RoleMiddleware("admin"))
	// e.POST("/user/bulk", user.BulkCreateUserHandler)
	e.DELETE("/user/:id", user.DeleteUserHandler, middleware.JWTMiddleware, middleware.RoleMiddleware("admin"))

	// Email routes (protected)
	emailGroup := e.Group("/email", middleware.JWTMiddleware)
	emailGroup.POST("/", email.SendEmailHandler)
	emailGroup.GET("/:email_id", email.GetEmailHandler)
	emailGroup.GET("/user/:user_id", email.ListEmailsHandler)
	emailGroup.DELETE("/:id", email.DeleteEmailHandler, middleware.RoleMiddleware("admin"))
}
