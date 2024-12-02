package routes

import (
	domain "email-platform/domain/domain_email"
	"email-platform/domain/email"
	"email-platform/domain/user"
	"email-platform/middleware"

	"github.com/labstack/echo/v4"
)

func RegisterRoutes(e *echo.Echo) {
	// User routes
	e.POST("/login", user.LoginHandler)
	e.POST("/logout", user.LogoutHandler, middleware.JWTMiddleware)

	domainGroup := e.Group("/domain", middleware.JWTMiddleware)
	domainGroup.GET("/dropdown", domain.GetDropdownDomainHandler, middleware.RoleMiddleware(0)) // Admin-only
	e.POST("/", domain.CreateDomainHandler, middleware.RoleMiddleware(0))
	e.DELETE("/:id", domain.DeleteDomainHandler, middleware.RoleMiddleware(0))

	userGroup := e.Group("/user")
	userGroup.Use(middleware.JWTMiddleware)
	userGroup.PUT("/change_password", user.ChangePasswordHandler)
	userGroup.POST("/", user.CreateUserHandler, middleware.RoleMiddleware(0))           // Admin-only
	userGroup.POST("/admin", user.CreateUserAdminHandler, middleware.RoleMiddleware(0)) // Admin-only
	userGroup.POST("/bulk", user.BulkCreateUserHandler, middleware.RoleMiddleware(0))   // Admin-only
	userGroup.GET("/:id", user.GetUserHandler, middleware.RoleMiddleware(0))
	userGroup.GET("/get_user_me", user.GetUserMeHandler)
	userGroup.GET("/", user.ListUsersHandler, middleware.RoleMiddleware(0))
	userGroup.GET("/admin", user.ListAdminUsersHandler, middleware.RoleMiddleware(0))
	userGroup.DELETE("/:id", user.DeleteUserHandler, middleware.RoleMiddleware(0)) // Admin-only

	// Email routes
	emailGroup := e.Group("/email", middleware.JWTMiddleware)
	emailGroup.GET("/:id", email.GetEmailHandler, middleware.RoleMiddleware(0))
	emailGroup.GET("/by_user", email.ListEmailByTokenHandler)
	emailGroup.GET("/by_user/detail/:id", email.GetEmailHandler)                             // email id
	emailGroup.GET("/by_user/:id", email.ListEmailByIDHandler, middleware.RoleMiddleware(0)) // user id
	emailGroup.GET("/sent/by_user", email.SentEmailByIDHandler, middleware.RoleMiddleware(0))
	emailGroup.POST("/send", email.SendEmailHandler)
	emailGroup.GET("/", email.ListEmailsHandler, middleware.RoleMiddleware(0))
	emailGroup.DELETE("/:id", email.DeleteEmailHandler, middleware.RoleMiddleware(0)) // Admin-only

	emailGroup.GET("/bucket/sync", email.SyncBucketInboxHandler, middleware.RoleMiddleware(0)) // Admin-only
	// emailGroup.GET("/bucket/inbox", email.GetInboxHandler, middleware.RoleMiddleware(0))       // Admin-only
}
