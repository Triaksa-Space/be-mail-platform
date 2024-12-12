package routes

import (
	domain "github.com/Triaksa-Space/be-mail-platform/domain/domain_email"
	"github.com/Triaksa-Space/be-mail-platform/domain/email"
	"github.com/Triaksa-Space/be-mail-platform/domain/user"
	"github.com/Triaksa-Space/be-mail-platform/middleware"

	"github.com/labstack/echo/v4"
)

func RegisterRoutes(e *echo.Echo) {
	// loginLimiter := middleware.LoginAttemptMiddleware(middleware.RateLimiterConfig{
	// 	MaxAttempts:   4,                // Block after 4 failed attempts
	// 	BlockDuration: 10 * time.Minute, // Block for 10 minutes
	// 	DB:            config.DB.DB,     // Your database connection
	// })

	// User routes
	e.POST("/login", user.LoginHandler)
	e.POST("/logout", user.LogoutHandler, middleware.JWTMiddleware)
	// e.POST("/sns/notifications", email.CallbackNotifEmailHandler)

	superAdminOnly := []int{0}
	admin := []int{0, 2}

	domainGroup := e.Group("/domain", middleware.JWTMiddleware)
	domainGroup.GET("/dropdown", domain.GetDropdownDomainHandler, middleware.RoleMiddleware(admin)) // Admin-only
	e.POST("/", domain.CreateDomainHandler, middleware.RoleMiddleware(superAdminOnly))
	e.DELETE("/:id", domain.DeleteDomainHandler, middleware.RoleMiddleware(superAdminOnly))

	userGroup := e.Group("/user")
	userGroup.Use(middleware.JWTMiddleware)
	userGroup.PUT("/change_password", user.ChangePasswordHandler)
	userGroup.PUT("/change_password/admin", user.ChangePasswordAdminHandler, middleware.RoleMiddleware(superAdminOnly))
	// `${process.env.NEXT_PUBLIC_API_BASE_URL}/user/${selectedAdmin.id}/change_password`,
	userGroup.POST("/", user.CreateUserHandler, middleware.RoleMiddleware(admin))                    // Admin-only
	userGroup.POST("/admin", user.CreateUserAdminHandler, middleware.RoleMiddleware(superAdminOnly)) // Admin-only
	userGroup.POST("/bulk", user.BulkCreateUserHandler, middleware.RoleMiddleware(admin))            // Admin-only
	userGroup.GET("/:id", user.GetUserHandler, middleware.RoleMiddleware(admin))
	userGroup.GET("/get_user_me", user.GetUserMeHandler)
	userGroup.GET("/", user.ListUsersHandler, middleware.RoleMiddleware(admin))
	userGroup.GET("/admin", user.ListAdminUsersHandler, middleware.RoleMiddleware(superAdminOnly))
	userGroup.DELETE("/:id", user.DeleteUserHandler, middleware.RoleMiddleware(admin))
	userGroup.DELETE("/admin/:id", user.DeleteUserAdminHandler, middleware.RoleMiddleware(superAdminOnly)) // Admin-only

	// Email routes
	emailGroup := e.Group("/email", middleware.JWTMiddleware)
	emailGroup.POST("/upload/attachment", email.UploadAttachmentHandler)
	emailGroup.GET("/:id", email.GetEmailHandler, middleware.RoleMiddleware(admin))
	emailGroup.GET("/by_user", email.ListEmailByTokenHandler)                                    // - sync mailbox
	emailGroup.GET("/by_user/detail/:id", email.GetEmailHandler)                                 // email id
	emailGroup.POST("/by_user/download/file", email.GetFileEmailToDownloadHandler)               // email id
	emailGroup.GET("/by_user/:id", email.ListEmailByIDHandler, middleware.RoleMiddleware(admin)) // user id - sync mailbox
	emailGroup.GET("/sent/by_user", email.SentEmailByIDHandler)
	emailGroup.POST("/send", email.SendEmailHandler)
	emailGroup.POST("/send/smtp", email.SendEmailSMTPHandler)
	emailGroup.POST("/send/test/haraka", email.SendEmailSMTPHHandler)
	emailGroup.POST("/send/url_attachment", email.SendEmailUrlAttachmentHandler)
	emailGroup.POST("/delete-attachment", email.DeleteUrlAttachmentHandler)
	emailGroup.GET("/", email.ListEmailsHandler, middleware.RoleMiddleware(admin))
	emailGroup.DELETE("/:id", email.DeleteEmailHandler, middleware.RoleMiddleware(admin)) // Admin-only

	emailGroup.GET("/bucket/sync", email.SyncBucketInboxHandler, middleware.RoleMiddleware(admin)) // Admin-only
	// emailGroup.GET("/bucket/inbox", email.GetInboxHandler, middleware.RoleMiddleware(0))       // Admin-only
}
