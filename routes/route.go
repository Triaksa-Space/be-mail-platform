package routes

import (
	"github.com/Triaksa-Space/be-mail-platform/domain/admin"
	"github.com/Triaksa-Space/be-mail-platform/domain/auth"
	"github.com/Triaksa-Space/be-mail-platform/domain/content"
	domain "github.com/Triaksa-Space/be-mail-platform/domain/domain_email"
	"github.com/Triaksa-Space/be-mail-platform/domain/email"
	"github.com/Triaksa-Space/be-mail-platform/domain/password"
	"github.com/Triaksa-Space/be-mail-platform/domain/user"
	"github.com/Triaksa-Space/be-mail-platform/middleware"

	"github.com/labstack/echo/v4"
)

func RegisterRoutes(e *echo.Echo) {
	// Role definitions
	superAdminOnly := []int{0}
	adminRoles := []int{0, 2}

	// Auth routes (new refresh token flow)
	e.POST("/login", auth.LoginHandler)
	e.POST("/token/refresh", auth.RefreshTokenHandler)
	e.POST("/logout", auth.LogoutHandler, middleware.JWTMiddleware)

	// Legacy login route (for backward compatibility)
	e.POST("/user/login", user.LoginHandler)
	e.POST("/email/bounce", email.HandleEmailBounceHandler)

	// Password reset routes (public)
	e.POST("/password/forgot", password.ForgotPasswordHandler)
	e.POST("/password/verify-code", password.VerifyCodeHandler)
	e.POST("/password/reset", password.ResetPasswordHandler)

	// Content routes (public)
	e.GET("/content/terms", content.GetTermsHandler)
	e.GET("/content/privacy", content.GetPrivacyHandler)

	// Domain routes
	domainGroup := e.Group("/domain", middleware.JWTMiddleware)
	domainGroup.GET("/dropdown", domain.GetDropdownDomainHandler, middleware.RoleMiddleware(adminRoles))
	domainGroup.POST("/", domain.CreateDomainHandler, middleware.RoleMiddleware(superAdminOnly))
	domainGroup.DELETE("/:id", domain.DeleteDomainHandler, middleware.RoleMiddleware(superAdminOnly))

	// User routes
	userGroup := e.Group("/user")
	userGroup.Use(middleware.JWTMiddleware)
	userGroup.PUT("/change_password", user.ChangePasswordHandler)
	userGroup.PUT("/change_password/admin", user.ChangePasswordAdminHandler, middleware.RoleMiddleware(superAdminOnly))
	userGroup.PUT("/binding-email", user.SetBindingEmailHandler) // User sets their binding email
	userGroup.POST("/", user.CreateUserHandler, middleware.RoleMiddleware(adminRoles), middleware.AdminPermissionMiddleware("create_single"))
	userGroup.POST("/admin", user.CreateUserAdminHandler, middleware.RoleMiddleware(superAdminOnly))
	userGroup.POST("/bulk", user.BulkCreateUserHandler, middleware.RoleMiddleware(adminRoles), middleware.AdminPermissionMiddleware("create_bulk"))
	userGroup.POST("/bulk/v2", user.BulkCreateUserV2Handler, middleware.RoleMiddleware(adminRoles), middleware.AdminPermissionMiddleware("create_bulk"))
	userGroup.GET("/get_user_me", user.GetUserMeHandler)                                            // Must be before /:id
	userGroup.GET("/", user.ListUsersHandler, middleware.RoleMiddleware(adminRoles), middleware.AdminPermissionMiddleware("user_list"))
	userGroup.GET("/admin", user.ListAdminUsersHandler, middleware.RoleMiddleware(superAdminOnly))
	userGroup.GET("/:id", user.GetUserHandler, middleware.RoleMiddleware(adminRoles), middleware.AdminPermissionMiddleware("user_list")) // Parameterized route last
	userGroup.DELETE("/admin/:id", user.DeleteUserAdminHandler, middleware.RoleMiddleware(superAdminOnly))
	userGroup.DELETE("/:id", user.DeleteUserHandler, middleware.RoleMiddleware(adminRoles), middleware.AdminPermissionMiddleware("user_list"))

	// Email routes
	emailGroup := e.Group("/email", middleware.JWTMiddleware)
	emailGroup.POST("/upload/attachment", email.UploadAttachmentHandler)
	emailGroup.GET("/:id", email.GetEmailHandler, middleware.RoleMiddleware(adminRoles))
	emailGroup.GET("/by_user", email.ListEmailByTokenHandler)
	emailGroup.GET("/by_user/detail/:id", email.GetEmailHandler)
	emailGroup.POST("/by_user/download/file", email.GetFileEmailToDownloadHandler)
	emailGroup.GET("/by_user/:id", email.ListEmailByIDHandler, middleware.RoleMiddleware(adminRoles))
	emailGroup.GET("/sent/by_user", email.SentEmailByIDHandler)
	emailGroup.GET("/sent/by_user/:id", email.ListSentEmailsByUserIDHandler, middleware.RoleMiddleware(adminRoles), middleware.AdminPermissionMiddleware("all_sent")) // Admin: list sent emails by user
	emailGroup.GET("/sent", email.GetUserSentEmailsHandler) // User's own sent emails
	emailGroup.POST("/send", email.SendEmailHandler)
	emailGroup.POST("/send/resend", email.SendEmailViaResendHandler)
	emailGroup.POST("/send/smtp", email.SendEmailSMTPHandler)
	emailGroup.POST("/send/test/haraka", email.SendEmailSMTPHHandler)
	emailGroup.POST("/send/url_attachment", email.SendEmailUrlAttachmentHandler)
	emailGroup.POST("/delete-attachment", email.DeleteUrlAttachmentHandler)
	emailGroup.GET("/", email.ListEmailsHandler, middleware.RoleMiddleware(adminRoles))
	emailGroup.DELETE("/:id", email.DeleteEmailHandler, middleware.RoleMiddleware(adminRoles))
	emailGroup.GET("/bucket/sync", email.SyncBucketInboxHandler, middleware.RoleMiddleware(adminRoles))

	// Admin routes
	adminGroup := e.Group("/admin", middleware.JWTMiddleware)
	adminGroup.Use(middleware.RoleMiddleware(adminRoles))

	// Admin content management (permission checked in handler based on :key)
	adminGroup.PUT("/content/:key", content.UpdateContentHandler)

	// Admin dashboard
	adminGroup.GET("/overview", admin.GetOverviewHandler, middleware.AdminPermissionMiddleware("overview"))

	// Admin inbox and sent views
	adminGroup.GET("/inbox", admin.GetAdminInboxHandler, middleware.AdminPermissionMiddleware("all_inbox"))
	adminGroup.GET("/inbox/:id", admin.GetAdminInboxDetailHandler, middleware.AdminPermissionMiddleware("all_inbox"))
	adminGroup.GET("/sent", admin.GetAdminSentHandler, middleware.AdminPermissionMiddleware("all_sent"))
	adminGroup.GET("/sent/:id", admin.GetAdminSentDetailHandler, middleware.AdminPermissionMiddleware("all_sent"))

	// Admin menu and permissions
	adminGroup.GET("/menus", admin.GetMenusHandler)
	adminGroup.GET("/permissions", admin.GetPermissionsHandler, middleware.RoleMiddleware(superAdminOnly))
	adminGroup.PUT("/permissions/:role_id", admin.UpdatePermissionsHandler, middleware.RoleMiddleware(superAdminOnly))

	// Admin user management (Roles & Permissions page) - Superadmin only
	adminGroup.GET("/admins", admin.ListAdminsHandler, middleware.RoleMiddleware(superAdminOnly))
	adminGroup.GET("/admins/:id", admin.GetAdminHandler, middleware.RoleMiddleware(superAdminOnly))
	adminGroup.POST("/admins", admin.CreateAdminHandler, middleware.RoleMiddleware(superAdminOnly))
	adminGroup.PUT("/admins/:id", admin.UpdateAdminHandler, middleware.RoleMiddleware(superAdminOnly))
	adminGroup.DELETE("/admins/:id", admin.DeleteAdminHandler, middleware.RoleMiddleware(superAdminOnly))
}
