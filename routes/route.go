package routes

import (
	"github.com/Triaksa-Space/be-mail-platform/domain/admin"
	"github.com/Triaksa-Space/be-mail-platform/domain/auth"
	"github.com/Triaksa-Space/be-mail-platform/domain/content"
	domain "github.com/Triaksa-Space/be-mail-platform/domain/domain_email"
	"github.com/Triaksa-Space/be-mail-platform/domain/email"
	"github.com/Triaksa-Space/be-mail-platform/domain/health"
	"github.com/Triaksa-Space/be-mail-platform/domain/password"
	"github.com/Triaksa-Space/be-mail-platform/domain/user"
	"github.com/Triaksa-Space/be-mail-platform/middleware"

	"github.com/labstack/echo/v4"
)

func RegisterRoutes(e *echo.Echo) {
	// Role definitions
	superAdminOnly := []int{0}
	adminRoles := []int{0, 2}

	// Health check routes (no auth required)
	e.GET("/v2/health", health.HealthHandler)
	e.GET("/v2/health/live", health.LivenessHandler)
	e.GET("/v2/health/ready", health.ReadinessHandler)
	e.GET("/v2/health/stats", health.StatsHandler)

	// Auth routes (new refresh token flow)
	e.POST("/login", auth.LoginHandler)
	e.POST("/token/refresh", auth.RefreshTokenHandler)
	e.POST("/logout", auth.LogoutHandler, middleware.JWTMiddleware)
	e.GET("/health", email.DatabaseHealthCheckHandler)

	// Legacy login route (for backward compatibility) - uses same handler as /login
	e.POST("/user/login", auth.LoginHandler)
	e.POST("/user/init_admin", user.CreateInitUserAdminHandler)

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
	domainGroup.POST("/update/staging", domain.UpdateStagingDomainsHandler, middleware.RoleMiddleware(superAdminOnly))
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
	userGroup.GET("/get_user_me", user.GetUserMeHandler) // Must be before /:id
	userGroup.GET("/", user.ListUsersHandler, middleware.RoleMiddleware(adminRoles), middleware.AdminPermissionMiddleware("user_list"))
	userGroup.GET("/admin", user.ListAdminUsersHandler, middleware.RoleMiddleware(superAdminOnly))
	userGroup.GET("/:id", user.GetUserHandler, middleware.RoleMiddleware(adminRoles), middleware.AdminPermissionMiddleware("user_list")) // Parameterized route last
	userGroup.DELETE("/admin/:id", user.DeleteUserAdminHandler, middleware.RoleMiddleware(superAdminOnly))
	userGroup.DELETE("/:id", user.DeleteUserHandler, middleware.RoleMiddleware(adminRoles), middleware.AdminPermissionMiddleware("user_list"))

	// Email routes
	emailGroup := e.Group("/email", middleware.JWTMiddleware)
	emailGroup.POST("/upload/attachment", email.UploadAttachmentHandler)
	emailGroup.GET("/by_user", email.ListEmailByTokenHandler)
	emailGroup.GET("/by_user/detail/:id", email.GetEmailHandler)
	emailGroup.POST("/by_user/download/file", email.GetFileEmailToDownloadHandler)
	emailGroup.GET("/by_user/:id", email.ListEmailByIDHandler, middleware.RoleMiddleware(adminRoles))
	emailGroup.GET("/sent/by_user", email.SentEmailByIDHandler)
	emailGroup.GET("/sent/by_user/:id", email.ListSentEmailsByUserIDHandler, middleware.RoleMiddleware(adminRoles), middleware.AdminPermissionMiddleware("all_sent")) // Admin: list sent emails by user
	emailGroup.GET("/sent/list", email.GetUserSentEmailsHandler)                                                                                                      // User's own sent emails list
	emailGroup.GET("/sent/detail/:id", email.GetUserSentEmailDetailHandler)                                                                                           // User's own sent email detail
	emailGroup.GET("/sent", email.GetUserSentEmailsHandler)                                                                                                           // User's own sent emails
	emailGroup.GET("/quota", email.GetEmailQuotaHandler)
	emailGroup.POST("/send", email.SendEmailHandler)
	emailGroup.POST("/send/resend", email.SendEmailViaResendHandler)
	emailGroup.POST("/send/smtp", email.SendEmailSMTPHandler)
	emailGroup.POST("/send/test/haraka", email.SendEmailSMTPHHandler)
	emailGroup.POST("/send/url_attachment", email.SendEmailUrlAttachmentHandler)
	emailGroup.POST("/delete-attachment", email.DeleteUrlAttachmentHandler)
	emailGroup.GET("/bucket/sync", email.SyncBucketInboxHandler, middleware.RoleMiddleware(adminRoles))
	emailGroup.GET("/", email.ListEmailsHandler, middleware.RoleMiddleware(adminRoles))
	emailGroup.GET("/:id", email.GetEmailHandler, middleware.RoleMiddleware(adminRoles))       // Wildcard route - must be last
	emailGroup.DELETE("/:id", email.DeleteEmailHandler, middleware.RoleMiddleware(adminRoles)) // Wildcard route - must be last

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
	adminGroup.GET("/permissions", admin.GetPermissionsHandler, middleware.AdminPermissionMiddleware("roles_permissions"))
	adminGroup.PUT("/permissions/:role_id", admin.UpdatePermissionsHandler, middleware.AdminPermissionMiddleware("roles_permissions"))

	// Admin user management (Roles & Permissions page)
	adminGroup.GET("/admins", admin.ListAdminsHandler, middleware.AdminPermissionMiddleware("roles_permissions"))
	adminGroup.GET("/admins/:id", admin.GetAdminHandler, middleware.AdminPermissionMiddleware("roles_permissions"))
	adminGroup.POST("/admins", admin.CreateAdminHandler, middleware.AdminPermissionMiddleware("roles_permissions"))
	adminGroup.PUT("/admins/:id", admin.UpdateAdminHandler, middleware.AdminPermissionMiddleware("roles_permissions"))
	adminGroup.DELETE("/admins/:id", admin.DeleteAdminHandler, middleware.AdminPermissionMiddleware("roles_permissions"))
}
