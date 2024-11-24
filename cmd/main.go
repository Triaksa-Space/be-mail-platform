package main

import (
	"email-platform/config"
	"email-platform/domain/user"

	"github.com/labstack/echo/v4"
)

func main() {
	config.InitConfig()
	config.InitDB()
	e := echo.New()

	// User routes
	e.POST("/user/login", user.LoginHandler)
	// e.POST("/user/logout", user.LogoutHandler)
	// e.PUT("/user/change_password", user.ChangePasswordHandler)
	// e.POST("/user", user.CreateUserHandler)
	// e.POST("/user/bulk", user.BulkCreateUserHandler)
	// e.DELETE("/user/:id", user.DeleteUserHandler)

	// // Email routes
	// emailGroup := e.Group("/email")
	// emailGroup.POST("/", email.SendEmailHandler)
	// emailGroup.GET("/:id", email.GetEmailHandler)
	// emailGroup.GET("/", email.ListEmailsHandler)
	// emailGroup.DELETE("/:id", email.DeleteEmailHandler)

	e.Logger.Fatal(e.Start(":8080"))
}
