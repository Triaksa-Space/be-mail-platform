package main

import (
	"email-platform/config"
	"email-platform/routes"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

func main() {
	config.InitConfig()
	config.InitDB()
	e := echo.New()

	// Allow CORS from localhost:3000
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins:     []string{"http://localhost:3000"},                                                                // Allowed origin
		AllowMethods:     []string{echo.GET, echo.POST, echo.PUT, echo.DELETE, echo.OPTIONS},                               // Allowed HTTP methods
		AllowHeaders:     []string{echo.HeaderOrigin, echo.HeaderContentType, echo.HeaderAccept, echo.HeaderAuthorization}, // Allowed headers
		ExposeHeaders:    []string{echo.HeaderContentLength},                                                               // Headers exposed to the browser
		AllowCredentials: true,                                                                                             // Allow credentials such as cookies and authorization headers
		MaxAge:           86400,                                                                                            // Maximum time (in seconds) the browser should cache the preflight response
	}))

	routes.RegisterRoutes(e)

	e.Logger.Fatal(e.Start(":8080"))
}
