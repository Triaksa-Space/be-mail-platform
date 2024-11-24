package main

import (
	"email-platform/config"
	"email-platform/routes"

	"github.com/labstack/echo/v4"
)

func main() {
	config.InitConfig()
	config.InitDB()
	e := echo.New()

	routes.RegisterRoutes(e)

	e.Logger.Fatal(e.Start(":8080"))
}
