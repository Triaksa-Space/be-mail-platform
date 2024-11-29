package domain

import (
	"email-platform/config"
	"fmt"
	"net/http"

	"github.com/labstack/echo/v4"
)

func GetDropdownDomainHandler(c echo.Context) error {
	// Fetch all domains
	var domains []DomainEmail
	err := config.DB.Select(&domains, `SELECT id, domain, created_at, updated_at FROM domains`)
	if err != nil {
		fmt.Println("error fetching domains", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to fetch domains"})
	}

	return c.JSON(http.StatusOK, domains)
}
