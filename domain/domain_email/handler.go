package domain

import (
	"email-platform/config"
	"net/http"

	"github.com/labstack/echo/v4"
)

func GetDropdownDomainHandler(c echo.Context) error {
	// Fetch email details by ID
	var domain []DomainEmail
	err := config.DB.Get(&domain, `SELECT 
			domain,
            created_at, 
            updated_at 
			FROM domains`)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "Domain not found"})
	}

	return c.JSON(http.StatusOK, domain)
}
