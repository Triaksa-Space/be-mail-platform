package domain

import (
	"fmt"
	"net/http"

	"github.com/Triaksa-Space/be-mail-platform/config"

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

func CreateDomainHandler(c echo.Context) error {
	req := new(CreateDomainRequest)
	if err := c.Bind(req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request payload"})
	}

	// Validate the request
	if err := c.Validate(req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	// Insert the domain into the database
	_, err := config.DB.Exec(
		"INSERT INTO domains (domain, created_at, updated_at) VALUES (?, NOW(), NOW())",
		req.Domain,
	)
	if err != nil {
		fmt.Println("Error inserting domain:", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to insert domain"})
	}

	return c.JSON(http.StatusCreated, map[string]string{"message": "Domain created successfully"})
}

func DeleteDomainHandler(c echo.Context) error {
	// Get the domain ID from the URL parameter
	domainID := c.Param("id")

	// Delete the domain from the database
	result, err := config.DB.Exec("DELETE FROM domains WHERE id = ?", domainID)
	if err != nil {
		fmt.Println("Error deleting domain:", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to delete domain"})
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to get affected rows"})
	}

	if rowsAffected == 0 {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "Domain not found"})
	}

	return c.JSON(http.StatusOK, map[string]string{"message": "Domain deleted successfully"})
}
