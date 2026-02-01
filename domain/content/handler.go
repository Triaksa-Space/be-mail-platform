package content

import (
	"database/sql"
	"fmt"
	"net/http"

	"github.com/Triaksa-Space/be-mail-platform/config"
	"github.com/labstack/echo/v4"
	"github.com/microcosm-cc/bluemonday"
)

// GetTermsHandler returns the terms of service content
func GetTermsHandler(c echo.Context) error {
	return getContentByKey(c, ContentKeyTerms)
}

// GetPrivacyHandler returns the privacy policy content
func GetPrivacyHandler(c echo.Context) error {
	return getContentByKey(c, ContentKeyPrivacy)
}

// getContentByKey retrieves content by its key
func getContentByKey(c echo.Context, key string) error {
	var content AppContent
	err := config.DB.Get(&content, `
		SELECT id, content_key, content_html, version, updated_at
		FROM app_contents
		WHERE content_key = ?
	`, key)

	if err != nil {
		if err == sql.ErrNoRows {
			return c.JSON(http.StatusNotFound, map[string]string{
				"error":   "not_found",
				"message": "Content not found",
			})
		}
		fmt.Println("Error fetching content:", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
	}

	response := ContentResponse{
		Content:   content.ContentHTML,
		Version:   content.Version,
		UpdatedAt: content.UpdatedAt,
	}

	return c.JSON(http.StatusOK, response)
}

// UpdateContentHandler updates content by key (admin only)
func UpdateContentHandler(c echo.Context) error {
	key := c.Param("key")

	// Validate content key
	if !ValidContentKeys[key] {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error":   "invalid_key",
			"message": "Invalid content key. Valid keys are: terms, privacy",
		})
	}

	userID := c.Get("user_id").(int64)
	roleID := c.Get("role_id").(int64)

	// Check permission based on key (SuperAdmin bypasses)
	if roleID != 0 {
		// Map content key to permission
		permissionMap := map[string]string{
			"terms":   "terms_of_services",
			"privacy": "privacy_policy",
		}

		requiredPermission := permissionMap[key]
		if requiredPermission != "" {
			var hasPermission bool
			err := config.DB.Get(&hasPermission, `
				SELECT EXISTS(
					SELECT 1 FROM admin_permissions
					WHERE user_id = ? AND permission_key = ?
				)
			`, userID, requiredPermission)

			if err != nil || !hasPermission {
				return c.JSON(http.StatusForbidden, map[string]string{
					"error":   "forbidden",
					"message": "You don't have permission to edit this content",
				})
			}
		}
	}

	// Get admin email for audit
	var adminEmail string
	err := config.DB.Get(&adminEmail, "SELECT email FROM users WHERE id = ?", userID)
	if err != nil {
		fmt.Println("Error fetching admin email:", err)
		adminEmail = "unknown"
	}

	req := new(UpdateContentRequest)
	if err := c.Bind(req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	if req.Content == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error":   "validation_error",
			"message": "Content cannot be empty",
		})
	}

	// Sanitize HTML content using bluemonday
	sanitizedContent := sanitizeHTML(req.Content)

	// Update the content and increment version
	result, err := config.DB.Exec(`
		UPDATE app_contents
		SET content_html = ?,
		    version = version + 1,
		    updated_by = ?,
		    updated_by_name = ?,
		    updated_at = NOW()
		WHERE content_key = ?
	`, sanitizedContent, userID, adminEmail, key)

	if err != nil {
		fmt.Println("Error updating content:", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		// Content doesn't exist, insert it
		_, err = config.DB.Exec(`
			INSERT INTO app_contents (content_key, content_html, version, updated_by, updated_by_name)
			VALUES (?, ?, 1, ?, ?)
		`, key, sanitizedContent, userID, adminEmail)
		if err != nil {
			fmt.Println("Error inserting content:", err)
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
		}
	}

	// Get the updated content
	var updatedContent AppContent
	err = config.DB.Get(&updatedContent, `
		SELECT version, updated_at
		FROM app_contents
		WHERE content_key = ?
	`, key)
	if err != nil {
		fmt.Println("Error fetching updated content:", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"message":    "Content updated successfully",
		"version":    updatedContent.Version,
		"updated_at": updatedContent.UpdatedAt,
	})
}

// sanitizeHTML sanitizes HTML content to prevent XSS attacks
func sanitizeHTML(content string) string {
	// Use UGCPolicy for TinyMCE/rich text editor content
	// This allows common formatting while removing dangerous elements
	p := bluemonday.UGCPolicy()

	// Allow additional elements commonly used in rich text editors
	p.AllowElements("h1", "h2", "h3", "h4", "h5", "h6")
	p.AllowAttrs("style").OnElements("p", "span", "div", "h1", "h2", "h3", "h4", "h5", "h6", "table", "tr", "td", "th")
	p.AllowAttrs("class").OnElements("p", "span", "div", "h1", "h2", "h3", "h4", "h5", "h6", "ul", "ol", "li", "table", "tr", "td", "th")

	// Allow table elements
	p.AllowElements("table", "thead", "tbody", "tr", "th", "td")
	p.AllowAttrs("border", "cellpadding", "cellspacing").OnElements("table")

	// Allow list elements
	p.AllowElements("ul", "ol", "li")

	// Allow text formatting
	p.AllowElements("strong", "em", "u", "s", "sub", "sup", "blockquote", "pre", "code")

	// Allow links with target attribute
	p.AllowAttrs("href", "target", "rel").OnElements("a")
	p.AllowRelativeURLs(true)

	// Allow images with common attributes
	p.AllowAttrs("src", "alt", "title", "width", "height").OnElements("img")

	return p.Sanitize(content)
}
