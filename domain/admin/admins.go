package admin

import (
	"database/sql"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Triaksa-Space/be-mail-platform/config"
	"github.com/Triaksa-Space/be-mail-platform/utils"
	"github.com/labstack/echo/v4"
)

// Valid permission keys
var ValidPermissions = map[string]bool{
	"overview":           true,
	"user_list":          true,
	"create_single":      true,
	"create_bulk":        true,
	"all_inbox":          true,
	"all_sent":           true,
	"terms_of_services":  true,
	"privacy_policy":     true,
	"roles_permissions":  true,
}

// AdminUser represents an admin user for the API response
type AdminUser struct {
	ID           string     `json:"id"`
	Username     string     `json:"username"`
	Password     string     `json:"password,omitempty"`
	LastActiveAt *time.Time `json:"last_active_at"`
	IsOnline     bool       `json:"is_online"`
	Permissions  []string   `json:"permissions"`
	CreatedAt    time.Time  `json:"created_at"`
}

// AdminUserDB represents an admin user from the database
type AdminUserDB struct {
	ID                int64            `db:"id"`
	Email             string           `db:"email"`
	EncryptedPassword sql.NullString   `db:"encrypted_password"`
	LastLogin         sql.NullTime     `db:"last_login"`
	CreatedAt         time.Time        `db:"created_at"`
}

// ListAdminsResponse represents the list admins API response
type ListAdminsResponse struct {
	Data []AdminUser       `json:"data"`
	Meta PaginationMeta    `json:"meta"`
}

// PaginationMeta represents pagination metadata
type PaginationMeta struct {
	Page       int `json:"page"`
	Limit      int `json:"limit"`
	TotalItems int `json:"total_items"`
	TotalPages int `json:"total_pages"`
}

// CreateAdminRequest represents the create admin request
type CreateAdminRequest struct {
	Username    string   `json:"username"`
	Password    string   `json:"password"`
	Permissions []string `json:"permissions"`
}

// UpdateAdminRequest represents the update admin request
type UpdateAdminRequest struct {
	Username    string   `json:"username,omitempty"`
	Password    string   `json:"password,omitempty"`
	Permissions []string `json:"permissions"`
}

// ListAdminsHandler returns a list of admin users
// GET /api/admins
func ListAdminsHandler(c echo.Context) error {
	roleID := c.Get("role_id").(int64)
	userID := c.Get("user_id").(int64)
	if roleID != 0 && !HasPermission(userID, "roles_permissions") {
		return c.JSON(http.StatusForbidden, map[string]string{
			"error": "Access denied.",
		})
	}

	// Parse query params
	page, _ := strconv.Atoi(c.QueryParam("page"))
	if page < 1 {
		page = 1
	}

	limit, _ := strconv.Atoi(c.QueryParam("limit"))
	if limit < 1 {
		limit = 10
	}
	if limit > 100 {
		limit = 100
	}

	offset := (page - 1) * limit

	searchQuery := strings.TrimSpace(c.QueryParam("q"))
	sortBy := c.QueryParam("sort_by")
	sortDir := c.QueryParam("sort_dir")

	// Validate sort_by
	validSortColumns := map[string]string{
		"username":       "email",
		"last_active_at": "last_login",
		"created_at":     "created_at",
	}
	sortColumn, ok := validSortColumns[sortBy]
	if !ok {
		sortColumn = "created_at"
	}

	// Validate sort_dir
	if sortDir != "asc" && sortDir != "desc" {
		sortDir = "desc"
	}

	// Build query
	var args []interface{}
	whereClause := "role_id = 2" // Admin role

	if searchQuery != "" {
		whereClause += " AND email LIKE ?"
		args = append(args, "%"+searchQuery+"%")
	}

	// Get total count
	var totalItems int
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM users WHERE %s", whereClause)
	err := config.DB.Get(&totalItems, countQuery, args...)
	if err != nil {
		fmt.Println("Error counting admins:", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
	}

	// Get admins
	args = append(args, limit, offset)
	query := fmt.Sprintf(`
		SELECT id, email, last_login, created_at
		FROM users
		WHERE %s
		ORDER BY %s %s
		LIMIT ? OFFSET ?
	`, whereClause, sortColumn, sortDir)

	var admins []AdminUserDB
	err = config.DB.Select(&admins, query, args...)
	if err != nil {
		fmt.Println("Error fetching admins:", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
	}

	// Build response with permissions
	data := make([]AdminUser, 0, len(admins))
	for _, admin := range admins {
		// Get permissions for this admin
		permissions, _ := getAdminPermissions(admin.ID)

		// Check if online (active in last 15 minutes)
		isOnline := false
		var lastActiveAt *time.Time
		if admin.LastLogin.Valid {
			lastActiveAt = &admin.LastLogin.Time
			isOnline = time.Since(admin.LastLogin.Time) < 15*time.Minute
		}

		data = append(data, AdminUser{
			ID:           utils.EncodeID(int(admin.ID)),
			Username:     admin.Email,
			LastActiveAt: lastActiveAt,
			IsOnline:     isOnline,
			Permissions:  permissions,
			CreatedAt:    admin.CreatedAt,
		})
	}

	totalPages := (totalItems + limit - 1) / limit

	return c.JSON(http.StatusOK, ListAdminsResponse{
		Data: data,
		Meta: PaginationMeta{
			Page:       page,
			Limit:      limit,
			TotalItems: totalItems,
			TotalPages: totalPages,
		},
	})
}

// GetAdminHandler returns a single admin user
// GET /api/admins/:id
func GetAdminHandler(c echo.Context) error {
	roleID := c.Get("role_id").(int64)
	userID := c.Get("user_id").(int64)
	if roleID != 0 && !HasPermission(userID, "roles_permissions") {
		return c.JSON(http.StatusForbidden, map[string]string{
			"error": "Access denied.",
		})
	}

	// Decode admin ID
	adminIDParam := c.Param("id")
	adminID, err := utils.DecodeID(adminIDParam)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid admin ID",
		})
	}

	// Get admin from database
	var admin AdminUserDB
	err = config.DB.Get(&admin, `
		SELECT id, email, encrypted_password, last_login, created_at
		FROM users
		WHERE id = ? AND role_id = 2
	`, adminID)

	if err != nil {
		if err == sql.ErrNoRows {
			return c.JSON(http.StatusNotFound, map[string]string{
				"error": "Admin not found",
			})
		}
		fmt.Println("Error fetching admin:", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
	}

	// Get permissions
	permissions, _ := getAdminPermissions(admin.ID)

	// Check if online
	isOnline := false
	var lastActiveAt *time.Time
	if admin.LastLogin.Valid {
		lastActiveAt = &admin.LastLogin.Time
		isOnline = time.Since(admin.LastLogin.Time) < 15*time.Minute
	}

	// Decrypt password for SuperAdmin viewing
	var decryptedPassword string
	if admin.EncryptedPassword.Valid {
		decryptedPassword, _ = utils.DecryptAES(admin.EncryptedPassword.String)
	}

	return c.JSON(http.StatusOK, AdminUser{
		ID:           utils.EncodeID(int(admin.ID)),
		Username:     admin.Email,
		Password:     decryptedPassword,
		LastActiveAt: lastActiveAt,
		IsOnline:     isOnline,
		Permissions:  permissions,
		CreatedAt:    admin.CreatedAt,
	})
}

// CreateAdminHandler creates a new admin user
// POST /api/admins
func CreateAdminHandler(c echo.Context) error {
	roleID := c.Get("role_id").(int64)
	userID := c.Get("user_id").(int64)
	if roleID != 0 && !HasPermission(userID, "roles_permissions") {
		return c.JSON(http.StatusForbidden, map[string]string{
			"error": "Access denied.",
		})
	}

	// Get superadmin email for audit
	var creatorEmail string
	config.DB.Get(&creatorEmail, "SELECT email FROM users WHERE id = ?", userID)

	req := new(CreateAdminRequest)
	if err := c.Bind(req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	// Validate request
	if req.Username == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Username is required",
		})
	}
	if req.Password == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Password is required",
		})
	}
	if len(req.Password) < 6 {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Password must be at least 6 characters",
		})
	}

	// Validate permissions
	for _, perm := range req.Permissions {
		if !ValidPermissions[perm] {
			return c.JSON(http.StatusBadRequest, map[string]string{
				"error": fmt.Sprintf("Invalid permission: %s", perm),
			})
		}
	}

	// Check if username already exists
	var exists bool
	config.DB.Get(&exists, "SELECT EXISTS(SELECT 1 FROM users WHERE email = ?)", req.Username)
	if exists {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Username already exists",
		})
	}

	// Hash password
	hashedPassword, err := utils.HashPassword(req.Password)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
	}

	// Encrypt password for SuperAdmin viewing
	encryptedPassword, err := utils.EncryptAES(req.Password)
	if err != nil {
		fmt.Println("Error encrypting password:", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
	}

	// Start transaction
	tx, err := config.DB.Begin()
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
	}
	defer tx.Rollback()

	// Insert admin user
	result, err := tx.Exec(`
		INSERT INTO users (email, password, encrypted_password, role_id, created_at, updated_at, created_by, created_by_name, updated_by, updated_by_name)
		VALUES (?, ?, ?, 2, NOW(), NOW(), ?, ?, ?, ?)
	`, req.Username, hashedPassword, encryptedPassword, userID, creatorEmail, userID, creatorEmail)

	if err != nil {
		fmt.Println("Error creating admin:", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to create admin"})
	}

	newAdminID, _ := result.LastInsertId()

	// Insert permissions
	for _, perm := range req.Permissions {
		_, err = tx.Exec(`
			INSERT INTO admin_permissions (user_id, permission_key, created_at)
			VALUES (?, ?, NOW())
		`, newAdminID, perm)
		if err != nil {
			fmt.Println("Error inserting permission:", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
	}

	// Get created_at
	var createdAt time.Time
	config.DB.Get(&createdAt, "SELECT created_at FROM users WHERE id = ?", newAdminID)

	return c.JSON(http.StatusCreated, map[string]interface{}{
		"id":          utils.EncodeID(int(newAdminID)),
		"username":    req.Username,
		"permissions": req.Permissions,
		"created_at":  createdAt,
	})
}

// UpdateAdminHandler updates an existing admin user
// PUT /api/admins/:id
func UpdateAdminHandler(c echo.Context) error {
	roleID := c.Get("role_id").(int64)
	userID := c.Get("user_id").(int64)
	if roleID != 0 && !HasPermission(userID, "roles_permissions") {
		return c.JSON(http.StatusForbidden, map[string]string{
			"error": "Access denied.",
		})
	}

	// Decode admin ID
	adminIDParam := c.Param("id")
	adminID, err := utils.DecodeID(adminIDParam)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid admin ID",
		})
	}

	// Check if admin exists
	var existingAdmin AdminUserDB
	err = config.DB.Get(&existingAdmin, `
		SELECT id, email, created_at
		FROM users
		WHERE id = ? AND role_id = 2
	`, adminID)

	if err != nil {
		if err == sql.ErrNoRows {
			return c.JSON(http.StatusNotFound, map[string]string{
				"error": "Admin not found",
			})
		}
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
	}

	req := new(UpdateAdminRequest)
	if err := c.Bind(req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	// Validate permissions (required)
	if req.Permissions == nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Permissions are required",
		})
	}

	for _, perm := range req.Permissions {
		if !ValidPermissions[perm] {
			return c.JSON(http.StatusBadRequest, map[string]string{
				"error": fmt.Sprintf("Invalid permission: %s", perm),
			})
		}
	}

	// Start transaction
	tx, err := config.DB.Begin()
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
	}
	defer tx.Rollback()

	// Update username if provided
	username := existingAdmin.Email
	if req.Username != "" && req.Username != existingAdmin.Email {
		// Check if new username already exists
		var exists bool
		config.DB.Get(&exists, "SELECT EXISTS(SELECT 1 FROM users WHERE email = ? AND id != ?)", req.Username, adminID)
		if exists {
			return c.JSON(http.StatusBadRequest, map[string]string{
				"error": "Username already exists",
			})
		}

		_, err = tx.Exec("UPDATE users SET email = ?, updated_at = NOW() WHERE id = ?", req.Username, adminID)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to update username"})
		}
		username = req.Username
	}

	// Update password if provided
	if req.Password != "" {
		if len(req.Password) < 6 {
			return c.JSON(http.StatusBadRequest, map[string]string{
				"error": "Password must be at least 6 characters",
			})
		}

		hashedPassword, err := utils.HashPassword(req.Password)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
		}

		encryptedPassword, err := utils.EncryptAES(req.Password)
		if err != nil {
			fmt.Println("Error encrypting password:", err)
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
		}

		_, err = tx.Exec("UPDATE users SET password = ?, encrypted_password = ?, updated_at = NOW() WHERE id = ?", hashedPassword, encryptedPassword, adminID)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to update password"})
		}
	}

	// Update permissions - delete all and re-insert
	_, err = tx.Exec("DELETE FROM admin_permissions WHERE user_id = ?", adminID)
	if err != nil {
		fmt.Println("Error deleting permissions:", err)
	}

	for _, perm := range req.Permissions {
		_, err = tx.Exec(`
			INSERT INTO admin_permissions (user_id, permission_key, created_at)
			VALUES (?, ?, NOW())
		`, adminID, perm)
		if err != nil {
			fmt.Println("Error inserting permission:", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"id":          utils.EncodeID(adminID),
		"username":    username,
		"permissions": req.Permissions,
		"created_at":  existingAdmin.CreatedAt,
	})
}

// DeleteAdminHandler deletes an admin user
// DELETE /api/admins/:id
func DeleteAdminHandler(c echo.Context) error {
	roleID := c.Get("role_id").(int64)
	userID := c.Get("user_id").(int64)
	if roleID != 0 && !HasPermission(userID, "roles_permissions") {
		return c.JSON(http.StatusForbidden, map[string]string{
			"error": "Access denied.",
		})
	}

	// Decode admin ID
	adminIDParam := c.Param("id")
	adminID, err := utils.DecodeID(adminIDParam)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid admin ID",
		})
	}

	// Check if admin exists
	var exists bool
	err = config.DB.Get(&exists, "SELECT EXISTS(SELECT 1 FROM users WHERE id = ? AND role_id = 2)", adminID)
	if err != nil || !exists {
		return c.JSON(http.StatusNotFound, map[string]string{
			"error": "Admin not found",
		})
	}

	// Start transaction
	tx, err := config.DB.Begin()
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
	}
	defer tx.Rollback()

	// Delete permissions first (foreign key constraint)
	_, err = tx.Exec("DELETE FROM admin_permissions WHERE user_id = ?", adminID)
	if err != nil {
		fmt.Println("Error deleting permissions:", err)
	}

	// Delete admin user
	_, err = tx.Exec("DELETE FROM users WHERE id = ? AND role_id = 2", adminID)
	if err != nil {
		fmt.Println("Error deleting admin:", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to delete admin"})
	}

	if err := tx.Commit(); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
	}

	return c.JSON(http.StatusOK, map[string]string{
		"message": "Admin deleted successfully",
	})
}

// getAdminPermissions returns permissions for an admin user
func getAdminPermissions(userID int64) ([]string, error) {
	var permissions []string
	err := config.DB.Select(&permissions, `
		SELECT permission_key
		FROM admin_permissions
		WHERE user_id = ?
		ORDER BY permission_key
	`, userID)

	if err != nil {
		return []string{}, err
	}

	return permissions, nil
}

// HasPermission checks if an admin has a specific permission
func HasPermission(userID int64, permission string) bool {
	var exists bool
	err := config.DB.Get(&exists, `
		SELECT EXISTS(
			SELECT 1 FROM admin_permissions
			WHERE user_id = ? AND permission_key = ?
		)
	`, userID, permission)

	return err == nil && exists
}
