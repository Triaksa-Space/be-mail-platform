package user

import (
	"email-platform/config"
	"email-platform/pkg"
	"email-platform/utils"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/spf13/viper"
)

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func LoginHandler(c echo.Context) error {
	req := new(LoginRequest)
	if err := c.Bind(req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	var user User
	err := config.DB.Get(&user, "SELECT * FROM users WHERE email = ?", req.Email)
	if err != nil || !utils.CheckPasswordHash(req.Password, user.Password) {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": err.Error()})
	}

	token, err := utils.GenerateJWT(user.ID, user.Email)
	if err != nil {
		fmt.Println("GenerateJWT", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	// Update last login
	_, _ = config.DB.Exec("UPDATE users SET last_login = ? WHERE id = ?", time.Now(), user.ID)

	return c.JSON(http.StatusOK, map[string]string{"token": token})
}

func LogoutHandler(c echo.Context) error {
	// Assuming JWT middleware has already validated the token
	return c.JSON(http.StatusOK, map[string]string{"message": "Logout successful"})
}

func ChangePasswordHandler(c echo.Context) error {
	// Extract user ID from JWT (set by JWT middleware)
	userID := c.Get("user_id").(int64)

	// Bind request body
	req := new(ChangePasswordRequest)
	if err := c.Bind(req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	// Fetch user data from the database
	var hashedPassword string
	err := config.DB.Get(&hashedPassword, "SELECT password FROM users WHERE id = ?", userID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	// Check if the old password is correct
	if !utils.CheckPasswordHash(req.OldPassword, hashedPassword) {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "The password you entered is incorrect."})
	}

	// Hash the new password
	newHashedPassword, err := utils.HashPassword(req.NewPassword)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	// Update the user's password in the database
	_, err = config.DB.Exec("UPDATE users SET password = ?, updated_at = NOW() WHERE id = ?", newHashedPassword, userID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	return c.JSON(http.StatusOK, map[string]string{"message": "Password updated successfully"})
}

func CreateUserHandler(c echo.Context) error {
	req := new(CreateUserRequest)
	if err := c.Bind(req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	// if err := c.Validate(req); err != nil {
	// 	return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	// }

	// Hash the password
	hashedPassword, err := utils.HashPassword(req.Password)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	// Insert the user into the database
	_, err = config.DB.Exec(
		"INSERT INTO users (email, password, role_id, created_at, updated_at) VALUES (?, ?, ?, NOW(), NOW())",
		req.Email, hashedPassword, 1, // Hardcoded role ID for now
	)
	if err != nil {
		fmt.Println("ERROR", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	// Insert into table generated_email
	_, err = config.DB.Exec(
		"INSERT INTO generated_emails (username, created_at, updated_at) VALUES (?, NOW(), NOW())",
		req.Email, // Hardcoded role ID for now
	)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	// Initialize AWS session
	sess, _ := pkg.InitAWS()

	// Create S3 client
	s3Client, _ := pkg.InitS3(sess)

	err = pkg.CreateBucketFolderEmailUser(s3Client, req.Email)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	return c.JSON(http.StatusCreated, map[string]string{"message": "User created successfully"})
}

func BulkCreateUserHandler(c echo.Context) error {
	req := new(BulkCreateUserRequest)
	if err := c.Bind(req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	if len(req.Users) == 0 {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "No users provided"})
	}

	createdUsers := []map[string]string{}
	skippedUsers := []map[string]string{}

	for i, user := range req.Users {
		// Check if user exists
		var exists bool
		err := config.DB.Get(&exists, "SELECT EXISTS(SELECT 1 FROM users WHERE email = ?)", user.Email)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}

		if exists {
			skippedUsers = append(skippedUsers, map[string]string{
				"No":    fmt.Sprintf("%d", i+1),
				"Email": user.Email,
			})
			continue
		}

		// Start transaction for this user
		tx, err := config.DB.Begin()
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}
		defer tx.Rollback()

		hashedPassword, err := utils.HashPassword(user.Password)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}

		// Insert user
		_, err = tx.Exec(
			"INSERT INTO users (email, password, role_id, created_at, updated_at) VALUES (?, ?, 1, NOW(), NOW())",
			user.Email, hashedPassword,
		)
		if err != nil {
			continue
		}

		// Insert generated email
		_, err = tx.Exec(
			"INSERT INTO generated_emails (username, created_at, updated_at) VALUES (?, NOW(), NOW())",
			user.Email,
		)
		if err != nil {
			continue
		}

		// Initialize AWS session and create S3 folder
		sess, _ := pkg.InitAWS()
		s3Client, _ := pkg.InitS3(sess)
		err = pkg.CreateBucketFolderEmailUser(s3Client, user.Email)
		if err != nil {
			continue
		}

		// Commit transaction
		if err := tx.Commit(); err != nil {
			continue
		}

		// Collect created user data
		createdUsers = append(createdUsers, map[string]string{
			"No":       fmt.Sprintf("%d", i+1),
			"Email":    user.Email,
			"Password": user.Password,
		})
	}

	return c.JSON(http.StatusCreated, map[string]interface{}{
		"message":       fmt.Sprintf("%d users created successfully", len(createdUsers)),
		"created_users": createdUsers,
		"skipped_users": skippedUsers,
	})
}

// ONLY ADMIN CAN DELETE USER
func DeleteUserHandler(c echo.Context) error {
	userID := c.Param("id")

	// Get user email before deletion for S3
	var userEmail string
	err := config.DB.Get(&userEmail, "SELECT email FROM users WHERE id = ? AND role_id = 1", userID)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "User not found"})
	}

	// Start transaction
	tx, err := config.DB.Begin()
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to start transaction"})
	}
	defer tx.Rollback()

	// Delete emails
	_, err = tx.Exec("DELETE FROM emails WHERE user_id = ?", userID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to delete emails"})
	}

	// Delete user
	result, err := tx.Exec("DELETE FROM users WHERE id = ? AND role_id = 1", userID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to delete user"})
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "User not found"})
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to commit transaction"})
	}

	// Initialize AWS session
	sess, _ := pkg.InitAWS()
	s3Client, _ := pkg.InitS3(sess)

	// Delete S3 folder
	bucketName := viper.GetString("S3_BUCKET_NAME")
	prefix := fmt.Sprintf("%s/", userEmail)

	// List and delete all objects with the user's prefix
	err = pkg.DeleteS3FolderContents(s3Client, bucketName, prefix)
	if err != nil {
		fmt.Println("Failed to delete S3 folder:", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to delete user files"})
	}

	return c.JSON(http.StatusOK, map[string]string{"message": "User and associated data deleted successfully"})
}

func GetUserHandler(c echo.Context) error {
	userID := c.Param("id")

	// Fetch user details by ID
	var user User
	err := config.DB.Get(&user, "SELECT * FROM users WHERE role_id = 1 AND id = ?", userID)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": err.Error()})
	}

	return c.JSON(http.StatusOK, user)
}

func GetUserMeHandler(c echo.Context) error {
	// Extract user ID from JWT (set by JWT middleware)
	userID := c.Get("user_id").(int64)

	// Fetch user details by ID
	var user User
	err := config.DB.Get(&user, "SELECT * FROM users WHERE id = ?", userID)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": err.Error()})
	}

	return c.JSON(http.StatusOK, user)
}

func ListAdminUsersHandler(c echo.Context) error {
	searchUsername := c.QueryParam("username")
	// Fetch paginated users
	var users []User
	query := "SELECT * FROM users WHERE role_id = 0 "
	if searchUsername != "" {
		query = query + " AND email LIKE '%" + searchUsername + "%' "
	}
	query = query + " ORDER BY last_login DESC"
	err := config.DB.Select(&users,
		query)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	response := PaginatedUsers{
		Users: users,
	}

	return c.JSON(http.StatusOK, response)
}

func ListUsersHandler(c echo.Context) error {
	// Get pagination parameters
	page, _ := strconv.Atoi(c.QueryParam("page"))
	pageSize, _ := strconv.Atoi(c.QueryParam("page_size"))
	searchEmail := c.QueryParam("email")

	// Set defaults
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 10 // Default page size
	}

	// Calculate offset
	offset := (page - 1) * pageSize

	// Get total count
	var totalCount int
	err := config.DB.Get(&totalCount, "SELECT COUNT(*) FROM users WHERE role_id = 1")
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	// Fetch paginated users
	var users []User
	query := "SELECT * FROM users WHERE role_id = 1 "
	if searchEmail != "" {
		query = query + " AND email LIKE '%" + searchEmail + "%' "
	}
	query = query + " ORDER BY last_login DESC LIMIT ? OFFSET ?"
	err = config.DB.Select(&users,
		query,
		pageSize, offset)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	// Calculate total pages
	totalPages := (totalCount + pageSize - 1) / pageSize

	response := PaginatedUsers{
		Users:      users,
		TotalCount: totalCount,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	}

	return c.JSON(http.StatusOK, response)
}
