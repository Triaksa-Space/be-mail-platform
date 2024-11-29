package user

import (
	"email-platform/config"
	"email-platform/utils"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/labstack/echo/v4"
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
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": err.Error()})
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

	tx, err := config.DB.Begin()
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	defer tx.Rollback()

	// Prepare statements
	userStmt, err := tx.Prepare(`
        INSERT INTO users (email, password, role_id, created_at, updated_at) 
        VALUES (?, ?, 1, NOW(), NOW())
    `)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	defer userStmt.Close()

	emailStmt, err := tx.Prepare(`
        INSERT INTO generated_emails (username, created_at, updated_at) 
        VALUES (?, NOW(), NOW())
    `)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	defer emailStmt.Close()

	createdUsers := []map[string]string{}

	for i, user := range req.Users {
		hashedPassword, err := utils.HashPassword(user.Password)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}

		// Insert user
		_, err = userStmt.Exec(user.Email, hashedPassword)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}

		// Insert generated email
		_, err = emailStmt.Exec(user.Email)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}

		// Collect created user data
		createdUsers = append(createdUsers, map[string]string{
			"No":       fmt.Sprintf("%d", i+1),
			"Email":    user.Email,
			"Password": user.Password,
		})
	}

	if err := tx.Commit(); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	return c.JSON(http.StatusCreated, map[string]interface{}{
		"message": fmt.Sprintf("%d users created successfully", len(req.Users)),
		"users":   createdUsers,
	})
}

// ONLY ADMIN CAN DELETE USER
func DeleteUserHandler(c echo.Context) error {
	userID := c.Param("id")

	// Delete the email first from the database
	resultEmail, err := config.DB.Exec("DELETE FROM emails WHERE user_id = ?", userID)
	if err != nil {
		fmt.Println("err email", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	rowsEmailAffected, err := resultEmail.RowsAffected()
	if err != nil || rowsEmailAffected == 0 {
		return c.JSON(http.StatusNotFound, map[string]string{"error": err.Error()})
	}

	// Delete the user from the database
	result, err := config.DB.Exec("DELETE FROM users WHERE role_id = 1 AND id = ?", userID)
	if err != nil {
		fmt.Println("err user", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil || rowsAffected == 0 {
		return c.JSON(http.StatusNotFound, map[string]string{"error": err.Error()})
	}

	return c.JSON(http.StatusOK, map[string]string{"message": "User deleted successfully"})
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
