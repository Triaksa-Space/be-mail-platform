package user

import (
	"email-platform/utils"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func LoginHandler(c echo.Context) error {
	req := new(LoginRequest)
	if err := c.Bind(req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request"})
	}

	// Authenticate user
	var user User
	err := utils.DB.Get(&user, "SELECT * FROM users WHERE email = $1", req.Email)
	if err != nil || !utils.CheckPasswordHash(req.Password, user.Password) {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
	}

	// Update last_login field
	_, err = utils.DB.Exec("UPDATE users SET last_login = $1 WHERE id = $2", time.Now(), user.ID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to update last login"})
	}

	// Generate JWT token
	token, err := utils.GenerateJWT(user.ID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to generate token"})
	}

	return c.JSON(http.StatusOK, map[string]string{"token": token})
}

func LogoutHandler(c echo.Context) error {
	// Simply return a successful response
	return c.JSON(http.StatusOK, map[string]string{"message": "Logout successful"})
}

func ChangePasswordHandler(c echo.Context) error {
	userID := c.Get("user_id").(string) // Assuming JWT middleware sets "user_id" in the context

	// Bind request body
	req := new(ChangePasswordRequest)
	if err := c.Bind(req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request"})
	}

	// Validate new password length
	if len(req.NewPassword) < 6 {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "password must be at least 6 characters"})
	}

	// Fetch user from the database
	var user User
	err := utils.DB.Get(&user, "SELECT * FROM users WHERE id = $1", userID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "user not found"})
	}

	// Check old password
	if !utils.CheckPasswordHash(req.OldPassword, user.Password) {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "old password is incorrect"})
	}

	// Hash the new password
	hashedPassword, err := utils.HashPassword(req.NewPassword)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to hash new password"})
	}

	// Update the password in the database
	_, err = utils.DB.Exec("UPDATE users SET password = $1, updated_at = NOW() WHERE id = $2", hashedPassword, userID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to update password"})
	}

	return c.JSON(http.StatusOK, map[string]string{"message": "Password updated successfully"})
}

func CreateUserHandler(c echo.Context) error {
	req := new(CreateUserRequest)
	if err := c.Bind(req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request"})
	}

	// Validate the request
	if err := c.Validate(req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	// Check if the user already exists
	var existingUser User
	err := utils.DB.Get(&existingUser, "SELECT * FROM users WHERE email = $1", req.Email)
	if err == nil {
		return c.JSON(http.StatusConflict, map[string]string{"error": "user already exists"})
	}

	// Hash the password
	hashedPassword, err := utils.HashPassword(req.Password)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to hash password"})
	}

	// Insert the new user into the database
	userID := uuid.New().String()
	_, err = utils.DB.Exec(
		"INSERT INTO users (id, email, password, created_at, updated_at) VALUES ($1, $2, $3, $4, $5)",
		userID, req.Email, hashedPassword, time.Now(), time.Now(),
	)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to create user"})
	}

	return c.JSON(http.StatusCreated, map[string]string{"message": "user created successfully", "user_id": userID})
}

func DeleteUserHandler(c echo.Context) error {
	userID := c.Param("id")

	// Check if the user exists
	var existingUser User
	err := utils.DB.Get(&existingUser, "SELECT * FROM users WHERE id = $1", userID)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "user not found"})
	}

	// Delete the user from the database
	_, err = utils.DB.Exec("DELETE FROM users WHERE id = $1", userID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to delete user"})
	}

	return c.JSON(http.StatusOK, map[string]string{"message": "user deleted successfully"})
}
