package user

import (
	"email-platform/config"
	"email-platform/utils"
	"net/http"
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
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request"})
	}

	var user User
	err := config.DB.Get(&user, "SELECT * FROM users WHERE email = ?", req.Email)
	if err != nil || !utils.CheckPasswordHash(req.Password, user.Password) {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Invalid credentials"})
	}

	token, err := utils.GenerateJWT(user.ID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to generate token"})
	}

	// Update last login
	_, _ = config.DB.Exec("UPDATE users SET last_login = ? WHERE id = ?", time.Now(), user.ID)

	return c.JSON(http.StatusOK, map[string]string{"token": token})
}
