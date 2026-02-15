package utils

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/spf13/viper"
)

// GenerateJWT generates a long-lived JWT token (30 days) for backward compatibility
func GenerateJWT(userID int64, email string, role_id int) (string, error) {
	jwtSecret := viper.GetString("JWT_SECRET")

	claims := jwt.MapClaims{
		"user_id": userID,
		"email":   email,
		"role_id": role_id,
		"exp":     time.Now().Add(time.Hour * 720).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(jwtSecret))
	if err != nil {
		fmt.Println("Error signing token:", err)
		return "", err
	}
	return tokenString, nil
}

// GenerateAccessToken generates a short-lived access token (15 minutes)
func GenerateAccessToken(userID int64, email string, roleID int, tokenVersion int64) (string, error) {
	jwtSecret := viper.GetString("JWT_SECRET")

	claims := jwt.MapClaims{
		"user_id":       userID,
		"email":         email,
		"role_id":       roleID,
		"token_version": tokenVersion,
		"exp":           time.Now().Add(15 * time.Minute).Unix(),
		"type":          "access",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(jwtSecret))
	if err != nil {
		fmt.Println("Error signing access token:", err)
		return "", err
	}
	return tokenString, nil
}
