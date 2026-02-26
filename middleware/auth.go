package middleware

import (
	"database/sql"
	"fmt"
	"net/http"
	"strings"

	"github.com/Triaksa-Space/be-mail-platform/config"
	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	"github.com/spf13/viper"
)

// JWTMiddleware validates the JWT token and extracts user claims
func JWTMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		jwtSecret := viper.GetString("JWT_SECRET")

		// Extract the token from the Authorization header
		authHeader := c.Request().Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Missing or invalid token"})
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")

		// Check if the token has the correct number of segments
		segments := strings.Split(tokenString, ".")
		if len(segments) != 3 {
			return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Malformed token"})
		}

		// Parse and validate the token
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// Validate signing method
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, echo.NewHTTPError(http.StatusUnauthorized, "Invalid signing method")
			}
			return []byte(jwtSecret), nil // Return the secret as a byte slice
		})

		if err != nil || !token.Valid {
			fmt.Println("Invalid or expired token:", err)
			return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Invalid or expired token"})
		}

		// Extract claims and set them in the context
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Invalid token claims"})
		}

		// Set user claims in the context for downstream handlers
		userID := int64(claims["user_id"].(float64))
		c.Set("user_id", userID)
		c.Set("email", claims["email"].(string))
		c.Set("role_id", int64(claims["role_id"].(float64)))

		// Validate token_version against the database
		if tokenVersionClaim, ok := claims["token_version"]; ok {
			claimVersion := int64(tokenVersionClaim.(float64))
			var dbVersion int64
			err := config.DB.QueryRow("SELECT token_version FROM users WHERE id = ?", userID).Scan(&dbVersion)
			if err != nil {
				if err == sql.ErrNoRows {
					return c.JSON(http.StatusUnauthorized, map[string]string{"error": "User not found."})
				}
				fmt.Println("Error checking token version:", err)
				return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error."})
			}
			if claimVersion != dbVersion {
				return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Session revoked. Please login again."})
			}
		}

		return next(c)
	}
}
