package middleware

import (
	"net/http"

	"github.com/golang-jwt/jwt/v5"
	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
)

func JWTMiddleware(secret string) echo.MiddlewareFunc {
	return echojwt.WithConfig(echojwt.Config{
		SigningKey:  []byte(secret),
		TokenLookup: "header:Authorization",
		NewClaimsFunc: func(c echo.Context) jwt.Claims {
			return jwt.MapClaims{}
		},
		SuccessHandler: func(c echo.Context) {
			// Extract user_id from the token and store it in context
			user := c.Get("user").(*jwt.Token)
			claims := user.Claims.(jwt.MapClaims)
			c.Set("user_id", int64(claims["user_id"].(float64))) // Store user_id as int64
		},
		ErrorHandler: func(c echo.Context, err error) error {
			return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Invalid or missing token"})
		},
	})
}
