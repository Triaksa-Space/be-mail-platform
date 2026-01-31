package auth

import (
	"database/sql"
	"time"
)

// RefreshToken represents a stored refresh token
type RefreshToken struct {
	ID         int64        `db:"id"`
	UserID     int64        `db:"user_id"`
	TokenHash  string       `db:"token_hash"`
	RememberMe bool         `db:"remember_me"`
	ExpiresAt  time.Time    `db:"expires_at"`
	CreatedAt  time.Time    `db:"created_at"`
	RevokedAt  sql.NullTime `db:"revoked_at"`
	ReplacedBy sql.NullInt64 `db:"replaced_by"`
	UserAgent  sql.NullString `db:"user_agent"`
	IPAddress  sql.NullString `db:"ip_address"`
}

// LoginRequest represents the login request payload
type LoginRequest struct {
	Email      string `json:"email"`
	Password   string `json:"password"`
	RememberMe bool   `json:"remember_me"`
}

// LoginResponse represents the login response
type LoginResponse struct {
	AccessToken  string       `json:"access_token"`
	RefreshToken string       `json:"refresh_token"`
	ExpiresIn    int          `json:"expires_in"`
	TokenType    string       `json:"token_type"`
	User         UserResponse `json:"user"`
}

// UserResponse represents the user data in login response
type UserResponse struct {
	ID       string `json:"id"`
	Email    string `json:"email"`
	RoleID   int    `json:"role_id"`
}

// RefreshTokenRequest represents the refresh token request
type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// RefreshTokenResponse represents the refresh token response
type RefreshTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
}

// LogoutRequest represents the logout request
type LogoutRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// Token expiry constants
const (
	AccessTokenExpiry           = 15 * time.Minute   // 15 minutes
	RefreshTokenExpiry          = 7 * 24 * time.Hour  // 7 days
	RefreshTokenExpiryRememberMe = 30 * 24 * time.Hour // 30 days
	AccessTokenExpirySeconds    = 900                  // 15 minutes in seconds
)
