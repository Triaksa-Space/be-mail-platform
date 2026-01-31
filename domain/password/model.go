package password

import (
	"database/sql"
	"time"
)

// PasswordResetCode represents a password reset code in the database
type PasswordResetCode struct {
	ID             int64          `db:"id"`
	UserID         int64          `db:"user_id"`
	CodeHash       string         `db:"code_hash"`
	BindingEmail   string         `db:"binding_email"`
	ExpiresAt      time.Time      `db:"expires_at"`
	FailedAttempts int            `db:"failed_attempts"`
	BlockedUntil   sql.NullTime   `db:"blocked_until"`
	VerifiedAt     sql.NullTime   `db:"verified_at"`
	UsedAt         sql.NullTime   `db:"used_at"`
	ResetToken     sql.NullString `db:"reset_token"`
	CreatedAt      time.Time      `db:"created_at"`
}

// ForgotPasswordRequest represents the forgot password request
type ForgotPasswordRequest struct {
	Email string `json:"email"`
}

// VerifyCodeRequest represents the verify code request
type VerifyCodeRequest struct {
	Email string `json:"email"`
	Code  string `json:"code"`
}

// VerifyCodeResponse represents the verify code response
type VerifyCodeResponse struct {
	Message    string `json:"message"`
	ResetToken string `json:"reset_token"`
}

// ResetPasswordRequest represents the reset password request
type ResetPasswordRequest struct {
	Email       string `json:"email"`
	ResetToken  string `json:"reset_token"`
	NewPassword string `json:"new_password"`
}

// Constants for password reset
const (
	CodeExpiry          = 30 * time.Minute // Code expires after 30 minutes
	MaxFailedAttempts   = 5
	BlockDuration       = 5 * time.Minute
	ResetTokenExpiry    = 10 * time.Minute // Reset token expires after 10 minutes
)
