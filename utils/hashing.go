package utils

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strconv"

	"github.com/spf13/viper"
	"golang.org/x/crypto/bcrypt"
)

func HashPassword(password string) (string, error) {
	secret := viper.GetString("JWT_SECRET")
	saltedPassword := password + secret
	bytes, err := bcrypt.GenerateFromPassword([]byte(saltedPassword), bcrypt.DefaultCost)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	secret := viper.GetString("JWT_SECRET")
	saltedPassword := password + secret
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(saltedPassword))
	return err == nil
}

// EncodeID generates a short obfuscated string using HMAC with a secret
func EncodeID(id int) string {
	idStr := strconv.Itoa(id)
	secret := viper.GetString("JWT_SECRET") // Get the secret from configuration

	// Create an HMAC using SHA256 and the secret
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(idStr)) // Hash the ID string

	// Take the first 6 bytes of the hash for a shorter ID
	hash := h.Sum(nil)[:6] // Truncate the hash to 6 bytes

	// Combine the original ID and truncated hash, then encode with Base64
	data := fmt.Sprintf("%s:%x", idStr, hash)
	return base64.RawURLEncoding.EncodeToString([]byte(data))
}

// DecodeID verifies and decodes the obfuscated string back to the original integer ID
func DecodeID(encoded string) (int, error) {
	// Decode the Base64 string
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return 0, fmt.Errorf("failed to decode: %w", err)
	}

	// Split the decoded string into the ID and hash
	parts := string(decoded)
	sepIndex := -1
	for i, char := range parts {
		if char == ':' {
			sepIndex = i
			break
		}
	}

	if sepIndex == -1 {
		return 0, fmt.Errorf("invalid encoded string format")
	}

	originalIDStr := parts[:sepIndex]
	originalID, err := strconv.Atoi(originalIDStr)
	if err != nil {
		return 0, fmt.Errorf("invalid ID format: %w", err)
	}

	// Verify the hash
	secret := viper.GetString("JWT_SECRET")
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(originalIDStr))
	expectedHash := fmt.Sprintf("%x", h.Sum(nil)[:6]) // Use the same truncated hash length

	if expectedHash != parts[sepIndex+1:] {
		return 0, fmt.Errorf("hash mismatch: invalid encoded ID")
	}

	return originalID, nil
}
