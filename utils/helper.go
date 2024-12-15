package utils

import "strings"

// IsFromMailria checks if the email is from @mailria or @mailsaja domains
func IsFromMailria(email string) bool {
	email = strings.ToLower(strings.TrimSpace(email))
	return strings.HasSuffix(email, "@mailria.com")
}
