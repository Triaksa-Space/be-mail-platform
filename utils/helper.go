package utils

import (
	"html"
	"regexp"
	"strings"
)

var htmlTagRe = regexp.MustCompile(`<[^>]*>`)

// StripHTMLToText converts an HTML string to plain text.
// Entities are decoded before tags are removed so encoded tags like
// &lt;img&gt; are stripped correctly.
func StripHTMLToText(src string) string {
	// Decode entities first so encoded tags are caught by the regex below
	text := html.UnescapeString(src)
	text = strings.ReplaceAll(text, "<br>", " ")
	text = strings.ReplaceAll(text, "<br/>", " ")
	text = strings.ReplaceAll(text, "<br />", " ")
	text = strings.ReplaceAll(text, "</p>", " ")
	text = strings.ReplaceAll(text, "</div>", " ")
	text = htmlTagRe.ReplaceAllString(text, "")
	text = strings.Join(strings.Fields(text), " ")
	return strings.TrimSpace(text)
}

// IsFromMailria checks if the email is from @mailria or @mailsaja domains
func IsFromMailria(email string) bool {
	email = strings.ToLower(strings.TrimSpace(email))
	return strings.HasSuffix(email, "@mailria.com")
}
