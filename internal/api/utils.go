package api

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// getClientIP extracts the client IP address from the request.
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header first (for proxies)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// X-Forwarded-For can contain multiple IPs, take the first one
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}

	// Fall back to RemoteAddr
	if r.RemoteAddr != "" {
		// RemoteAddr is in format "IP:port", extract just IP
		if colonIdx := strings.LastIndex(r.RemoteAddr, ":"); colonIdx != -1 {
			return r.RemoteAddr[:colonIdx]
		}
		return r.RemoteAddr
	}

	return "unknown"
}

// getRequestID extracts or generates a request ID from the request.
func getRequestID(r *http.Request) string {
	// Check for existing request ID header
	if rid := r.Header.Get("X-Request-ID"); rid != "" {
		return rid
	}

	// Could generate a new one, but for now return empty if not present
	return ""
}

// validateTags validates the x-amz-tagging header value.
// Format: URL-encoded key=value pairs, separated by &
// Limits: max 10 tags, key len 128, value len 256, specific charset
func validateTags(tagging string) error {
	if tagging == "" {
		return nil
	}

	tags, err := url.ParseQuery(tagging)
	if err != nil {
		return fmt.Errorf("invalid tagging format: %w", err)
	}

	// Count total tags (keys)
	if len(tags) > 10 {
		return fmt.Errorf("too many tags: max 10 allowed")
	}

	for k, vs := range tags {
		if len(k) > 128 {
			return fmt.Errorf("tag key too long: %s", k)
		}
		// Validate charset for key
		if !isValidTagChars(k) {
			return fmt.Errorf("invalid characters in tag key: %s", k)
		}

		for _, v := range vs {
			if len(v) > 256 {
				return fmt.Errorf("tag value too long: %s", v)
			}
			// Validate charset for value
			if !isValidTagChars(v) {
				return fmt.Errorf("invalid characters in tag value: %s", v)
			}
		}
	}
	return nil
}

// isValidTagChars checks if the string contains only allowed characters for S3 tags.
// Allowed: a-z, A-Z, 0-9, + - = . _ : /
func isValidTagChars(s string) bool {
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '+' || c == '-' || c == '=' || c == '.' || c == '_' || c == ':' || c == '/') {
			return false
		}
	}
	return true
}
