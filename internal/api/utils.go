package api

import (
	"net/http"
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
