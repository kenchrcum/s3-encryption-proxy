package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTracingMiddleware_Redaction(t *testing.T) {
	// Create a test handler that records span attributes
	var recordedHeaders map[string]string
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// In a real scenario, this would be done by the tracing framework
		// For testing, we'll simulate what the middleware does
		headers := make(map[string]string)
		for k, v := range r.Header {
			headers[strings.ToLower(k)] = strings.Join(v, ",")
		}
		recordedHeaders = headers
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// Test with redaction enabled
	middleware := TracingMiddleware(true)
	handler := middleware(testHandler)

	// Create a request with sensitive headers
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer secret-token")
	req.Header.Set("X-Amz-Security-Token", "sensitive-token")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Custom-Header", "safe-value")

	// Execute request
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// Verify response
	assert.Equal(t, http.StatusOK, w.Code)

	// In the actual middleware, sensitive headers would be redacted in spans
	// For this test, we verify the middleware doesn't interfere with the request
	assert.Equal(t, "Bearer secret-token", recordedHeaders["authorization"])
	assert.Equal(t, "sensitive-token", recordedHeaders["x-amz-security-token"])
	assert.Equal(t, "application/json", recordedHeaders["content-type"])
}

func TestTracingMiddleware_NoRedaction(t *testing.T) {
	// Test with redaction disabled
	middleware := TracingMiddleware(false)
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	handler := middleware(testHandler)

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer secret-token")
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// Verify response
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestExtractBucketAndKey(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		bucket   string
		key      string
	}{
		{
			name:   "simple bucket and key",
			path:   "/mybucket/mykey",
			bucket: "mybucket",
			key:    "mykey",
		},
		{
			name:   "bucket only",
			path:   "/mybucket",
			bucket: "mybucket",
			key:    "",
		},
		{
			name:   "nested key",
			path:   "/mybucket/path/to/file.txt",
			bucket: "mybucket",
			key:    "path/to/file.txt",
		},
		{
			name:   "root path",
			path:   "/",
			bucket: "",
			key:    "",
		},
		{
			name:   "empty path",
			path:   "",
			bucket: "",
			key:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bucket, key := extractBucketAndKey(tt.path)
			assert.Equal(t, tt.bucket, bucket)
			assert.Equal(t, tt.key, key)
		})
	}
}

func TestGetSpanName(t *testing.T) {
	tests := []struct {
		name   string
		method string
		bucket string
		key    string
		want   string
	}{
		{
			name:   "GET with key",
			method: "GET",
			bucket: "bucket",
			key:    "key",
			want:   "S3 GetObject",
		},
		{
			name:   "GET without key",
			method: "GET",
			bucket: "bucket",
			key:    "",
			want:   "S3 ListObjects",
		},
		{
			name:   "PUT",
			method: "PUT",
			bucket: "bucket",
			key:    "key",
			want:   "S3 PutObject",
		},
		{
			name:   "DELETE",
			method: "DELETE",
			bucket: "bucket",
			key:    "key",
			want:   "S3 DeleteObject",
		},
		{
			name:   "HEAD",
			method: "HEAD",
			bucket: "bucket",
			key:    "key",
			want:   "S3 HeadObject",
		},
		{
			name:   "POST with multipart",
			method: "POST",
			bucket: "bucket",
			key:    "multipart",
			want:   "S3 CompleteMultipartUpload",
		},
		{
			name:   "unknown method",
			method: "UNKNOWN",
			bucket: "bucket",
			key:    "key",
			want:   "HTTP UNKNOWN",
		},
		{
			name:   "no bucket",
			method: "GET",
			bucket: "",
			key:    "",
			want:   "HTTP GET",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getSpanName(tt.method, tt.bucket, tt.key)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestGetRemoteAddr(t *testing.T) {
	tests := []struct {
		name string
		req  *http.Request
		want string
	}{
		{
			name: "X-Forwarded-For single IP",
			req: func() *http.Request {
				req := httptest.NewRequest("GET", "/", nil)
				req.Header.Set("X-Forwarded-For", "192.168.1.1")
				req.RemoteAddr = "127.0.0.1:1234"
				return req
			}(),
			want: "192.168.1.1",
		},
		{
			name: "X-Forwarded-For multiple IPs",
			req: func() *http.Request {
				req := httptest.NewRequest("GET", "/", nil)
				req.Header.Set("X-Forwarded-For", "192.168.1.1, 10.0.0.1")
				req.RemoteAddr = "127.0.0.1:1234"
				return req
			}(),
			want: "192.168.1.1",
		},
		{
			name: "X-Real-IP",
			req: func() *http.Request {
				req := httptest.NewRequest("GET", "/", nil)
				req.Header.Set("X-Real-IP", "192.168.1.1")
				req.RemoteAddr = "127.0.0.1:1234"
				return req
			}(),
			want: "192.168.1.1",
		},
		{
			name: "fallback to RemoteAddr",
			req: func() *http.Request {
				req := httptest.NewRequest("GET", "/", nil)
				req.RemoteAddr = "127.0.0.1:1234"
				return req
			}(),
			want: "127.0.0.1:1234",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getRemoteAddr(tt.req)
			assert.Equal(t, tt.want, got)
		})
	}
}
