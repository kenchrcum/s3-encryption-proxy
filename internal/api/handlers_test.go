package api

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/gorilla/mux"
	"github.com/kenneth/s3-encryption-gateway/internal/crypto"
	"github.com/kenneth/s3-encryption-gateway/internal/metrics"
	"github.com/kenneth/s3-encryption-gateway/internal/s3"
	"github.com/sirupsen/logrus"
)

// mockS3Client is a mock implementation of s3.Client for testing.
type mockS3Client struct {
	objects  map[string][]byte
	metadata map[string]map[string]string
	errors   map[string]error
}

func newMockS3Client() *mockS3Client {
	return &mockS3Client{
		objects:  make(map[string][]byte),
		metadata: make(map[string]map[string]string),
		errors:   make(map[string]error),
	}
}

func (m *mockS3Client) PutObject(ctx context.Context, bucket, key string, reader io.Reader, metadata map[string]string, contentLength *int64) error {
	if err := m.errors[bucket+"/"+key+"/put"]; err != nil {
		return err
	}
	data, _ := io.ReadAll(reader)
	m.objects[bucket+"/"+key] = data
	m.metadata[bucket+"/"+key] = metadata
	return nil
}

func (m *mockS3Client) GetObject(ctx context.Context, bucket, key string, versionID *string, rangeHeader *string) (io.ReadCloser, map[string]string, error) {
	if err := m.errors[bucket+"/"+key+"/get"]; err != nil {
		return nil, nil, err
	}
	data, ok := m.objects[bucket+"/"+key]
	if !ok {
		return nil, nil, &s3Error{code: "NoSuchKey", message: "Object not found"}
	}
	meta := m.metadata[bucket+"/"+key]
	if meta == nil {
		meta = make(map[string]string)
	}
	return io.NopCloser(bytes.NewReader(data)), meta, nil
}

func (m *mockS3Client) DeleteObject(ctx context.Context, bucket, key string, versionID *string) error {
	if err := m.errors[bucket+"/"+key+"/delete"]; err != nil {
		return err
	}
	delete(m.objects, bucket+"/"+key)
	delete(m.metadata, bucket+"/"+key)
	return nil
}

func (m *mockS3Client) HeadObject(ctx context.Context, bucket, key string, versionID *string) (map[string]string, error) {
	if err := m.errors[bucket+"/"+key+"/head"]; err != nil {
		return nil, err
	}
	meta, ok := m.metadata[bucket+"/"+key]
	if !ok {
		return nil, &s3Error{code: "NoSuchKey", message: "Object not found"}
	}
	if meta == nil {
		meta = make(map[string]string)
	}
	return meta, nil
}

func (m *mockS3Client) ListObjects(ctx context.Context, bucket, prefix string, opts s3.ListOptions) ([]s3.ObjectInfo, error) {
	if err := m.errors[bucket+"/list"]; err != nil {
		return nil, err
	}
	var objects []s3.ObjectInfo
	for key := range m.objects {
		if len(key) > len(bucket)+1 && key[:len(bucket)+1] == bucket+"/" {
			objKey := key[len(bucket)+1:]
			if prefix == "" || len(objKey) >= len(prefix) && objKey[:len(prefix)] == prefix {
				objects = append(objects, s3.ObjectInfo{Key: objKey})
			}
		}
	}
	return objects, nil
}

func (m *mockS3Client) CreateMultipartUpload(ctx context.Context, bucket, key string, metadata map[string]string) (string, error) {
	return "upload-id-123", nil
}

func (m *mockS3Client) UploadPart(ctx context.Context, bucket, key, uploadID string, partNumber int32, reader io.Reader, contentLength *int64) (string, error) {
	return "\"etag-123\"", nil
}

func (m *mockS3Client) CompleteMultipartUpload(ctx context.Context, bucket, key, uploadID string, parts []s3.CompletedPart) (string, error) {
	return "\"final-etag\"", nil
}

func (m *mockS3Client) AbortMultipartUpload(ctx context.Context, bucket, key, uploadID string) error {
	return nil
}

func (m *mockS3Client) ListParts(ctx context.Context, bucket, key, uploadID string) ([]s3.PartInfo, error) {
	return []s3.PartInfo{}, nil
}

func (m *mockS3Client) CopyObject(ctx context.Context, dstBucket, dstKey string, srcBucket, srcKey string, srcVersionID *string, metadata map[string]string) (string, map[string]string, error) {
	// Get source
	srcReader, srcMeta, err := m.GetObject(ctx, srcBucket, srcKey, srcVersionID, nil)
	if err != nil {
		return "", nil, err
	}
	defer srcReader.Close()
	data, _ := io.ReadAll(srcReader)
	
	// Put as destination
    if err := m.PutObject(ctx, dstBucket, dstKey, bytes.NewReader(data), metadata, nil); err != nil {
		return "", nil, err
	}
	
	resultMeta := make(map[string]string)
	if srcMeta != nil {
		for k, v := range srcMeta {
			resultMeta[k] = v
		}
	}
	return "\"copied-etag\"", resultMeta, nil
}

func (m *mockS3Client) DeleteObjects(ctx context.Context, bucket string, keys []s3.ObjectIdentifier) ([]s3.DeletedObject, []s3.ErrorObject, error) {
	deleted := []s3.DeletedObject{}
	errors := []s3.ErrorObject{}
	
	for _, k := range keys {
		if err := m.DeleteObject(ctx, bucket, k.Key, nil); err != nil {
			errors = append(errors, s3.ErrorObject{
				Key:     k.Key,
				Code:    "InternalError",
				Message: err.Error(),
			})
		} else {
			deleted = append(deleted, s3.DeletedObject{
				Key: k.Key,
			})
		}
	}
	
	return deleted, errors, nil
}

type s3Error struct {
	code    string
	message string
}

func (e *s3Error) Error() string {
	return e.message
}

var (
	sharedTestMetrics *metrics.Metrics
	metricsOnce       sync.Once
)

func getTestMetrics() *metrics.Metrics {
	metricsOnce.Do(func() {
		sharedTestMetrics = metrics.NewMetrics()
	})
	return sharedTestMetrics
}

func TestHandler_HandleHealth(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	mockEngine, _ := crypto.NewEngine("test-password-123456")
	handler := NewHandler(newMockS3Client(), mockEngine, logger, getTestMetrics())

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	router := mux.NewRouter()
	handler.RegisterRoutes(router)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}
}

func TestHandler_HandlePutObject(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	mockClient := newMockS3Client()
	mockEngine, _ := crypto.NewEngine("test-password-123456")
	handler := NewHandler(mockClient, mockEngine, logger, getTestMetrics())

	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	tests := []struct {
		name     string
		bucket   string
		key      string
		body     string
		wantCode int
	}{
		{
			name:     "valid put",
			bucket:   "test-bucket",
			key:      "test-key",
			body:     "test data",
			wantCode: http.StatusOK,
		},
		{
			name:     "missing bucket",
			bucket:   "",
			key:      "test-key",
			body:     "test data",
			wantCode: http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var url string
			if tt.bucket == "" {
				// For missing bucket, use a URL that doesn't match the route pattern
				url = "/missing-bucket-test"
			} else {
				url = "/" + tt.bucket + "/" + tt.key
			}
			req := httptest.NewRequest("PUT", url, bytes.NewReader([]byte(tt.body)))
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			if w.Code != tt.wantCode {
				t.Errorf("expected status %d, got %d", tt.wantCode, w.Code)
			}

		if tt.wantCode == http.StatusOK {
			// Verify object was stored
			_, _, err := mockClient.GetObject(context.Background(), tt.bucket, tt.key, nil, nil)
			if err != nil {
				t.Errorf("object should have been stored: %v", err)
			}
		}
		})
	}
}

func TestHandler_HandleGetObject(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	mockClient := newMockS3Client()
	mockEngine, _ := crypto.NewEngine("test-password-123456")
	handler := NewHandler(mockClient, mockEngine, logger, getTestMetrics())

	// Pre-populate with test data
    mockClient.PutObject(context.Background(), "test-bucket", "test-key", bytes.NewReader([]byte("test data")), nil, nil)

	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	req := httptest.NewRequest("GET", "/test-bucket/test-key", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	if w.Body.String() != "test data" {
		t.Errorf("expected body 'test data', got %q", w.Body.String())
	}
}

func TestHandler_HandleDeleteObject(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	mockClient := newMockS3Client()
	mockEngine, _ := crypto.NewEngine("test-password-123456")
	handler := NewHandler(mockClient, mockEngine, logger, getTestMetrics())

	// Pre-populate with test data
    mockClient.PutObject(context.Background(), "test-bucket", "test-key", bytes.NewReader([]byte("test data")), nil, nil)

	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	req := httptest.NewRequest("DELETE", "/test-bucket/test-key", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("expected status %d, got %d", http.StatusNoContent, w.Code)
	}

	// Verify object was deleted
	_, _, err := mockClient.GetObject(context.Background(), "test-bucket", "test-key", nil, nil)
	if err == nil {
		t.Error("object should have been deleted")
	}
}

func TestHandler_HandleHeadObject(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	mockClient := newMockS3Client()
	mockEngine, _ := crypto.NewEngine("test-password-123456")
	handler := NewHandler(mockClient, mockEngine, logger, getTestMetrics())

	metadata := map[string]string{"content-type": "text/plain"}
    mockClient.PutObject(context.Background(), "test-bucket", "test-key", bytes.NewReader([]byte("test")), metadata, nil)

	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	req := httptest.NewRequest("HEAD", "/test-bucket/test-key", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}
}

func TestHandler_HandleListObjects(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	mockClient := newMockS3Client()
	mockEngine, _ := crypto.NewEngine("test-password-123456")
	handler := NewHandler(mockClient, mockEngine, logger, getTestMetrics())

	// Pre-populate with test data
    mockClient.PutObject(context.Background(), "test-bucket", "key1", bytes.NewReader([]byte("data1")), nil, nil)
    mockClient.PutObject(context.Background(), "test-bucket", "key2", bytes.NewReader([]byte("data2")), nil, nil)

	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	req := httptest.NewRequest("GET", "/test-bucket", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	if w.Header().Get("Content-Type") != "application/xml" {
		t.Errorf("expected Content-Type application/xml, got %s", w.Header().Get("Content-Type"))
	}
}

// TestContentRangeMapping tests Content-Range and Content-Length header mapping for range requests
func TestContentRangeMapping(t *testing.T) {
	// Create a crypto engine that supports chunking and range decryption
	engine, err := crypto.NewEngineWithChunking("test-password-123456", nil, "", nil, true, 16*1024)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	// Create test data (32KB to ensure chunking)
	testData := make([]byte, 32*1024)
	for i := range testData {
		testData[i] = byte(i % 256)
	}

	// Encrypt the data with original ETag
	originalMetadata := map[string]string{
		"ETag": "\"original-etag-12345\"", // Mock original ETag
	}
	encryptedReader, metadata, err := engine.Encrypt(bytes.NewReader(testData), originalMetadata)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	encryptedData, err := io.ReadAll(encryptedReader)
	if err != nil {
		t.Fatalf("Failed to read encrypted data: %v", err)
	}

	// Check that original ETag was stored
	if metadata[crypto.MetaOriginalETag] == "" {
		t.Fatalf("Original ETag not stored in metadata: %+v", metadata)
	}

	// Update metadata for chunked format
	metadata[crypto.MetaEncrypted] = "true"
	metadata[crypto.MetaChunkCount] = "2"  // 32KB / 16KB = 2 chunks
	metadata[crypto.MetaChunkSize] = "16384"  // 16KB
	metadata[crypto.MetaChunkedFormat] = "true"

	// Create mock S3 client and populate it
	mockClient := newMockS3Client()
	mockClient.PutObject(context.Background(), "test-bucket", "range-test", bytes.NewReader(encryptedData), metadata, nil)

	// Create handler
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	handler := NewHandler(mockClient, engine, logger, getTestMetrics())

	// Test various range requests
	testCases := []struct {
		name                 string
		rangeHeader          string
		expectedStatus       int
		expectedContentRange string
		expectedContentLength string
		expectedDataLength   int
	}{
		{
			name:                 "simple range",
			rangeHeader:          "bytes=1000-1999",
			expectedStatus:       http.StatusPartialContent,
			expectedContentRange: "bytes 1000-1999/32768",
			expectedContentLength: "1000",
			expectedDataLength:   1000,
		},
		{
			name:                 "first byte",
			rangeHeader:          "bytes=0-0",
			expectedStatus:       http.StatusPartialContent,
			expectedContentRange: "bytes 0-0/32768",
			expectedContentLength: "1",
			expectedDataLength:   1,
		},
		{
			name:                 "last byte",
			rangeHeader:          "bytes=32767-32767",
			expectedStatus:       http.StatusPartialContent,
			expectedContentRange: "bytes 32767-32767/32768",
			expectedContentLength: "1",
			expectedDataLength:   1,
		},
		{
			name:                 "cross chunk boundary",
			rangeHeader:          "bytes=16380-16390", // Spans chunk boundary
			expectedStatus:       http.StatusPartialContent,
			expectedContentRange: "bytes 16380-16390/32768",
			expectedContentLength: "11",
			expectedDataLength:   11,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			router := mux.NewRouter()
			handler.RegisterRoutes(router)

			req := httptest.NewRequest("GET", "/test-bucket/range-test", nil)
			req.Header.Set("Range", tc.rangeHeader)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			if w.Code != tc.expectedStatus {
				t.Errorf("expected status %d, got %d", tc.expectedStatus, w.Code)
			}

			if tc.expectedStatus == http.StatusPartialContent {
				contentRange := w.Header().Get("Content-Range")
				if contentRange != tc.expectedContentRange {
					t.Errorf("Content-Range mismatch: expected %q, got %q", tc.expectedContentRange, contentRange)
				}

				contentLength := w.Header().Get("Content-Length")
				if contentLength != tc.expectedContentLength {
					t.Errorf("Content-Length mismatch: expected %q, got %q", tc.expectedContentLength, contentLength)
				}

				body := w.Body.Bytes()
				if len(body) != tc.expectedDataLength {
					t.Errorf("Body length mismatch: expected %d, got %d", tc.expectedDataLength, len(body))
				}

				// Verify Content-Length header matches actual body length
				if contentLength != fmt.Sprintf("%d", len(body)) {
					t.Errorf("Content-Length header (%s) doesn't match body length (%d)", contentLength, len(body))
				}

				// Verify ETag is preserved in range responses
				etag := w.Header().Get("ETag")
				if etag == "" {
					t.Errorf("ETag header should be present in range response")
				}
				// The ETag should be the original ETag (not the encrypted object's ETag)
				// We can't easily verify the exact value without more setup, but presence is key
			}
		})
	}
}