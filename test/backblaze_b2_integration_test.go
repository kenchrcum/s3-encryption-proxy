//go:build integration
// +build integration

package test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/kenneth/s3-encryption-gateway/internal/config"
	"github.com/kenneth/s3-encryption-gateway/internal/crypto"
	"github.com/stretchr/testify/require"
)

const (
	// Backblaze B2 S3-compatible endpoint
	b2Endpoint = "s3.eu-central-003.backblazeb2.com"
)

// getB2Credentials retrieves Backblaze B2 credentials from environment variables.
// Returns accessKey, secretKey, bucket, and an error if any required variable is missing.
func getB2Credentials(t *testing.T) (accessKey, secretKey, bucket string, err error) {
	t.Helper()

	accessKey = os.Getenv("B2_ACCESS_KEY_ID")
	secretKey = os.Getenv("B2_SECRET_ACCESS_KEY")
	bucket = os.Getenv("B2_BUCKET_NAME")

	if accessKey == "" {
		return "", "", "", fmt.Errorf("B2_ACCESS_KEY_ID environment variable is required")
	}
	if secretKey == "" {
		return "", "", "", fmt.Errorf("B2_SECRET_ACCESS_KEY environment variable is required")
	}
	if bucket == "" {
		return "", "", "", fmt.Errorf("B2_BUCKET_NAME environment variable is required")
	}

	return accessKey, secretKey, bucket, nil
}

// TestBackblazeB2_BasicEncryption tests basic encryption/decryption with Backblaze B2.
func TestBackblazeB2_BasicEncryption(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	accessKey, secretKey, bucket, err := getB2Credentials(t)
	if err != nil {
		t.Skipf("Skipping Backblaze B2 test: %v", err)
	}

	// Create gateway config for Backblaze B2
	cfg := &config.Config{
		ListenAddr: ":0",
		LogLevel:   "error",
		Backend: config.BackendConfig{
			Endpoint:  fmt.Sprintf("https://%s", b2Endpoint),
			AccessKey: accessKey,
			SecretKey: secretKey,
			Provider:  "backblaze",
			UseSSL:    true,
		},
		Encryption: config.EncryptionConfig{
			Password:           "test-password-123456",
			PreferredAlgorithm: "AES256-GCM",
		},
	}

	gateway := StartGateway(t, cfg)
	defer gateway.Close()

	// Test data
	testKey := fmt.Sprintf("test-basic-%d", time.Now().UnixNano())
	testData := []byte("Hello from Backblaze B2 integration test!")

	// PUT encrypted object
	putURL := fmt.Sprintf("http://%s/%s/%s", gateway.Addr, bucket, testKey)
	putReq, err := http.NewRequest("PUT", putURL, bytes.NewReader(testData))
	require.NoError(t, err)
	putReq.Header.Set("Content-Type", "text/plain")

	putResp, err := http.DefaultClient.Do(putReq)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, putResp.StatusCode, "PUT should succeed")
	putResp.Body.Close()

	// GET and verify decryption
	getURL := fmt.Sprintf("http://%s/%s/%s", gateway.Addr, bucket, testKey)
	getResp, err := http.Get(getURL)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, getResp.StatusCode, "GET should succeed")
	defer getResp.Body.Close()

	gotData, err := io.ReadAll(getResp.Body)
	require.NoError(t, err)
	require.Equal(t, testData, gotData, "Decrypted data should match original")

	// Cleanup: Delete object
	deleteURL := fmt.Sprintf("http://%s/%s/%s", gateway.Addr, bucket, testKey)
	deleteReq, err := http.NewRequest("DELETE", deleteURL, nil)
	require.NoError(t, err)
	deleteResp, err := http.DefaultClient.Do(deleteReq)
	if err == nil {
		deleteResp.Body.Close()
	}
}

// TestBackblazeB2_LargeFile tests encryption/decryption with a larger file.
func TestBackblazeB2_LargeFile(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	accessKey, secretKey, bucket, err := getB2Credentials(t)
	if err != nil {
		t.Skipf("Skipping Backblaze B2 test: %v", err)
	}

	cfg := &config.Config{
		ListenAddr: ":0",
		LogLevel:   "error",
		Backend: config.BackendConfig{
			Endpoint:  fmt.Sprintf("https://%s", b2Endpoint),
			AccessKey: accessKey,
			SecretKey: secretKey,
			Provider:  "backblaze",
			UseSSL:    true,
		},
		Encryption: config.EncryptionConfig{
			Password:           "test-password-123456",
			PreferredAlgorithm: "AES256-GCM",
		},
	}

	gateway := StartGateway(t, cfg)
	defer gateway.Close()

	// Create a larger test file (100KB)
	testKey := fmt.Sprintf("test-large-%d", time.Now().UnixNano())
	testData := bytes.Repeat([]byte("A"), 100*1024)

	// PUT encrypted object
	putURL := fmt.Sprintf("http://%s/%s/%s", gateway.Addr, bucket, testKey)
	putReq, err := http.NewRequest("PUT", putURL, bytes.NewReader(testData))
	require.NoError(t, err)
	putReq.Header.Set("Content-Type", "application/octet-stream")

	putResp, err := http.DefaultClient.Do(putReq)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, putResp.StatusCode)
	putResp.Body.Close()

	// GET and verify
	getURL := fmt.Sprintf("http://%s/%s/%s", gateway.Addr, bucket, testKey)
	getResp, err := http.Get(getURL)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, getResp.StatusCode)
	defer getResp.Body.Close()

	gotData, err := io.ReadAll(getResp.Body)
	require.NoError(t, err)
	require.Equal(t, len(testData), len(gotData))
	require.Equal(t, testData, gotData)

	// Cleanup
	deleteURL := fmt.Sprintf("http://%s/%s/%s", gateway.Addr, bucket, testKey)
	deleteReq, err := http.NewRequest("DELETE", deleteURL, nil)
	require.NoError(t, err)
	deleteResp, err := http.DefaultClient.Do(deleteReq)
	if err == nil {
		deleteResp.Body.Close()
	}
}

// TestBackblazeB2_WithCosmianKMS tests encryption/decryption with Cosmian KMS integration.
// This test requires both B2 credentials and a running Cosmian KMS instance.
func TestBackblazeB2_WithCosmianKMS(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Check if Docker is available for Cosmian KMS
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("Docker not available, skipping KMS integration test")
	}

	accessKey, secretKey, bucket, err := getB2Credentials(t)
	if err != nil {
		t.Skipf("Skipping Backblaze B2 test: %v", err)
	}

	// Start Cosmian KMS container
	_, kmsEndpoint, tlsCfg, kmsCleanup, containerName, _ := startCosmianKMS(t)
	defer kmsCleanup()

	// Wait for KMS to be ready
	waitForKMSReady(t, kmsEndpoint, containerName)

	// Create a wrapping key in Cosmian KMS
	keyID := createWrappingKey(t, kmsEndpoint)

	// Create KMS manager
	manager, err := crypto.NewCosmianKMIPManager(crypto.CosmianKMIPOptions{
		Endpoint: kmsEndpoint,
		Keys: []crypto.KMIPKeyReference{
			{ID: keyID, Version: 1},
		},
		TLSConfig:      tlsCfg,
		Timeout:        10 * time.Second,
		Provider:       "cosmian",
		DualReadWindow: 1,
	})
	require.NoError(t, err)
	defer func() {
		_ = manager.Close(context.Background())
	}()

	// Create gateway config with KMS
	cfg := &config.Config{
		ListenAddr: ":0",
		LogLevel:   "error",
		Backend: config.BackendConfig{
			Endpoint:  fmt.Sprintf("https://%s", b2Endpoint),
			AccessKey: accessKey,
			SecretKey: secretKey,
			Provider:  "backblaze",
			UseSSL:    true,
		},
		Encryption: config.EncryptionConfig{
			Password:           "fallback-password-123456",
			PreferredAlgorithm: "AES256-GCM",
			KeyManager: config.KeyManagerConfig{
				Enabled:        true,
				Provider:       "cosmian",
				DualReadWindow: 1,
				Cosmian: config.CosmianConfig{
					Endpoint:           kmsEndpoint,
					Timeout:            10 * time.Second,
					InsecureSkipVerify: true,
					Keys: []config.CosmianKeyReference{
						{ID: keyID, Version: 1},
					},
				},
			},
		},
	}

	// Start gateway with KMS
	gateway := StartGatewayWithKMS(t, cfg, manager)
	defer gateway.Close()

	// Test data
	testKey := fmt.Sprintf("test-kms-%d", time.Now().UnixNano())
	testData := []byte("Hello from Backblaze B2 with Cosmian KMS!")

	// PUT encrypted object
	putURL := fmt.Sprintf("%s/%s/%s", gateway.URL, bucket, testKey)
	putReq, err := http.NewRequest("PUT", putURL, bytes.NewReader(testData))
	require.NoError(t, err)
	putReq.Header.Set("Content-Type", "text/plain")

	putResp, err := http.DefaultClient.Do(putReq)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, putResp.StatusCode, "PUT should succeed")
	putResp.Body.Close()

	// GET and verify decryption
	getURL := fmt.Sprintf("%s/%s/%s", gateway.URL, bucket, testKey)
	getResp, err := http.Get(getURL)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, getResp.StatusCode, "GET should succeed")
	defer getResp.Body.Close()

	gotData, err := io.ReadAll(getResp.Body)
	require.NoError(t, err)
	require.Equal(t, testData, gotData, "Decrypted data should match original")

	// Cleanup
	deleteURL := fmt.Sprintf("%s/%s/%s", gateway.URL, bucket, testKey)
	deleteReq, err := http.NewRequest("DELETE", deleteURL, nil)
	require.NoError(t, err)
	deleteResp, err := http.DefaultClient.Do(deleteReq)
	if err == nil {
		deleteResp.Body.Close()
	}
}

// TestBackblazeB2_MetadataHandling tests that metadata is correctly stored and retrieved from B2.
// This is critical for KMS integration as wrapped keys are stored in metadata.
func TestBackblazeB2_MetadataHandling(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	accessKey, secretKey, bucket, err := getB2Credentials(t)
	if err != nil {
		t.Skipf("Skipping Backblaze B2 test: %v", err)
	}

	cfg := &config.Config{
		ListenAddr: ":0",
		LogLevel:   "error",
		Backend: config.BackendConfig{
			Endpoint:  fmt.Sprintf("https://%s", b2Endpoint),
			AccessKey: accessKey,
			SecretKey: secretKey,
			Provider:  "backblaze",
			UseSSL:    true,
		},
		Encryption: config.EncryptionConfig{
			Password:           "test-password-123456",
			PreferredAlgorithm: "AES256-GCM",
		},
	}

	gateway := StartGateway(t, cfg)
	defer gateway.Close()

	// Test with multiple objects to verify metadata consistency
	testKeys := []string{
		fmt.Sprintf("test-meta-1-%d", time.Now().UnixNano()),
		fmt.Sprintf("test-meta-2-%d", time.Now().UnixNano()),
		fmt.Sprintf("test-meta-3-%d", time.Now().UnixNano()),
	}

	for i, testKey := range testKeys {
		testData := []byte(fmt.Sprintf("Test data for metadata handling #%d", i+1))

		// PUT
		putURL := fmt.Sprintf("http://%s/%s/%s", gateway.Addr, bucket, testKey)
		putReq, err := http.NewRequest("PUT", putURL, bytes.NewReader(testData))
		require.NoError(t, err)
		putReq.Header.Set("Content-Type", "text/plain")

		putResp, err := http.DefaultClient.Do(putReq)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, putResp.StatusCode)
		putResp.Body.Close()

		// GET and verify
		getURL := fmt.Sprintf("http://%s/%s/%s", gateway.Addr, bucket, testKey)
		getResp, err := http.Get(getURL)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, getResp.StatusCode)
		defer getResp.Body.Close()

		gotData, err := io.ReadAll(getResp.Body)
		require.NoError(t, err)
		require.Equal(t, testData, gotData, "Data should match for key %s", testKey)

		// Cleanup
		deleteURL := fmt.Sprintf("http://%s/%s/%s", gateway.Addr, bucket, testKey)
		deleteReq, err := http.NewRequest("DELETE", deleteURL, nil)
		require.NoError(t, err)
		deleteResp, err := http.DefaultClient.Do(deleteReq)
		if err == nil {
			deleteResp.Body.Close()
		}
	}
}

// TestBackblazeB2_ConcurrentOperations tests concurrent PUT/GET operations.
func TestBackblazeB2_ConcurrentOperations(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	accessKey, secretKey, bucket, err := getB2Credentials(t)
	if err != nil {
		t.Skipf("Skipping Backblaze B2 test: %v", err)
	}

	cfg := &config.Config{
		ListenAddr: ":0",
		LogLevel:   "error",
		Backend: config.BackendConfig{
			Endpoint:  fmt.Sprintf("https://%s", b2Endpoint),
			AccessKey: accessKey,
			SecretKey: secretKey,
			Provider:  "backblaze",
			UseSSL:    true,
		},
		Encryption: config.EncryptionConfig{
			Password:           "test-password-123456",
			PreferredAlgorithm: "AES256-GCM",
		},
	}

	gateway := StartGateway(t, cfg)
	defer gateway.Close()

	// Test concurrent operations
	const numConcurrent = 5
	errors := make(chan error, numConcurrent*2)

	for i := 0; i < numConcurrent; i++ {
		go func(idx int) {
			testKey := fmt.Sprintf("test-concurrent-%d-%d", idx, time.Now().UnixNano())
			testData := []byte(fmt.Sprintf("Concurrent test data #%d", idx))

			// PUT
			putURL := fmt.Sprintf("http://%s/%s/%s", gateway.Addr, bucket, testKey)
			putReq, err := http.NewRequest("PUT", putURL, bytes.NewReader(testData))
			if err != nil {
				errors <- fmt.Errorf("PUT request creation failed: %w", err)
				return
			}

			putResp, err := http.DefaultClient.Do(putReq)
			if err != nil {
				errors <- fmt.Errorf("PUT request failed: %w", err)
				return
			}
			putResp.Body.Close()

			if putResp.StatusCode != http.StatusOK {
				errors <- fmt.Errorf("PUT returned status %d", putResp.StatusCode)
				return
			}

			// GET
			getURL := fmt.Sprintf("http://%s/%s/%s", gateway.Addr, bucket, testKey)
			getResp, err := http.Get(getURL)
			if err != nil {
				errors <- fmt.Errorf("GET request failed: %w", err)
				return
			}
			defer getResp.Body.Close()

			if getResp.StatusCode != http.StatusOK {
				errors <- fmt.Errorf("GET returned status %d", getResp.StatusCode)
				return
			}

			gotData, err := io.ReadAll(getResp.Body)
			if err != nil {
				errors <- fmt.Errorf("Failed to read GET response: %w", err)
				return
			}

			if !bytes.Equal(gotData, testData) {
				errors <- fmt.Errorf("Data mismatch for key %s", testKey)
				return
			}

			// Cleanup
			deleteURL := fmt.Sprintf("http://%s/%s/%s", gateway.Addr, bucket, testKey)
			deleteReq, err := http.NewRequest("DELETE", deleteURL, nil)
			if err == nil {
				deleteResp, err := http.DefaultClient.Do(deleteReq)
				if err == nil {
					deleteResp.Body.Close()
				}
			}
		}(i)
	}

	// Wait for all operations to complete
	time.Sleep(2 * time.Second)

	// Check for errors
	close(errors)
	var errorList []error
	for err := range errors {
		if err != nil {
			errorList = append(errorList, err)
		}
	}

	require.Empty(t, errorList, "Concurrent operations should not produce errors")
}

