//go:build integration
// +build integration

package test

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kenneth/s3-encryption-gateway/internal/config"
	"github.com/kenneth/s3-encryption-gateway/internal/crypto"
	"github.com/stretchr/testify/require"
)

// TestBackblazeB2_MultipartUpload tests multipart upload functionality.
func TestBackblazeB2_MultipartUpload(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	gateway, tracker, bucket, cleanup := setupB2TestWithCleanup(t, "multipart")
	defer cleanup()

	// Create a file large enough to trigger multipart (5MB)
	testKey := fmt.Sprintf("%smultipart-test", tracker.Prefix())
	testData := bytes.Repeat([]byte("A"), 5*1024*1024)

	// PUT large object (should use multipart internally)
	putURL := fmt.Sprintf("http://%s/%s/%s", gateway.Addr, bucket, testKey)
	putReq, err := http.NewRequest("PUT", putURL, bytes.NewReader(testData))
	require.NoError(t, err)
	putReq.Header.Set("Content-Type", "application/octet-stream")

	putResp, err := http.DefaultClient.Do(putReq)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, putResp.StatusCode, "PUT should succeed")
	putResp.Body.Close()

	// Track for cleanup
	tracker.Track(testKey)

	// GET and verify
	getURL := fmt.Sprintf("http://%s/%s/%s", gateway.Addr, bucket, testKey)
	getResp, err := http.Get(getURL)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, getResp.StatusCode, "GET should succeed")
	defer getResp.Body.Close()

	gotData, err := io.ReadAll(getResp.Body)
	require.NoError(t, err)
	require.Equal(t, len(testData), len(gotData), "Data size should match")
	require.Equal(t, testData, gotData, "Data should match")
}

// TestBackblazeB2_RangeRequest tests range request functionality.
func TestBackblazeB2_RangeRequest(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	gateway, tracker, bucket, cleanup := setupB2TestWithCleanup(t, "range")
	defer cleanup()

	// Create test data
	testKey := fmt.Sprintf("%srange-test", tracker.Prefix())
	testData := bytes.Repeat([]byte("0123456789"), 100) // 1000 bytes

	// PUT object
	putURL := fmt.Sprintf("http://%s/%s/%s", gateway.Addr, bucket, testKey)
	putReq, err := http.NewRequest("PUT", putURL, bytes.NewReader(testData))
	require.NoError(t, err)

	putResp, err := http.DefaultClient.Do(putReq)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, putResp.StatusCode)
	putResp.Body.Close()

	tracker.Track(testKey)

	// Test range request: bytes 0-499 (first 500 bytes)
	getURL := fmt.Sprintf("http://%s/%s/%s", gateway.Addr, bucket, testKey)
	getReq, err := http.NewRequest("GET", getURL, nil)
	require.NoError(t, err)
	getReq.Header.Set("Range", "bytes=0-499")

	getResp, err := http.DefaultClient.Do(getReq)
	require.NoError(t, err)
	require.Equal(t, http.StatusPartialContent, getResp.StatusCode, "Should return 206 Partial Content")
	defer getResp.Body.Close()

	gotData, err := io.ReadAll(getResp.Body)
	require.NoError(t, err)
	require.Equal(t, 500, len(gotData), "Should return 500 bytes")
	require.Equal(t, testData[:500], gotData, "Range data should match")

	// Test range request: bytes 500-999 (last 500 bytes)
	getReq2, err := http.NewRequest("GET", getURL, nil)
	require.NoError(t, err)
	getReq2.Header.Set("Range", "bytes=500-999")

	getResp2, err := http.DefaultClient.Do(getReq2)
	require.NoError(t, err)
	require.Equal(t, http.StatusPartialContent, getResp2.StatusCode)
	defer getResp2.Body.Close()

	gotData2, err := io.ReadAll(getResp2.Body)
	require.NoError(t, err)
	require.Equal(t, 500, len(gotData2), "Should return 500 bytes")
	require.Equal(t, testData[500:], gotData2, "Range data should match")
}

// TestBackblazeB2_BatchDelete tests batch delete operation.
func TestBackblazeB2_BatchDelete(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	gateway, tracker, bucket, cleanup := setupB2TestWithCleanup(t, "batch-delete")
	defer cleanup()

	client := gateway.GetHTTPClient()

	// Upload multiple objects
	keys := []string{
		fmt.Sprintf("%sbatch-1", tracker.Prefix()),
		fmt.Sprintf("%sbatch-2", tracker.Prefix()),
		fmt.Sprintf("%sbatch-3", tracker.Prefix()),
	}

	for _, key := range keys {
		testData := []byte(fmt.Sprintf("Test data for %s", key))
		putURL := fmt.Sprintf("http://%s/%s/%s", gateway.Addr, bucket, key)
		putReq, err := http.NewRequest("PUT", putURL, bytes.NewReader(testData))
		require.NoError(t, err)

		putResp, err := client.Do(putReq)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, putResp.StatusCode)
		putResp.Body.Close()

		tracker.Track(key)
	}

	// Batch delete
	deleteXML := fmt.Sprintf(`<Delete>
		<Object><Key>%s</Key></Object>
		<Object><Key>%s</Key></Object>
		<Object><Key>%s</Key></Object>
	</Delete>`, keys[0], keys[1], keys[2])

	deleteURL := fmt.Sprintf("http://%s/%s?delete", gateway.Addr, bucket)
	deleteReq, err := http.NewRequest("POST", deleteURL, bytes.NewReader([]byte(deleteXML)))
	require.NoError(t, err)
	deleteReq.Header.Set("Content-Type", "application/xml")

	deleteResp, err := client.Do(deleteReq)
	require.NoError(t, err)
	defer deleteResp.Body.Close()

	require.Equal(t, http.StatusOK, deleteResp.StatusCode, "Batch delete should succeed")

	// Verify objects are deleted
	for _, key := range keys {
		getURL := fmt.Sprintf("http://%s/%s/%s", gateway.Addr, bucket, key)
		getResp, err := http.Get(getURL)
		require.NoError(t, err)
		defer getResp.Body.Close()
		require.Equal(t, http.StatusNotFound, getResp.StatusCode, "Object should be deleted")
	}
}

// TestBackblazeB2_ListObjects tests list objects operation.
func TestBackblazeB2_ListObjects(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	gateway, tracker, bucket, cleanup := setupB2TestWithCleanup(t, "list")
	defer cleanup()

	client := gateway.GetHTTPClient()

	// Upload multiple objects
	keys := []string{
		fmt.Sprintf("%slist-1", tracker.Prefix()),
		fmt.Sprintf("%slist-2", tracker.Prefix()),
		fmt.Sprintf("%slist-3", tracker.Prefix()),
	}

	for _, key := range keys {
		testData := []byte(fmt.Sprintf("Test data for %s", key))
		putURL := fmt.Sprintf("http://%s/%s/%s", gateway.Addr, bucket, key)
		putReq, err := http.NewRequest("PUT", putURL, bytes.NewReader(testData))
		require.NoError(t, err)

		putResp, err := client.Do(putReq)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, putResp.StatusCode)
		putResp.Body.Close()

		tracker.Track(key)
	}

	// List objects with prefix
	listURL := fmt.Sprintf("http://%s/%s?prefix=%s", gateway.Addr, bucket, tracker.Prefix())
	listResp, err := http.Get(listURL)
	require.NoError(t, err)
	defer listResp.Body.Close()

	require.Equal(t, http.StatusOK, listResp.StatusCode, "List should succeed")

	body, err := io.ReadAll(listResp.Body)
	require.NoError(t, err)

	// Parse XML response
	var result struct {
		Contents []struct {
			Key string `xml:"Key"`
		} `xml:"Contents"`
	}
	err = xml.Unmarshal(body, &result)
	require.NoError(t, err, "Should parse list response XML")

	// Verify we got our objects
	foundKeys := make(map[string]bool)
	for _, obj := range result.Contents {
		foundKeys[obj.Key] = true
	}

	for _, key := range keys {
		require.True(t, foundKeys[key], "Object %s should be in list", key)
	}
}

// TestBackblazeB2_WithCosmianKMS_Extended tests KMS integration with comprehensive cleanup.
func TestBackblazeB2_WithCosmianKMS_Extended(t *testing.T) {
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

	// Create test prefix
	testPrefix := GetTestPrefix("kms-extended")

	// Create S3 client for cleanup
	backendCfg := getB2BackendConfig(accessKey, secretKey)
	s3Client, err := CreateS3ClientForCleanup(backendCfg)
	require.NoError(t, err, "Failed to create S3 client for cleanup")

	// Create object tracker
	tracker := NewObjectTracker(bucket, testPrefix, "backblaze", s3Client)
	defer func() {
		ctx := context.Background()
		tracker.Cleanup(ctx, t)
	}()

	// Create gateway config with KMS
	cfg := &config.Config{
		ListenAddr: ":0",
		LogLevel:   "error",
		Backend:    *backendCfg,
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

	// Test multiple objects with KMS
	testKeys := []string{
		fmt.Sprintf("%skms-1", testPrefix),
		fmt.Sprintf("%skms-2", testPrefix),
		fmt.Sprintf("%skms-3", testPrefix),
	}

	for _, testKey := range testKeys {
		testData := []byte(fmt.Sprintf("KMS test data for %s", testKey))

		// PUT encrypted object with KMS
		putURL := fmt.Sprintf("%s/%s/%s", gateway.URL, bucket, testKey)
		putReq, err := http.NewRequest("PUT", putURL, bytes.NewReader(testData))
		require.NoError(t, err)
		putReq.Header.Set("Content-Type", "text/plain")

		putResp, err := http.DefaultClient.Do(putReq)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, putResp.StatusCode, "PUT should succeed")
		putResp.Body.Close()

		// Track for cleanup
		tracker.Track(testKey)

		// GET and verify decryption
		getURL := fmt.Sprintf("%s/%s/%s", gateway.URL, bucket, testKey)
		getResp, err := http.Get(getURL)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, getResp.StatusCode, "GET should succeed")
		defer getResp.Body.Close()

		gotData, err := io.ReadAll(getResp.Body)
		require.NoError(t, err)
		require.Equal(t, testData, gotData, "Decrypted data should match original")
	}
}

// TestBackblazeB2_LoadTest runs a load test against Backblaze B2.
func TestBackblazeB2_LoadTest(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping load test in short mode")
	}

	gateway, tracker, bucket, cleanup := setupB2TestWithCleanup(t, "load")
	defer cleanup()

	// Custom load test for Backblaze (load_test.go uses hardcoded "test-bucket")
	const numWorkers = 5
	const duration = 30 * time.Second
	const qps = 2 // requests per second per worker
	const objectSize = 1024 // 1KB

	client := &http.Client{Timeout: 30 * time.Second}
	interval := time.Second / time.Duration(qps)
	if interval <= 0 {
		interval = time.Millisecond
	}

	var totalRequests, successfulReqs, failedReqs int64
	stopChan := make(chan struct{})
	doneChan := make(chan struct{})

	// Start workers
	for workerID := 0; workerID < numWorkers; workerID++ {
		go func(id int) {
			ticker := time.NewTicker(interval)
			defer ticker.Stop()

			requestCount := 0
			for {
				select {
				case <-stopChan:
					doneChan <- struct{}{}
					return
				case <-ticker.C:
					objectKey := fmt.Sprintf("%sload-test/worker-%d/obj-%d", tracker.Prefix(), id, requestCount)
					data := make([]byte, objectSize)
					for j := range data {
						data[j] = byte(j % 256)
					}

					// PUT
					putURL := fmt.Sprintf("http://%s/%s/%s", gateway.Addr, bucket, objectKey)
					putReq, err := http.NewRequest("PUT", putURL, bytes.NewReader(data))
					if err != nil {
						atomic.AddInt64(&failedReqs, 1)
						atomic.AddInt64(&totalRequests, 1)
						continue
					}

					putResp, err := client.Do(putReq)
					atomic.AddInt64(&totalRequests, 1)
					if err != nil || putResp.StatusCode != http.StatusOK {
						atomic.AddInt64(&failedReqs, 1)
						if putResp != nil {
							putResp.Body.Close()
						}
						continue
					}
					putResp.Body.Close()

					// Track for cleanup
					tracker.Track(objectKey)

					// GET
					getURL := fmt.Sprintf("http://%s/%s/%s", gateway.Addr, bucket, objectKey)
					getResp, err := http.Get(getURL)
					if err != nil || getResp.StatusCode != http.StatusOK {
						atomic.AddInt64(&failedReqs, 1)
						if getResp != nil {
							getResp.Body.Close()
						}
						continue
					}
					getResp.Body.Close()

					atomic.AddInt64(&successfulReqs, 1)
					requestCount++
				}
			}
		}(workerID)
	}

	// Run for specified duration
	time.Sleep(duration)
	close(stopChan)

	// Wait for all workers to finish
	for i := 0; i < numWorkers; i++ {
		<-doneChan
	}

	// Verify results
	require.Greater(t, totalRequests, int64(0), "Should have made some requests")
	require.Greater(t, successfulReqs, int64(0), "Should have successful requests")
	
	failureRate := float64(failedReqs) / float64(totalRequests)
	require.Less(t, failureRate, 0.1, "Failure rate should be < 10%%")

	throughput := float64(totalRequests) / duration.Seconds()
	t.Logf("Load test results: Total=%d, Success=%d, Failed=%d, Throughput=%.2f req/s, FailureRate=%.2f%%",
		totalRequests, successfulReqs, failedReqs, throughput, failureRate*100)
}

