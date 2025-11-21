package test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/api"
	v1 "github.com/prometheus/client_golang/api/prometheus/v1"
	"github.com/prometheus/common/model"
	"github.com/sirupsen/logrus"
)

// RangeLoadTestConfig holds configuration for range-specific load testing.
type RangeLoadTestConfig struct {
	GatewayURL       string
	Bucket           string // Target bucket name
	NumWorkers       int
	Duration         time.Duration
	QPS              int
	ObjectSize       int64  // Size of test objects in bytes
	ChunkSize        int64  // Encryption chunk size (affects range behavior)
	BaselineFile     string // File to store/load baseline metrics
	RegressionThreshold float64 // Max allowed regression percentage
}

// RangeTestScenario defines a specific range request test case.
type RangeTestScenario struct {
	Name         string
	RangeHeader  string
	Description  string
	ExpectedCode int
}

// MultipartLoadTestConfig holds configuration for multipart-specific load testing.
type MultipartLoadTestConfig struct {
	GatewayURL       string
	Bucket           string // Target bucket name
	NumWorkers       int
	Duration         time.Duration
	QPS              int
	ObjectSize       int64  // Total object size
	PartSize         int64  // Size of each part
	BaselineFile     string
	RegressionThreshold float64
}

// LoadTestMetrics holds comprehensive metrics for regression tracking.
type LoadTestMetrics struct {
	Timestamp           time.Time         `json:"timestamp"`
	TestName            string            `json:"test_name"`
	Duration            time.Duration     `json:"duration"`
	TotalRequests       int64             `json:"total_requests"`
	SuccessfulRequests  int64             `json:"successful_requests"`
	FailedRequests      int64             `json:"failed_requests"`
	P50Latency          time.Duration     `json:"p50_latency"`
	P95Latency          time.Duration     `json:"p95_latency"`
	P99Latency          time.Duration     `json:"p99_latency"`
	AvgLatency          time.Duration     `json:"avg_latency"`
	MinLatency          time.Duration     `json:"min_latency"`
	MaxLatency          time.Duration     `json:"max_latency"`
	Throughput          float64           `json:"throughput_req_per_sec"`
	TotalBytesSent      int64             `json:"total_bytes_sent"`
	TotalBytesReceived  int64             `json:"total_bytes_received"`
	ErrorRate           float64           `json:"error_rate"`
	RangeSpecific       *RangeMetrics     `json:"range_specific,omitempty"`
	MultipartSpecific   *MultipartMetrics `json:"multipart_specific,omitempty"`
}

// RangeMetrics holds range-specific metrics.
type RangeMetrics struct {
	FirstByteRanges     int64         `json:"first_byte_ranges"`
	LastByteRanges      int64         `json:"last_byte_ranges"`
	SuffixRanges        int64         `json:"suffix_ranges"`
	CrossChunkRanges    int64         `json:"cross_chunk_ranges"`
	InvalidRanges       int64         `json:"invalid_ranges"`
	AvgRangeSize        int64         `json:"avg_range_size"`
	TimeToFirstByteAvg  time.Duration `json:"time_to_first_byte_avg"`
	TimeToFirstByteP95  time.Duration `json:"time_to_first_byte_p95"`
}

// MultipartMetrics holds multipart-specific metrics.
type MultipartMetrics struct {
	TotalUploads        int64         `json:"total_uploads"`
	AvgPartsPerUpload   float64       `json:"avg_parts_per_upload"`
	AvgPartSize         int64         `json:"avg_part_size"`
	UploadTimeAvg       time.Duration `json:"upload_time_avg"`
	UploadTimeP95       time.Duration `json:"upload_time_p95"`
	FailedParts         int64         `json:"failed_parts"`
}

// RegressionResult holds the result of regression analysis.
type RegressionResult struct {
	TestName            string
	BaselineMetrics     *LoadTestMetrics
	CurrentMetrics      *LoadTestMetrics
	LatencyRegression   float64 // Percentage change in latency
	ThroughputRegression float64 // Percentage change in throughput
	ErrorRateRegression float64 // Percentage change in error rate
	SignificantRegression bool
	Details             []string
}

// RunRangeLoadTest runs comprehensive range request load tests.
func RunRangeLoadTest(config RangeLoadTestConfig, logger *logrus.Logger) (*LoadTestMetrics, error) {
	if logger == nil {
		logger = logrus.New()
		logger.SetLevel(logrus.InfoLevel)
	}

	logger.WithFields(logrus.Fields{
		"workers":     config.NumWorkers,
		"duration":    config.Duration,
		"qps":         config.QPS,
		"object_size": config.ObjectSize,
		"chunk_size":  config.ChunkSize,
	}).Info("Starting range load test")

	// Define range test scenarios
	scenarios := []RangeTestScenario{
		{
			Name:         "first_byte",
			RangeHeader:  "bytes=0-1023", // First 1KB
			Description:  "First byte range request",
			ExpectedCode: http.StatusPartialContent,
		},
		{
			Name:         "last_byte",
			RangeHeader:  fmt.Sprintf("bytes=%d-%d", config.ObjectSize-1024, config.ObjectSize-1), // Last 1KB
			Description:  "Last byte range request",
			ExpectedCode: http.StatusPartialContent,
		},
		{
			Name:         "suffix",
			RangeHeader:  "bytes=-1024", // Last 1KB using suffix
			Description:  "Suffix range request",
			ExpectedCode: http.StatusPartialContent,
		},
		{
			Name:         "middle_chunk",
			RangeHeader:  fmt.Sprintf("bytes=%d-%d", config.ChunkSize/2, config.ChunkSize/2+1023), // Cross chunk boundary
			Description:  "Range crossing chunk boundary",
			ExpectedCode: http.StatusPartialContent,
		},
		{
			Name:         "large_range",
			RangeHeader:  fmt.Sprintf("bytes=%d-%d", config.ObjectSize/4, config.ObjectSize/2), // Large range
			Description:  "Large range request",
			ExpectedCode: http.StatusPartialContent,
		},
		{
			Name:         "invalid_range",
			RangeHeader:  "bytes=999999999-1000000000", // Out of bounds
			Description:  "Invalid range request",
			ExpectedCode: http.StatusRequestedRangeNotSatisfiable,
		},
	}

	results := &LoadTestMetrics{
		Timestamp:     time.Now(),
		TestName:      "range_load_test",
		MinLatency:    time.Hour,
		RangeSpecific: &RangeMetrics{},
	}

	// Create test objects first
	if err := prepareRangeTestObjects(config, scenarios, logger); err != nil {
		return nil, fmt.Errorf("failed to prepare test objects: %w", err)
	}

	// Run the load test
	metrics, err := runRangeLoadTestInternal(config, scenarios, logger)
	if err != nil {
		return nil, err
	}

	*results = *metrics
	results.Timestamp = time.Now()
	results.TestName = "range_load_test"

	// Save metrics for regression tracking
	if config.BaselineFile != "" {
		if err := saveBaselineMetrics(results, config.BaselineFile); err != nil {
			logger.WithError(err).Warn("Failed to save baseline metrics")
		}
	}

	return results, nil
}

// RunMultipartLoadTest runs comprehensive multipart upload load tests.
func RunMultipartLoadTest(config MultipartLoadTestConfig, logger *logrus.Logger) (*LoadTestMetrics, error) {
	if logger == nil {
		logger = logrus.New()
		logger.SetLevel(logrus.InfoLevel)
	}

	logger.WithFields(logrus.Fields{
		"workers":     config.NumWorkers,
		"duration":    config.Duration,
		"qps":         config.QPS,
		"object_size": config.ObjectSize,
		"part_size":   config.PartSize,
	}).Info("Starting multipart load test")

	results := &LoadTestMetrics{
		Timestamp:          time.Now(),
		TestName:           "multipart_load_test",
		MinLatency:         time.Hour,
		MultipartSpecific:  &MultipartMetrics{},
	}

	// Run the load test
	metrics, err := runMultipartLoadTestInternal(config, logger)
	if err != nil {
		return nil, err
	}

	*results = *metrics
	results.Timestamp = time.Now()
	results.TestName = "multipart_load_test"

	// Save metrics for regression tracking
	if config.BaselineFile != "" {
		if err := saveBaselineMetrics(results, config.BaselineFile); err != nil {
			logger.WithError(err).Warn("Failed to save baseline metrics")
		}
	}

	return results, nil
}

// prepareRangeTestObjects creates test objects for range testing.
func prepareRangeTestObjects(config RangeLoadTestConfig, scenarios []RangeTestScenario, logger *logrus.Logger) error {
	client := &http.Client{Timeout: 30 * time.Second}

	// Create one large test object
	objectKey := "range-test-object"
	data := make([]byte, config.ObjectSize)
	for i := range data {
		data[i] = byte(i % 256)
	}

	bucket := config.Bucket
	if bucket == "" {
		bucket = "test-bucket"
	}

	putURL := fmt.Sprintf("%s/%s/%s", config.GatewayURL, bucket, objectKey)
	req, err := http.NewRequest("PUT", putURL, bytes.NewReader(data))
	if err != nil {
		return err
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to create test object: status %d", resp.StatusCode)
	}

	logger.Info("Prepared test object for range testing")
	return nil
}

// runRangeLoadTestInternal implements the core range load testing logic.
func runRangeLoadTestInternal(config RangeLoadTestConfig, scenarios []RangeTestScenario, logger *logrus.Logger) (*LoadTestMetrics, error) {
	results := &LoadTestMetrics{
		MinLatency:    time.Hour,
		RangeSpecific: &RangeMetrics{},
	}

	var wg sync.WaitGroup
	var latencies []time.Duration
	var latenciesMu sync.Mutex

	// Calculate interval between requests
	interval := time.Second / time.Duration(config.QPS)
	if interval <= 0 {
		interval = time.Millisecond
	}

	stopChan := make(chan struct{})
	startTime := time.Now()

	// Start workers
	for i := 0; i < config.NumWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			client := &http.Client{Timeout: 60 * time.Second}
			ticker := time.NewTicker(interval)
			defer ticker.Stop()

			requestCount := int64(0)

			for {
				select {
				case <-stopChan:
					return
				case <-ticker.C:
					// Select random scenario
					scenario := scenarios[requestCount%int64(len(scenarios))]

					reqStart := time.Now()
					objectKey := "range-test-object"
					bucket := config.Bucket
					if bucket == "" {
						bucket = "test-bucket"
					}
					getURL := fmt.Sprintf("%s/%s/%s", config.GatewayURL, bucket, objectKey)

					req, err := http.NewRequest("GET", getURL, nil)
					if err != nil {
						atomic.AddInt64(&results.FailedRequests, 1)
						continue
					}

					if scenario.RangeHeader != "" {
						req.Header.Set("Range", scenario.RangeHeader)
					}

					resp, err := client.Do(req)
					latency := time.Since(reqStart)
					atomic.AddInt64(&results.TotalRequests, 1)

					if err != nil || resp.StatusCode != scenario.ExpectedCode {
						atomic.AddInt64(&results.FailedRequests, 1)
						if resp != nil {
							resp.Body.Close()
						}
						continue
					}

					atomic.AddInt64(&results.SuccessfulRequests, 1)

					// Read response body to measure data transfer
					n, _ := io.Copy(io.Discard, resp.Body)
					atomic.AddInt64(&results.TotalBytesReceived, n)
					resp.Body.Close()

					// Record scenario-specific metrics
					recordRangeMetrics(results.RangeSpecific, scenario, latency)

					// Record latency
					latenciesMu.Lock()
					latencies = append(latencies, latency)
					if latency < results.MinLatency {
						results.MinLatency = latency
					}
					if latency > results.MaxLatency {
						results.MaxLatency = latency
					}
					latenciesMu.Unlock()

					requestCount++
				}
			}
		}(i)
	}

	// Run for specified duration
	time.Sleep(config.Duration)
	close(stopChan)
	wg.Wait()

	results.Duration = time.Since(startTime)

	// Calculate statistics
	if len(latencies) > 0 {
		// Sort latencies for percentiles
		sortedLatencies := make([]time.Duration, len(latencies))
		copy(sortedLatencies, latencies)

		// Simple percentile calculation
		results.AvgLatency = calculateAverageLatency(latencies)
		results.P50Latency = calculatePercentileLatency(sortedLatencies, 0.5)
		results.P95Latency = calculatePercentileLatency(sortedLatencies, 0.95)
		results.P99Latency = calculatePercentileLatency(sortedLatencies, 0.99)
	}

	results.Throughput = float64(results.TotalRequests) / results.Duration.Seconds()
	results.ErrorRate = float64(results.FailedRequests) / float64(results.TotalRequests)

	return results, nil
}

// runMultipartLoadTestInternal implements the core multipart load testing logic.
func runMultipartLoadTestInternal(config MultipartLoadTestConfig, logger *logrus.Logger) (*LoadTestMetrics, error) {
	results := &LoadTestMetrics{
		MinLatency:        time.Hour,
		MultipartSpecific: &MultipartMetrics{},
	}

	var wg sync.WaitGroup
	var latencies []time.Duration
	var latenciesMu sync.Mutex

	// Calculate interval between requests
	interval := time.Second / time.Duration(config.QPS)
	if interval <= 0 {
		interval = time.Millisecond
	}

	stopChan := make(chan struct{})
	startTime := time.Now()

	// Start workers
	for i := 0; i < config.NumWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			client := &http.Client{Timeout: 300 * time.Second} // 5 minutes for large multipart uploads
			ticker := time.NewTicker(interval)
			defer ticker.Stop()

			requestCount := int64(0)

			for {
				select {
				case <-stopChan:
					return
				case <-ticker.C:
					reqStart := time.Now()
					objectKey := fmt.Sprintf("multipart-load-test/worker-%d/obj-%d", workerID, requestCount)

					// Perform multipart upload
					err := performFullMultipartUpload(client, config, objectKey, logger)
					latency := time.Since(reqStart)

					atomic.AddInt64(&results.TotalRequests, 1)

					if err != nil {
						atomic.AddInt64(&results.FailedRequests, 1)
						logger.WithError(err).WithField("object", objectKey).Debug("Multipart upload failed")
						continue
					}

					atomic.AddInt64(&results.SuccessfulRequests, 1)
					atomic.AddInt64(&results.TotalBytesSent, config.ObjectSize)

					// Record multipart-specific metrics
					recordMultipartMetrics(results.MultipartSpecific, config, latency)

					// Record latency
					latenciesMu.Lock()
					latencies = append(latencies, latency)
					if latency < results.MinLatency {
						results.MinLatency = latency
					}
					if latency > results.MaxLatency {
						results.MaxLatency = latency
					}
					latenciesMu.Unlock()

					requestCount++
				}
			}
		}(i)
	}

	// Run for specified duration
	time.Sleep(config.Duration)
	close(stopChan)
	wg.Wait()

	results.Duration = time.Since(startTime)

	// Calculate statistics
	if len(latencies) > 0 {
		sortedLatencies := make([]time.Duration, len(latencies))
		copy(sortedLatencies, latencies)

		results.AvgLatency = calculateAverageLatency(latencies)
		results.P50Latency = calculatePercentileLatency(sortedLatencies, 0.5)
		results.P95Latency = calculatePercentileLatency(sortedLatencies, 0.95)
		results.P99Latency = calculatePercentileLatency(sortedLatencies, 0.99)
	}

	results.Throughput = float64(results.TotalRequests) / results.Duration.Seconds()
	results.ErrorRate = float64(results.FailedRequests) / float64(results.TotalRequests)

	return results, nil
}

// performFullMultipartUpload performs a complete multipart upload operation.
func performFullMultipartUpload(client *http.Client, config MultipartLoadTestConfig, objectKey string, logger *logrus.Logger) error {
	bucket := config.Bucket
	if bucket == "" {
		bucket = "test-bucket"
	}
	url := fmt.Sprintf("%s/%s/%s", config.GatewayURL, bucket, objectKey)

	// Generate data
	data := make([]byte, config.ObjectSize)
	for i := range data {
		data[i] = byte((i + int(time.Now().UnixNano())) % 256)
	}

	// For simplicity, we'll use regular PUT for smaller objects
	// In a real S3 multipart implementation, this would follow the proper S3 multipart protocol
	if config.ObjectSize <= 100*1024*1024 { // <= 100MB
		req, err := http.NewRequest("PUT", url, bytes.NewReader(data))
		if err != nil {
			return err
		}

		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("upload failed with status %d", resp.StatusCode)
		}

		return nil
	}

	// For larger objects, simulate multipart by uploading in parts
	partSize := config.PartSize
	if partSize <= 0 {
		partSize = 100 * 1024 * 1024 // 100MB default
	}

	for offset := int64(0); offset < config.ObjectSize; offset += partSize {
		end := offset + partSize
		if end > config.ObjectSize {
			end = config.ObjectSize
		}

		req, err := http.NewRequest("PUT", url, bytes.NewReader(data[offset:end]))
		if err != nil {
			return err
		}

		// Add part number header for simulation
		partNumber := (offset / partSize) + 1
		req.Header.Set("X-Part-Number", fmt.Sprintf("%d", partNumber))
		req.Header.Set("X-Object-Offset", fmt.Sprintf("%d", offset))

		resp, err := client.Do(req)
		if err != nil {
			return err
		}

		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("part upload failed with status %d", resp.StatusCode)
		}
	}

	return nil
}

// Helper functions for metrics calculation
func recordRangeMetrics(metrics *RangeMetrics, scenario RangeTestScenario, latency time.Duration) {
	switch scenario.Name {
	case "first_byte":
		atomic.AddInt64(&metrics.FirstByteRanges, 1)
	case "last_byte":
		atomic.AddInt64(&metrics.LastByteRanges, 1)
	case "suffix":
		atomic.AddInt64(&metrics.SuffixRanges, 1)
	case "middle_chunk":
		atomic.AddInt64(&metrics.CrossChunkRanges, 1)
	case "invalid_range":
		atomic.AddInt64(&metrics.InvalidRanges, 1)
	}

	// Update time-to-first-byte metrics (simplified)
	atomic.AddInt64((*int64)(&metrics.TimeToFirstByteAvg), int64(latency))
	atomic.AddInt64((*int64)(&metrics.TimeToFirstByteP95), int64(latency))
}

func recordMultipartMetrics(metrics *MultipartMetrics, config MultipartLoadTestConfig, latency time.Duration) {
	atomic.AddInt64(&metrics.TotalUploads, 1)

	atomic.AddInt64((*int64)(&metrics.AvgPartSize), config.PartSize)
	atomic.AddInt64((*int64)(&metrics.UploadTimeAvg), int64(latency))
	atomic.AddInt64((*int64)(&metrics.UploadTimeP95), int64(latency))
}

func calculateAverageLatency(latencies []time.Duration) time.Duration {
	if len(latencies) == 0 {
		return 0
	}

	var total time.Duration
	for _, lat := range latencies {
		total += lat
	}
	return total / time.Duration(len(latencies))
}

func calculatePercentileLatency(latencies []time.Duration, percentile float64) time.Duration {
	if len(latencies) == 0 {
		return 0
	}

	// Simple implementation - sort and pick
	for i := 0; i < len(latencies)-1; i++ {
		for j := i + 1; j < len(latencies); j++ {
			if latencies[i] > latencies[j] {
				latencies[i], latencies[j] = latencies[j], latencies[i]
			}
		}
	}

	index := int(float64(len(latencies)-1) * percentile)
	return latencies[index]
}

// Baseline and regression tracking functions
func saveBaselineMetrics(metrics *LoadTestMetrics, filename string) error {
	// Ensure directory exists
	dir := filepath.Dir(filename)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(metrics, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filename, data, 0644)
}

func loadBaselineMetrics(filename string) (*LoadTestMetrics, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var metrics LoadTestMetrics
	if err := json.Unmarshal(data, &metrics); err != nil {
		return nil, err
	}

	return &metrics, nil
}

// AnalyzeRegression compares current metrics against baseline and detects regressions.
func AnalyzeRegression(current *LoadTestMetrics, baselineFile string, threshold float64) (*RegressionResult, error) {
	baseline, err := loadBaselineMetrics(baselineFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load baseline metrics: %w", err)
	}

	result := &RegressionResult{
		TestName:        current.TestName,
		BaselineMetrics: baseline,
		CurrentMetrics:  current,
		Details:         []string{},
	}

	// Calculate latency regression
	if baseline.AvgLatency > 0 {
		latencyChange := float64(current.AvgLatency-baseline.AvgLatency) / float64(baseline.AvgLatency) * 100
		result.LatencyRegression = latencyChange
		if math.Abs(latencyChange) > threshold {
			result.SignificantRegression = true
			result.Details = append(result.Details, fmt.Sprintf("Latency regression: %.2f%% (threshold: %.2f%%)", latencyChange, threshold))
		}
	}

	// Calculate throughput regression
	if baseline.Throughput > 0 {
		throughputChange := (current.Throughput - baseline.Throughput) / baseline.Throughput * 100
		result.ThroughputRegression = throughputChange
		if math.Abs(throughputChange) > threshold {
			result.SignificantRegression = true
			result.Details = append(result.Details, fmt.Sprintf("Throughput regression: %.2f%% (threshold: %.2f%%)", throughputChange, threshold))
		}
	}

	// Calculate error rate regression
	if baseline.ErrorRate >= 0 {
		errorRateChange := current.ErrorRate - baseline.ErrorRate
		result.ErrorRateRegression = errorRateChange * 100 // Convert to percentage points
		if errorRateChange > threshold/100 { // threshold is in percentage
			result.SignificantRegression = true
			result.Details = append(result.Details, fmt.Sprintf("Error rate increased by %.2f percentage points", errorRateChange*100))
		}
	}

	return result, nil
}

// PrintLoadTestResults prints comprehensive load test results.
func PrintLoadTestResults(results *LoadTestMetrics) {
	fmt.Printf("\n=== %s Results ===\n", results.TestName)
	fmt.Printf("Timestamp: %s\n", results.Timestamp.Format(time.RFC3339))
	fmt.Printf("Duration: %v\n", results.Duration)
	fmt.Printf("Total Requests: %d\n", results.TotalRequests)
	fmt.Printf("Successful: %d\n", results.SuccessfulRequests)
	fmt.Printf("Failed: %d\n", results.FailedRequests)
	fmt.Printf("Error Rate: %.2f%%\n", results.ErrorRate*100)
	fmt.Printf("Throughput: %.2f req/s\n", results.Throughput)
	fmt.Printf("Latency (avg): %v\n", results.AvgLatency)
	fmt.Printf("Latency (p50): %v\n", results.P50Latency)
	fmt.Printf("Latency (p95): %v\n", results.P95Latency)
	fmt.Printf("Latency (p99): %v\n", results.P99Latency)
	fmt.Printf("Min Latency: %v\n", results.MinLatency)
	fmt.Printf("Max Latency: %v\n", results.MaxLatency)
	fmt.Printf("Total Bytes Sent: %d\n", results.TotalBytesSent)
	fmt.Printf("Total Bytes Received: %d\n", results.TotalBytesReceived)

	if results.RangeSpecific != nil {
		fmt.Printf("\n--- Range-Specific Metrics ---\n")
		fmt.Printf("First Byte Ranges: %d\n", results.RangeSpecific.FirstByteRanges)
		fmt.Printf("Last Byte Ranges: %d\n", results.RangeSpecific.LastByteRanges)
		fmt.Printf("Suffix Ranges: %d\n", results.RangeSpecific.SuffixRanges)
		fmt.Printf("Cross-Chunk Ranges: %d\n", results.RangeSpecific.CrossChunkRanges)
		fmt.Printf("Invalid Ranges: %d\n", results.RangeSpecific.InvalidRanges)
		fmt.Printf("Time to First Byte (avg): %v\n", results.RangeSpecific.TimeToFirstByteAvg)
		fmt.Printf("Time to First Byte (p95): %v\n", results.RangeSpecific.TimeToFirstByteP95)
	}

	if results.MultipartSpecific != nil {
		fmt.Printf("\n--- Multipart-Specific Metrics ---\n")
		fmt.Printf("Total Uploads: %d\n", results.MultipartSpecific.TotalUploads)
		fmt.Printf("Average Parts per Upload: %.2f\n", results.MultipartSpecific.AvgPartsPerUpload)
		fmt.Printf("Average Part Size: %d\n", results.MultipartSpecific.AvgPartSize)
		fmt.Printf("Upload Time (avg): %v\n", results.MultipartSpecific.UploadTimeAvg)
		fmt.Printf("Upload Time (p95): %v\n", results.MultipartSpecific.UploadTimeP95)
		fmt.Printf("Failed Parts: %d\n", results.MultipartSpecific.FailedParts)
	}

	fmt.Printf("==============================\n\n")
}

// PrintRegressionResult prints regression analysis results.
func PrintRegressionResult(result *RegressionResult) {
	fmt.Printf("\n=== Regression Analysis for %s ===\n", result.TestName)
	fmt.Printf("Significant Regression: %t\n", result.SignificantRegression)
	fmt.Printf("Latency Regression: %.2f%%\n", result.LatencyRegression)
	fmt.Printf("Throughput Regression: %.2f%%\n", result.ThroughputRegression)
	fmt.Printf("Error Rate Regression: %.2f percentage points\n", result.ErrorRateRegression)

	if len(result.Details) > 0 {
		fmt.Printf("\nDetails:\n")
		for _, detail := range result.Details {
			fmt.Printf("- %s\n", detail)
		}
	}

	fmt.Printf("=====================================\n\n")
}

// QueryPrometheusMetrics queries Prometheus for additional metrics during load testing.
func QueryPrometheusMetrics(prometheusURL string, startTime, endTime time.Time) (map[string]interface{}, error) {
	client, err := api.NewClient(api.Config{
		Address: prometheusURL,
	})
	if err != nil {
		return nil, err
	}

	v1api := v1.NewAPI(client)

	// Query for key metrics during the test period
	queries := map[string]string{
		"http_request_duration_seconds": `histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m]))`,
		"s3_operation_duration_seconds": `histogram_quantile(0.95, rate(s3_operation_duration_seconds_bucket[5m]))`,
		"encryption_duration_seconds":   `histogram_quantile(0.95, rate(encryption_duration_seconds_bucket[5m]))`,
		"memory_alloc_bytes":           `avg_over_time(memory_alloc_bytes[5m])`,
		"goroutines":                   `avg_over_time(goroutines[5m])`,
	}

	results := make(map[string]interface{})

	for name, query := range queries {
		value, warnings, err := v1api.Query(context.Background(), query, endTime)
		if err != nil {
			return nil, fmt.Errorf("failed to query %s: %w", name, err)
		}

		if len(warnings) > 0 {
			fmt.Printf("Warnings for query %s: %v\n", name, warnings)
		}

		// Extract scalar value
		if vector, ok := value.(model.Vector); ok && len(vector) > 0 {
			results[name] = float64(vector[0].Value)
		}
	}

	return results, nil
}
