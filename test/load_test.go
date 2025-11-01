package test

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"
)

// LoadTestConfig holds configuration for load testing.
type LoadTestConfig struct {
	GatewayURL string
	NumWorkers int
	Duration   time.Duration
	QPS        int // Queries per second per worker
	ObjectSize int // Size of test objects in bytes
}

// LoadTestResults holds the results of a load test.
type LoadTestResults struct {
	TotalRequests    int64
	SuccessfulReqs   int64
	FailedReqs       int64
	TotalDuration    time.Duration
	AvgLatency       time.Duration
	MinLatency       time.Duration
	MaxLatency       time.Duration
	Throughput       float64 // requests per second
	TotalBytesSent   int64
	TotalBytesRecv   int64
}

// RunLoadTest runs a load test against the gateway.
func RunLoadTest(config LoadTestConfig, logger *logrus.Logger) (*LoadTestResults, error) {
	if logger == nil {
		logger = logrus.New()
		logger.SetLevel(logrus.InfoLevel)
	}

	logger.WithFields(logrus.Fields{
		"workers":    config.NumWorkers,
		"duration":   config.Duration,
		"qps":        config.QPS,
		"object_size": config.ObjectSize,
	}).Info("Starting load test")

	results := &LoadTestResults{
		MinLatency: time.Hour, // Initialize with a large value
	}

	startTime := time.Now()
	var wg sync.WaitGroup
	var latencies []time.Duration
	latenciesMu := &sync.Mutex{}

	// Calculate interval between requests
	interval := time.Second / time.Duration(config.QPS)
	if interval <= 0 {
		interval = time.Millisecond
	}

	// Start workers
	stopChan := make(chan struct{})
	for i := 0; i < config.NumWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			client := &http.Client{
				Timeout: 30 * time.Second,
			}

			ticker := time.NewTicker(interval)
			defer ticker.Stop()

			requestCount := 0
			for {
				select {
				case <-stopChan:
					return
				case <-ticker.C:
					// Perform PUT request
					objectKey := fmt.Sprintf("load-test/worker-%d/obj-%d", workerID, requestCount)
					data := make([]byte, config.ObjectSize)
					for j := range data {
						data[j] = byte(j % 256)
					}

					reqStart := time.Now()
					putURL := fmt.Sprintf("%s/test-bucket/%s", config.GatewayURL, objectKey)
					putReq, err := http.NewRequest("PUT", putURL, bytes.NewReader(data))
					if err != nil {
						atomic.AddInt64(&results.FailedReqs, 1)
						continue
					}

					resp, err := client.Do(putReq)
					latency := time.Since(reqStart)
					atomic.AddInt64(&results.TotalRequests, 1)

					if err != nil || resp.StatusCode != http.StatusOK {
						atomic.AddInt64(&results.FailedReqs, 1)
						if resp != nil {
							resp.Body.Close()
						}
					} else {
						atomic.AddInt64(&results.SuccessfulReqs, 1)
						atomic.AddInt64(&results.TotalBytesSent, int64(len(data)))
						resp.Body.Close()

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
					}

					// Perform GET request
					getURL := fmt.Sprintf("%s/test-bucket/%s", config.GatewayURL, objectKey)
					getReqStart := time.Now()
					getReq, err := http.NewRequest("GET", getURL, nil)
					if err != nil {
						atomic.AddInt64(&results.FailedReqs, 1)
						continue
					}

					getResp, err := client.Do(getReq)
					getLatency := time.Since(getReqStart)
					atomic.AddInt64(&results.TotalRequests, 1)

					if err != nil || getResp.StatusCode != http.StatusOK {
						atomic.AddInt64(&results.FailedReqs, 1)
						if getResp != nil {
							getResp.Body.Close()
						}
					} else {
						atomic.AddInt64(&results.SuccessfulReqs, 1)
						n, _ := io.Copy(io.Discard, getResp.Body)
						atomic.AddInt64(&results.TotalBytesRecv, n)
						getResp.Body.Close()

						// Record latency
						latenciesMu.Lock()
						latencies = append(latencies, getLatency)
						if getLatency < results.MinLatency {
							results.MinLatency = getLatency
						}
						if getLatency > results.MaxLatency {
							results.MaxLatency = getLatency
						}
						latenciesMu.Unlock()
					}

					requestCount++
				}
			}
		}(i)
	}

	// Run for specified duration
	time.Sleep(config.Duration)
	close(stopChan)

	// Wait for all workers to finish
	wg.Wait()

	results.TotalDuration = time.Since(startTime)

	// Calculate average latency
	if len(latencies) > 0 {
		var total time.Duration
		for _, lat := range latencies {
			total += lat
		}
		results.AvgLatency = total / time.Duration(len(latencies))
	}

	// Calculate throughput
	if results.TotalDuration > 0 {
		results.Throughput = float64(results.TotalRequests) / results.TotalDuration.Seconds()
	}

	return results, nil
}

// PrintLoadTestResults prints load test results in a formatted way.
func PrintLoadTestResults(results *LoadTestResults) {
	fmt.Printf("\n=== Load Test Results ===\n")
	fmt.Printf("Duration: %v\n", results.TotalDuration)
	fmt.Printf("Total Requests: %d\n", results.TotalRequests)
	fmt.Printf("Successful: %d\n", results.SuccessfulReqs)
	fmt.Printf("Failed: %d\n", results.FailedReqs)
	fmt.Printf("Success Rate: %.2f%%\n", float64(results.SuccessfulReqs)/float64(results.TotalRequests)*100)
	fmt.Printf("Throughput: %.2f req/s\n", results.Throughput)
	fmt.Printf("Average Latency: %v\n", results.AvgLatency)
	fmt.Printf("Min Latency: %v\n", results.MinLatency)
	fmt.Printf("Max Latency: %v\n", results.MaxLatency)
	fmt.Printf("Total Bytes Sent: %d\n", results.TotalBytesSent)
	fmt.Printf("Total Bytes Received: %d\n", results.TotalBytesRecv)
	fmt.Printf("=======================\n\n")
}
