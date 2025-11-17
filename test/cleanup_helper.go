//go:build integration
// +build integration

package test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/kenneth/s3-encryption-gateway/internal/config"
	"github.com/kenneth/s3-encryption-gateway/internal/s3"
)

// CleanupConfig holds configuration for test cleanup behavior.
// Some providers (like Wasabi) have "Timed Deleted Storage" that charges
// for early deletion, so cleanup should be configurable per provider.
type CleanupConfig struct {
	// EnableCleanup controls whether objects should be deleted after tests.
	// Set to false for providers with timed deletion costs (e.g., Wasabi).
	EnableCleanup bool
	// Provider name for logging/debugging
	Provider string
}

// ProviderCleanupConfigs defines cleanup behavior per provider.
var ProviderCleanupConfigs = map[string]CleanupConfig{
	"backblaze": {
		EnableCleanup: true,  // Backblaze allows free deletion
		Provider:      "backblaze",
	},
	"wasabi": {
		EnableCleanup: false, // Wasabi charges for early deletion (< 90 days)
		Provider:      "wasabi",
	},
	"minio": {
		EnableCleanup: true, // MinIO is local, no cost
		Provider:      "minio",
	},
	"aws": {
		EnableCleanup: true, // AWS allows free deletion
		Provider:      "aws",
	},
	// Default: enable cleanup for unknown providers (can be overridden)
	"default": {
		EnableCleanup: true,
		Provider:      "default",
	},
}

// GetCleanupConfig returns cleanup configuration for a provider.
func GetCleanupConfig(provider string) CleanupConfig {
	if cfg, ok := ProviderCleanupConfigs[provider]; ok {
		return cfg
	}
	return ProviderCleanupConfigs["default"]
}

// ObjectTracker tracks objects created during tests for cleanup.
type ObjectTracker struct {
	mu      sync.Mutex
	objects []string
	bucket  string
	prefix  string
	config  CleanupConfig
	client  s3.Client
}

// Prefix returns the test prefix for this tracker.
func (ot *ObjectTracker) Prefix() string {
	return ot.prefix
}

// NewObjectTracker creates a new object tracker for test cleanup.
func NewObjectTracker(bucket, prefix string, provider string, client s3.Client) *ObjectTracker {
	config := GetCleanupConfig(provider)
	return &ObjectTracker{
		objects: make([]string, 0),
		bucket:  bucket,
		prefix:  prefix,
		config:  config,
		client:  client,
	}
}

// Track adds an object key to the tracker.
func (ot *ObjectTracker) Track(key string) {
	ot.mu.Lock()
	defer ot.mu.Unlock()
	ot.objects = append(ot.objects, key)
}

// Cleanup deletes all tracked objects if cleanup is enabled.
func (ot *ObjectTracker) Cleanup(ctx context.Context, t *testing.T) {
	ot.mu.Lock()
	defer ot.mu.Unlock()

	if !ot.config.EnableCleanup {
		t.Logf("Cleanup disabled for provider %s (timed deletion costs may apply)", ot.config.Provider)
		if len(ot.objects) > 0 {
			t.Logf("Warning: %d objects were created but not cleaned up: %v", len(ot.objects), ot.objects)
		}
		return
	}

	if len(ot.objects) == 0 {
		return
	}

	t.Logf("Cleaning up %d tracked objects for provider %s", len(ot.objects), ot.config.Provider)

	// Delete objects in batches (S3 DeleteObjects supports up to 1000 objects per request)
	const batchSize = 1000
	for i := 0; i < len(ot.objects); i += batchSize {
		end := i + batchSize
		if end > len(ot.objects) {
			end = len(ot.objects)
		}

		batch := ot.objects[i:end]
		identifiers := make([]s3.ObjectIdentifier, len(batch))
		for j, key := range batch {
			identifiers[j] = s3.ObjectIdentifier{Key: key}
		}

		deleted, errors, err := ot.client.DeleteObjects(ctx, ot.bucket, identifiers)
		if err != nil {
			t.Logf("Failed to delete objects batch %d-%d: %v", i, end-1, err)
			continue
		}

		if len(errors) > 0 {
			t.Logf("Some objects failed to delete in batch %d-%d: %v", i, end-1, errors)
		}

		if len(deleted) > 0 {
			t.Logf("Deleted %d objects in batch %d-%d", len(deleted), i, end-1)
		}
	}

	ot.objects = nil
}

// CleanupAllObjects lists and deletes all objects with the test prefix.
// This is a more aggressive cleanup that finds objects even if not tracked.
func (ot *ObjectTracker) CleanupAllObjects(ctx context.Context, t *testing.T) {
	if !ot.config.EnableCleanup {
		t.Logf("Cleanup disabled for provider %s, skipping cleanup of all objects", ot.config.Provider)
		return
	}

	t.Logf("Cleaning up all objects with prefix %s in bucket %s", ot.prefix, ot.bucket)

	var allObjects []string
	var continuationToken string

	for {
		opts := s3.ListOptions{
			ContinuationToken: continuationToken,
			MaxKeys:           1000,
		}

		result, err := ot.client.ListObjects(ctx, ot.bucket, ot.prefix, opts)
		if err != nil {
			t.Logf("Failed to list objects for cleanup: %v", err)
			return
		}

		for _, obj := range result.Objects {
			allObjects = append(allObjects, obj.Key)
		}

		if !result.IsTruncated {
			break
		}
		continuationToken = result.NextContinuationToken
	}

	if len(allObjects) == 0 {
		t.Logf("No objects found with prefix %s", ot.prefix)
		return
	}

	t.Logf("Found %d objects to delete", len(allObjects))

	// Delete in batches
	const batchSize = 1000
	for i := 0; i < len(allObjects); i += batchSize {
		end := i + batchSize
		if end > len(allObjects) {
			end = len(allObjects)
		}

		batch := allObjects[i:end]
		identifiers := make([]s3.ObjectIdentifier, len(batch))
		for j, key := range batch {
			identifiers[j] = s3.ObjectIdentifier{Key: key}
		}

		deleted, errors, err := ot.client.DeleteObjects(ctx, ot.bucket, identifiers)
		if err != nil {
			t.Logf("Failed to delete objects batch %d-%d: %v", i, end-1, err)
			continue
		}

		if len(errors) > 0 {
			t.Logf("Some objects failed to delete in batch %d-%d: %v", i, end-1, errors)
		}

		if len(deleted) > 0 {
			t.Logf("Deleted %d objects in batch %d-%d", len(deleted), i, end-1)
		}
	}

	t.Logf("Cleanup complete: deleted %d objects", len(allObjects))
}

// GetTestPrefix returns a unique prefix for test objects based on test name and timestamp.
func GetTestPrefix(testName string) string {
	return fmt.Sprintf("test-%s-%d/", testName, time.Now().UnixNano())
}

// CreateS3ClientForCleanup creates an S3 client from backend config for cleanup operations.
func CreateS3ClientForCleanup(cfg *config.BackendConfig) (s3.Client, error) {
	return s3.NewClient(cfg)
}

