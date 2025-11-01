package cache

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestMemoryCache_GetSet(t *testing.T) {
	cache := NewMemoryCache(1024*1024, 100, 5*time.Minute)
	ctx := context.Background()
	
	// Set a value
	data := []byte("test data")
	metadata := map[string]string{"Content-Type": "text/plain"}
	err := cache.Set(ctx, "bucket", "key", data, metadata, 0)
	if err != nil {
		t.Fatalf("failed to set cache: %v", err)
	}
	
	// Get the value
	entry, ok := cache.Get(ctx, "bucket", "key")
	if !ok {
		t.Fatal("cache entry not found")
	}
	
	if string(entry.Data) != string(data) {
		t.Fatalf("expected data %q, got %q", string(data), string(entry.Data))
	}
	
	if entry.Metadata["Content-Type"] != "text/plain" {
		t.Fatalf("expected metadata Content-Type text/plain, got %s", entry.Metadata["Content-Type"])
	}
}

func TestMemoryCache_Expiration(t *testing.T) {
	cache := NewMemoryCache(1024*1024, 100, 5*time.Minute)
	ctx := context.Background()
	
	// Set a value with short TTL
	data := []byte("test data")
	err := cache.Set(ctx, "bucket", "key", data, nil, 100*time.Millisecond)
	if err != nil {
		t.Fatalf("failed to set cache: %v", err)
	}
	
	// Get immediately - should work
	_, ok := cache.Get(ctx, "bucket", "key")
	if !ok {
		t.Fatal("cache entry not found immediately after set")
	}
	
	// Wait for expiration
	time.Sleep(150 * time.Millisecond)
	
	// Should be expired
	_, ok = cache.Get(ctx, "bucket", "key")
	if ok {
		t.Fatal("cache entry should be expired")
	}
}

func TestMemoryCache_Delete(t *testing.T) {
	cache := NewMemoryCache(1024*1024, 100, 5*time.Minute)
	ctx := context.Background()
	
	// Set a value
	data := []byte("test data")
	err := cache.Set(ctx, "bucket", "key", data, nil, 0)
	if err != nil {
		t.Fatalf("failed to set cache: %v", err)
	}
	
	// Delete it
	err = cache.Delete(ctx, "bucket", "key")
	if err != nil {
		t.Fatalf("failed to delete cache: %v", err)
	}
	
	// Should not be found
	_, ok := cache.Get(ctx, "bucket", "key")
	if ok {
		t.Fatal("cache entry should be deleted")
	}
}

func TestMemoryCache_Stats(t *testing.T) {
	cache := NewMemoryCache(1024*1024, 100, 5*time.Minute)
	ctx := context.Background()
	
	// Set some values
	for i := 0; i < 5; i++ {
		data := []byte(fmt.Sprintf("test data %d", i))
		err := cache.Set(ctx, "bucket", fmt.Sprintf("key%d", i), data, nil, 0)
		if err != nil {
			t.Fatalf("failed to set cache: %v", err)
		}
	}
	
	// Get some values to generate hits
	for i := 0; i < 3; i++ {
		cache.Get(ctx, "bucket", fmt.Sprintf("key%d", i))
	}
	
	// Try to get non-existent key to generate miss
	cache.Get(ctx, "bucket", "nonexistent")
	
	stats := cache.Stats()
	
	if stats.Items != 5 {
		t.Fatalf("expected 5 items, got %d", stats.Items)
	}
	
	if stats.Hits != 3 {
		t.Fatalf("expected 3 hits, got %d", stats.Hits)
	}
	
	if stats.Misses != 1 {
		t.Fatalf("expected 1 miss, got %d", stats.Misses)
	}
}

func TestMemoryCache_Clear(t *testing.T) {
	cache := NewMemoryCache(1024*1024, 100, 5*time.Minute)
	ctx := context.Background()
	
	// Set some values
	for i := 0; i < 5; i++ {
		data := []byte(fmt.Sprintf("test data %d", i))
		err := cache.Set(ctx, "bucket", fmt.Sprintf("key%d", i), data, nil, 0)
		if err != nil {
			t.Fatalf("failed to set cache: %v", err)
		}
	}
	
	// Clear cache
	err := cache.Clear(ctx)
	if err != nil {
		t.Fatalf("failed to clear cache: %v", err)
	}
	
	// Verify empty
	stats := cache.Stats()
	if stats.Items != 0 {
		t.Fatalf("expected 0 items after clear, got %d", stats.Items)
	}
}
