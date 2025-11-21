package test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func TestTaggingPassthrough(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	minioServer := StartMinIOServer(t)
	defer minioServer.Stop()

	createBucketInMinIO(t, minioServer)

	gateway := StartGateway(t, minioServer.GetGatewayConfig())
	defer gateway.Close()

	bucket := minioServer.Bucket
	key := "tagged-object"
	data := []byte("tagged data")
	tagging := "key1=value1&key2=value2"

	// 1. PUT to Gateway with tagging header
	putURL := fmt.Sprintf("http://%s/%s/%s", gateway.Addr, bucket, key)
	req, err := http.NewRequest("PUT", putURL, bytes.NewReader(data))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("x-amz-tagging", tagging)

	client := gateway.GetHTTPClient()
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("PUT request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("PUT failed with status %d: %s", resp.StatusCode, string(body))
	}

	// 2. Verify tags in MinIO directly
	// Configure AWS SDK to talk to MinIO
	cfg, err := awsconfig.LoadDefaultConfig(context.Background(),
		awsconfig.WithRegion("us-east-1"),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(minioServer.AccessKey, minioServer.SecretKey, "")),
	)
	if err != nil {
		t.Fatalf("Failed to load AWS config: %v", err)
	}

	s3Client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(minioServer.Endpoint)
		o.UsePathStyle = true
	})

	tags, err := s3Client.GetObjectTagging(context.Background(), &s3.GetObjectTaggingInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		t.Fatalf("Failed to get tags from MinIO: %v", err)
	}

	if len(tags.TagSet) != 2 {
		t.Errorf("Expected 2 tags, got %d", len(tags.TagSet))
	}

	found := make(map[string]string)
	for _, tag := range tags.TagSet {
		found[*tag.Key] = *tag.Value
	}

	if found["key1"] != "value1" {
		t.Errorf("Expected key1=value1, got %s", found["key1"])
	}
	if found["key2"] != "value2" {
		t.Errorf("Expected key2=value2, got %s", found["key2"])
	}
}

func TestTaggingValidation(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	minioServer := StartMinIOServer(t)
	defer minioServer.Stop()

	createBucketInMinIO(t, minioServer)

	gateway := StartGateway(t, minioServer.GetGatewayConfig())
	defer gateway.Close()

	bucket := minioServer.Bucket
	key := "invalid-tags"
	data := []byte("data")

	client := gateway.GetHTTPClient()

	tests := []struct {
		name    string
		tagging string
		want    int
	}{
		{"valid", "k=v", http.StatusOK},
		{"too many tags", "1=1&2=2&3=3&4=4&5=5&6=6&7=7&8=8&9=9&10=10&11=11", http.StatusBadRequest},
		{"key too long", fmt.Sprintf("%s=v", strings.Repeat("a", 129)), http.StatusBadRequest},
		{"value too long", fmt.Sprintf("k=%s", strings.Repeat("a", 257)), http.StatusBadRequest},
		{"invalid chars", "k@=v", http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			putURL := fmt.Sprintf("http://%s/%s/%s", gateway.Addr, bucket, key)
			req, err := http.NewRequest("PUT", putURL, bytes.NewReader(data))
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}
			req.Header.Set("x-amz-tagging", tt.tagging)

			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("PUT request failed: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != tt.want {
				t.Errorf("For %s, expected status %d, got %d", tt.name, tt.want, resp.StatusCode)
			}
		})
	}
}

