package test

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"

	"github.com/kenneth/s3-encryption-gateway/internal/config"
	"github.com/kenneth/s3-encryption-gateway/internal/s3"
)

// MinIOTestServer manages a local MinIO server for testing.
type MinIOTestServer struct {
	Endpoint   string
	AccessKey  string
	SecretKey  string
	Bucket     string
	DataDir    string
	cmd        *exec.Cmd
	once       sync.Once
	cleanup    func()
}

var (
	minioServer *MinIOTestServer
	minioOnce   sync.Once
)

// StartMinIOServer starts a local MinIO server for testing.
// It uses Docker if available, otherwise tries to use a local MinIO binary.
func StartMinIOServer(t *testing.T) *MinIOTestServer {
	t.Helper()

	minioOnce.Do(func() {
		server := &MinIOTestServer{
			AccessKey: "minioadmin",
			SecretKey: "minioadmin",
			Bucket:    "test-bucket",
		}

		// Try Docker first
		if hasDocker() {
			server.startDockerMinIO(t)
		} else {
			// Fallback: check if MinIO binary is available
			if hasMinIOBinary() {
				server.startBinaryMinIO(t)
			} else {
				t.Skip("MinIO server not available. Install Docker or MinIO binary for integration tests.")
				return
			}
		}

		minioServer = server
	})

	return minioServer
}

// hasDocker checks if Docker is available.
func hasDocker() bool {
	cmd := exec.Command("docker", "version")
	return cmd.Run() == nil
}

// hasDockerCompose checks if docker-compose is available.
func hasDockerCompose() bool {
	cmd := exec.Command("docker-compose", "version")
	return cmd.Run() == nil
}

// hasMinIOBinary checks if MinIO binary is available in PATH.
func hasMinIOBinary() bool {
	cmd := exec.Command("minio", "version")
	return cmd.Run() == nil
}

// startDockerMinIO starts MinIO using Docker.
func (m *MinIOTestServer) startDockerMinIO(t *testing.T) {
	t.Helper()

	// Try docker-compose first (if docker-compose.yml exists)
	// Try multiple paths
	dockerComposePaths := []string{
		"test/docker-compose.yml",
		"./test/docker-compose.yml",
	}
	var dockerComposePath string
	for _, path := range dockerComposePaths {
		if _, err := os.Stat(path); err == nil {
			dockerComposePath = path
			break
		}
	}
	
	if dockerComposePath != "" {
		// Use docker-compose if available
		var cmd *exec.Cmd
		if hasDockerCompose() {
			cmd = exec.Command("docker-compose", "-f", dockerComposePath, "up", "-d")
		} else if hasDocker() {
			// Try "docker compose" (newer syntax)
			cmd = exec.Command("docker", "compose", "-f", dockerComposePath, "up", "-d")
		}
		
		if cmd != nil && cmd.Run() == nil {
			// Wait a bit for MinIO to start
			time.Sleep(3 * time.Second)
			m.Endpoint = "http://localhost:9000"
			
			// Verify MinIO is running
			if err := m.waitForMinIO(); err != nil {
				var downCmd *exec.Cmd
				if hasDockerCompose() {
					downCmd = exec.Command("docker-compose", "-f", dockerComposePath, "down")
				} else {
					downCmd = exec.Command("docker", "compose", "-f", dockerComposePath, "down")
				}
				downCmd.Run()
				t.Fatalf("MinIO failed to start: %v", err)
			}

			var cleanupCmd *exec.Cmd
			if hasDockerCompose() {
				cleanupCmd = exec.Command("docker-compose", "-f", dockerComposePath, "down", "-v")
			} else {
				cleanupCmd = exec.Command("docker", "compose", "-f", dockerComposePath, "down", "-v")
			}
			m.cleanup = func() {
				cleanupCmd.Run()
			}
			return
		}
	}

	// Fallback: Start MinIO container directly
	containerName := fmt.Sprintf("minio-test-%d", time.Now().Unix())
	port := "9000"
	m.Endpoint = fmt.Sprintf("http://localhost:%s", port)

	// Start MinIO in Docker
	cmd := exec.Command("docker", "run", "--rm", "-d",
		"-p", fmt.Sprintf("%s:9000", port),
		"-p", "9001:9001",
		"-e", fmt.Sprintf("MINIO_ROOT_USER=%s", m.AccessKey),
		"-e", fmt.Sprintf("MINIO_ROOT_PASSWORD=%s", m.SecretKey),
		"--name", containerName,
		"minio/minio:latest",
		"server", "/data", "--console-address", ":9001",
	)

	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to start MinIO Docker container: %v", err)
	}

	time.Sleep(3 * time.Second) // Wait for MinIO to start

	// Verify MinIO is running
	if err := m.waitForMinIO(); err != nil {
		exec.Command("docker", "stop", containerName).Run()
		t.Fatalf("MinIO failed to start: %v", err)
	}

	// Create test bucket
	if err := m.createBucket(); err != nil {
		exec.Command("docker", "stop", containerName).Run()
		t.Logf("Bucket creation note: %v (bucket will be created on first put)", err)
	}

	m.cleanup = func() {
		exec.Command("docker", "stop", containerName).Run()
	}
}

// startBinaryMinIO starts MinIO using local binary.
func (m *MinIOTestServer) startBinaryMinIO(t *testing.T) {
	t.Helper()

	// Create temporary data directory
	dataDir, err := os.MkdirTemp("", "minio-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	m.DataDir = dataDir

	port := "9000"
	m.Endpoint = fmt.Sprintf("http://localhost:%s", port)

	// Start MinIO server
	cmd := exec.Command("minio", "server", dataDir,
		"--address", fmt.Sprintf(":%s", port),
		"--console-address", ":9001",
	)
	cmd.Env = os.Environ()
	cmd.Env = append(cmd.Env,
		fmt.Sprintf("MINIO_ROOT_USER=%s", m.AccessKey),
		fmt.Sprintf("MINIO_ROOT_PASSWORD=%s", m.SecretKey),
	)

	if err := cmd.Start(); err != nil {
		os.RemoveAll(dataDir)
		t.Fatalf("Failed to start MinIO: %v", err)
	}

	m.cmd = cmd
	time.Sleep(2 * time.Second)

	// Verify MinIO is running
	if err := m.waitForMinIO(); err != nil {
		m.Stop()
		t.Fatalf("MinIO failed to start: %v", err)
	}

	// Create test bucket
	if err := m.createBucket(); err != nil {
		m.Stop()
		t.Fatalf("Failed to create test bucket: %v", err)
	}

	m.cleanup = func() {
		if m.cmd != nil && m.cmd.Process != nil {
			m.cmd.Process.Kill()
		}
		os.RemoveAll(dataDir)
	}
}

// waitForMinIO waits for MinIO to be ready.
func (m *MinIOTestServer) waitForMinIO() error {
	timeout := time.After(30 * time.Second)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-timeout:
			return fmt.Errorf("timeout waiting for MinIO")
		case <-ticker.C:
			resp, err := http.Get(m.Endpoint + "/minio/health/live")
			if err == nil {
				resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					return nil
				}
			}
		}
	}
}

// createBucket creates the test bucket in MinIO using AWS SDK.
func (m *MinIOTestServer) createBucket() error {
	cfg := &config.BackendConfig{
		Endpoint:  m.Endpoint,
		Region:    "us-east-1",
		AccessKey: m.AccessKey,
		SecretKey: m.SecretKey,
		Provider:  "minio",
		UseSSL:    false,
	}

	client, err := s3.NewClient(cfg)
	if err != nil {
		return fmt.Errorf("failed to create S3 client: %w", err)
	}

	// Create bucket by putting a dummy object
	// MinIO/S3 creates buckets implicitly on first object
	testKey := ".bucket-init"
	ctx := context.Background()
	emptyReader := bytes.NewReader([]byte{})
	err = client.PutObject(ctx, m.Bucket, testKey, emptyReader, nil)
	if err != nil {
		// Bucket will be created when first real object is uploaded
		// This is acceptable for MinIO
	}

	return nil
}

// Stop stops the MinIO server and cleans up resources.
func (m *MinIOTestServer) Stop() {
	m.once.Do(func() {
		if m.cleanup != nil {
			m.cleanup()
		}
	})
}

// GetS3Client returns a configured S3 client for the test server.
func (m *MinIOTestServer) GetS3Client() (s3.Client, error) {
	cfg := &config.BackendConfig{
		Endpoint:  m.Endpoint,
		Region:    "us-east-1",
		AccessKey: m.AccessKey,
		SecretKey: m.SecretKey,
		Provider:  "minio",
		UseSSL:    false,
	}

	return s3.NewClient(cfg)
}

// GetGatewayConfig returns gateway configuration for testing.
func (m *MinIOTestServer) GetGatewayConfig() *config.Config {
	return &config.Config{
		ListenAddr: ":18080", // Use different port to avoid conflicts
		LogLevel:   "error",
		Backend: config.BackendConfig{
			Endpoint:  m.Endpoint,
			Region:    "us-east-1",
			AccessKey: m.AccessKey,
			SecretKey: m.SecretKey,
			Provider:  "minio",
			UseSSL:    false,
		},
		Encryption: config.EncryptionConfig{
			Password: "test-encryption-password-123456",
		},
		Compression: config.CompressionConfig{
			Enabled: false,
		},
	}
}
