# Project Structure Guidelines

## Package Organization

### Internal Package Structure
```
internal/
├── api/              # HTTP handlers and routing logic
│   ├── handlers/     # Request handlers
│   ├── middleware/   # HTTP middleware
│   └── routes.go     # Route definitions
├── config/           # Configuration management
│   ├── config.go     # Main config struct
│   ├── env.go        # Environment variable parsing
│   └── validation.go # Config validation
├── crypto/           # Encryption/decryption
│   ├── engine.go     # Main encryption engine
│   ├── aesgcm.go     # AES-GCM implementation
│   ├── pbkdf2.go     # Key derivation
│   └── reader.go     # Streaming readers
├── s3/               # S3 client implementations
│   ├── client.go     # Generic S3 client interface
│   ├── aws.go        # AWS S3 implementation
│   ├── minio.go      # MinIO implementation
│   └── backends/     # Backend-specific code
├── middleware/       # Shared middleware
│   ├── logging.go    # Request logging
│   ├── metrics.go    # Prometheus metrics
│   └── auth.go       # Authentication middleware
└── metrics/          # Monitoring and metrics
    ├── prometheus.go # Prometheus setup
    └── collectors.go # Custom metrics
```

### Command Structure
```
cmd/
└── server/
    ├── main.go       # Application entrypoint
    ├── server.go     # HTTP server setup
    └── wire.go       # Dependency injection (if using Wire)
```

### Package Naming Rules
- **Lowercase**: All package names should be lowercase
- **Descriptive**: Use descriptive names (not abbreviations)
- **Single purpose**: Each package has one clear responsibility

```go
// Good package names
package crypto    // Encryption operations
package config    // Configuration management
package api       // HTTP API handling

// Bad package names
package utils     // Too generic
package helpers   // Too generic
package crypt     // Abbreviation
```

## File Organization

### File Naming
- **snake_case**: Use snake_case for file names
- **descriptive**: File names should describe their contents
- **grouping**: Group related files together

```go
// Good file names
config.go         // Main config logic
config_test.go    // Config tests
encryption.go     // Encryption functions
encryption_test.go // Encryption tests

// Bad file names
conf.go          // Too abbreviated
encrypt.go       // Missing context
util.go          // Too generic
```

### File Size Limits
- **Maximum 500 lines**: Break up large files
- **Single responsibility**: Each file should have one clear purpose
- **Related functions**: Group closely related functions together

## Interface Design

### Interface Location
- **Consumer packages**: Define interfaces where they're used
- **Accept interfaces**: Functions should accept interfaces
- **Return concretes**: Functions should return concrete types

```go
// Define interface in consumer package
package api

type Encryptor interface {
    Encrypt(reader io.Reader) (io.Reader, error)
}

func NewHandler(encryptor Encryptor) *Handler {
    return &Handler{encryptor: encryptor}
}

// Implementation in producer package
package crypto

type AESEngine struct{ /* ... */ }

func (e *AESEngine) Encrypt(reader io.Reader) (io.Reader, error) {
    // Implementation
}

func NewAESEngine() *AESEngine { // Return concrete
    return &AESEngine{}
}
```

### Interface Segregation
- **Small interfaces**: Keep interfaces focused and small
- **Client-specific**: Define only methods clients need
- **Composition**: Combine interfaces when needed

```go
// Good - small, focused interfaces
type Reader interface {
    Read(p []byte) (n int, err error)
}

type Writer interface {
    Write(p []byte) (n int, err error)
}

type ReadWriter interface {
    Reader
    Writer
}

// Bad - large, unfocused interface
type File interface {
    Read(p []byte) (n int, err error)
    Write(p []byte) (n int, err error)
    Seek(offset int64, whence int) (int64, error)
    Close() error
    Stat() (os.FileInfo, error)
    // ... many more methods
}
```

## Dependency Management

### Import Organization
```go
import (
    // Standard library (alphabetical)
    "context"
    "crypto/rand"
    "fmt"
    "io"
    "time"

    // Third-party (alphabetical)
    "github.com/aws/aws-sdk-go/aws"
    "github.com/prometheus/client_golang/prometheus"

    // Internal (alphabetical)
    "github.com/your-org/s3-gateway/internal/config"
    "github.com/your-org/s3-gateway/internal/crypto"
)
```

### Dependency Direction
- **Internal only**: Internal packages should not import cmd/
- **No circular imports**: Maintain acyclic dependency graph
- **Stable APIs**: Internal packages should have stable interfaces

```
cmd/server → internal/api
           → internal/config
           → internal/crypto
           → internal/s3

internal/api → internal/crypto
             → internal/s3
             → internal/middleware

internal/crypto → (no internal dependencies)
internal/s3 → (no internal dependencies)
```

## Configuration Management

### Config Structure
```go
type Config struct {
    Server ServerConfig `yaml:"server"`
    Crypto CryptoConfig `yaml:"crypto"`
    S3     S3Config     `yaml:"s3"`
    Metrics MetricsConfig `yaml:"metrics"`
}

type ServerConfig struct {
    Host         string        `yaml:"host" env:"SERVER_HOST"`
    Port         int           `yaml:"port" env:"SERVER_PORT"`
    ReadTimeout  time.Duration `yaml:"read_timeout"`
    WriteTimeout time.Duration `yaml:"write_timeout"`
}

type CryptoConfig struct {
    Password           string `yaml:"password" env:"ENCRYPTION_PASSWORD"`
    PBKDF2Iterations   int    `yaml:"pbkdf2_iterations"`
    EnableCompression  bool   `yaml:"enable_compression"`
}

type S3Config struct {
    Endpoint   string `yaml:"endpoint" env:"S3_ENDPOINT"`
    Region     string `yaml:"region" env:"S3_REGION"`
    AccessKey  string `yaml:"access_key" env:"S3_ACCESS_KEY"`
    SecretKey  string `yaml:"secret_key" env:"S3_SECRET_KEY"`
    Bucket     string `yaml:"bucket" env:"S3_BUCKET"`
}
```

### Config Loading Priority
1. **Defaults**: Sensible default values
2. **Config file**: YAML/JSON configuration file
3. **Environment**: Environment variables override file
4. **Flags**: Command-line flags override environment

## Error Handling Patterns

### Error Types
```go
// Domain-specific error types
type EncryptionError struct {
    Op  string
    Err  error
    Meta map[string]interface{}
}

func (e *EncryptionError) Error() string {
    return fmt.Sprintf("encryption operation %s failed: %v", e.Op, e.Err)
}

func (e *EncryptionError) Unwrap() error {
    return e.Err
}

// Usage
return fmt.Errorf("failed to process: %w", &EncryptionError{
    Op:   "decrypt",
    Err:  err,
    Meta: map[string]interface{}{"algorithm": "AES256-GCM"},
})
```

### Error Handling in Handlers
```go
func (h *Handler) handlePutObject(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()

    bucket := mux.Vars(r)["bucket"]
    key := mux.Vars(r)["key"]

    if err := h.validateBucketKey(bucket, key); err != nil {
        h.logger.WithError(err).Warn("Invalid bucket/key")
        http.Error(w, "Invalid bucket or key", http.StatusBadRequest)
        return
    }

    if err := h.processObject(ctx, bucket, key, r.Body); err != nil {
        h.logger.WithError(err).Error("Failed to process object")

        // Map errors to appropriate HTTP status codes
        status := mapErrorToStatus(err)
        http.Error(w, "Internal server error", status)
        return
    }

    w.WriteHeader(http.StatusOK)
}
```

## Testing Organization

### Test File Location
- **Same package**: Unit tests in same package as code
- **Integration tests**: In separate integration test packages
- **Test data**: Store test fixtures in testdata/ directories

```
internal/crypto/
├── engine.go
├── engine_test.go         # Unit tests
└── testdata/
    ├── valid-key.bin
    └── corrupted-data.bin

internal/api/
├── handlers/
│   ├── put.go
│   ├── put_test.go
│   └── testdata/
│       └── sample-request.json
└── integration_test.go    # Integration tests
```

### Test Helpers
```go
// Test utilities in separate files
func setupTestServer(t *testing.T) *httptest.Server {
    // Setup test server
}

func createTestConfig() *Config {
    return &Config{
        // Test configuration
    }
}

// Example test
func TestPutObject(t *testing.T) {
    server := setupTestServer(t)
    defer server.Close()

    client := &http.Client{}
    // Test implementation
}
```

## Build and Deployment

### Build Tags
```go
// Use build tags for conditional compilation
//go:build !debug

package main

// Production code
```

### Version Information
```go
// Version information embedded at build time
var (
    version   = "dev"
    commit    = "none"
    buildDate = "unknown"
)

// Build command:
// go build -ldflags "-X main.version=v1.0.0 -X main.commit=$(git rev-parse HEAD) -X main.buildDate=$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
```

### Docker Structure
```
Dockerfile
docker-compose.yml          # Development environment
docker-compose.test.yml     # Testing environment
.dockerignore
```

## Documentation Structure

### README Files
- **Project root**: Overall project description and setup
- **Package directories**: Package-specific documentation
- **docs/**: Detailed documentation and guides

### Code Documentation
- **Package comments**: Every package must have a comment
- **Exported symbols**: All exported functions/types documented
- **Examples**: Include usage examples where helpful

```go
// Package crypto provides client-side encryption for S3 objects.
//
// This package implements AES-256-GCM encryption with PBKDF2 key derivation
// for secure, authenticated encryption of object data. It supports streaming
// operations for memory-efficient handling of large objects.
//
// Example usage:
//
//	engine := crypto.NewEngine("my-secret-password")
//	encrypted := engine.Encrypt(strings.NewReader("hello world"))
//	decrypted := engine.Decrypt(encrypted)
package crypto
```

Follow this structure to maintain a clean, organized, and maintainable codebase. Consistent structure makes it easier for team members to navigate and contribute to the project.