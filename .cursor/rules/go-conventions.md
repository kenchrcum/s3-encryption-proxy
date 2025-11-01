# Go Coding Conventions

## Naming Conventions

### Variables and Functions
- Use `camelCase` for unexported identifiers
- Use `PascalCase` for exported identifiers
- Avoid abbreviations except for common ones (URL, ID, HTTP)
- Use descriptive names: `customerID` not `cid`

```go
// Good
var encryptionKey []byte
func processS3Request(ctx context.Context, req *S3Request) error

// Bad
var key []byte
func proc(ctx context.Context, r *S3Request) error
```

### Types and Structs
- Use `PascalCase` for all type names
- Struct field names follow same rules as variables
- Use meaningful receiver names (1-2 characters)

```go
type EncryptionEngine struct {
    password string  // unexported field
    SaltSize int     // exported field
}

func (e *EncryptionEngine) Encrypt(data []byte) ([]byte, error) {
    // e is the receiver
}
```

## Import Organization

Always organize imports in this order:
1. Standard library packages
2. Blank line
3. Third-party packages
4. Blank line
5. Internal/project packages

```go
import (
    "context"
    "crypto/rand"
    "io"

    "github.com/aws/aws-sdk-go/aws"
    "github.com/prometheus/client_golang/prometheus"

    "github.com/your-org/s3-gateway/internal/config"
    "github.com/your-org/s3-gateway/internal/crypto"
)
```

## Error Handling

### Error Wrapping
Always wrap errors with additional context using `fmt.Errorf` with `%w` verb.

```go
// Good
func (s *S3Client) GetObject(bucket, key string) ([]byte, error) {
    resp, err := s.client.GetObject(&s3.GetObjectInput{
        Bucket: &bucket,
        Key:    &key,
    })
    if err != nil {
        return nil, fmt.Errorf("failed to get object %s/%s from S3: %w", bucket, key, err)
    }
    // ...
}

// Bad - loses context
if err != nil {
    return nil, errors.New("S3 operation failed")
}
```

### Custom Error Types
Define custom error types for specific error conditions.

```go
type EncryptionError struct {
    Op   string
    Err  error
    Meta map[string]string
}

func (e *EncryptionError) Error() string {
    return fmt.Sprintf("encryption %s failed: %v", e.Op, e.Err)
}

func (e *EncryptionError) Unwrap() error {
    return e.Err
}

// Usage
return &EncryptionError{
    Op:   "decrypt",
    Err:  err,
    Meta: map[string]string{"algorithm": "AES256-GCM"},
}
```

## Context Usage

Always use `context.Context` for operations that may be cancelled or have timeouts.

```go
func (h *Handler) handleRequest(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()

    // Pass context to all operations
    err := h.processRequest(ctx, r)
    if err != nil {
        select {
        case <-ctx.Done():
            // Request was cancelled
            return
        default:
            // Other error
            http.Error(w, "Internal error", http.StatusInternalServerError)
        }
    }
}
```

## Interface Design

### Accept Interfaces, Return Structs
Functions should accept interfaces but return concrete types.

```go
// Good
func NewEncryptionEngine(password string) *EncryptionEngine {
    return &EncryptionEngine{password: password}
}

func (e *EncryptionEngine) Encrypt(reader io.Reader) (io.Reader, error) {
    // Accept io.Reader interface
}

// Bad - returning interface
func (e *EncryptionEngine) Encrypt(reader io.Reader) (io.Reader, error) {
    return &encryptedReader{}, nil  // This is OK, but prefer concrete types
}
```

### Small Interfaces
Keep interfaces small and focused on single responsibilities.

```go
type Encryptor interface {
    Encrypt(reader io.Reader) (io.Reader, error)
}

type Decryptor interface {
    Decrypt(reader io.Reader) (io.Reader, error)
}

// Combined interface only if needed
type CryptoEngine interface {
    Encryptor
    Decryptor
}
```

## Goroutines and Concurrency

### Channel Usage
Use channels appropriately for different concurrency patterns.

```go
// Error handling with channels
func processBatch(ctx context.Context, items []Item) error {
    errCh := make(chan error, len(items))

    for _, item := range items {
        go func(item Item) {
            if err := processItem(ctx, item); err != nil {
                select {
                case errCh <- err:
                default:
                }
            }
        }(item)
    }

    // Wait for completion or first error
    for i := 0; i < len(items); i++ {
        select {
        case err := <-errCh:
            return err
        case <-ctx.Done():
            return ctx.Err()
        }
    }

    return nil
}
```

### sync.WaitGroup for Coordination
```go
func encryptBatch(ctx context.Context, objects []*S3Object) error {
    var wg sync.WaitGroup
    var mu sync.Mutex
    var firstErr error

    for _, obj := range objects {
        wg.Add(1)
        go func(o *S3Object) {
            defer wg.Done()

            if err := encryptObject(ctx, o); err != nil {
                mu.Lock()
                if firstErr == nil {
                    firstErr = err
                }
                mu.Unlock()
            }
        }(obj)
    }

    wg.Wait()
    return firstErr
}
```

## Memory Management

### Streaming for Large Data
Use streaming interfaces for large data to avoid memory exhaustion.

```go
type EncryptReader struct {
    source io.Reader
    cipher cipher.AEAD
    buffer []byte
}

func (r *EncryptReader) Read(p []byte) (n int, err error) {
    // Read chunks, encrypt, return
    // Avoid loading entire file into memory
}
```

### Buffer Pools
Reuse buffers to reduce garbage collection pressure.

```go
var bufferPool = sync.Pool{
    New: func() interface{} {
        return make([]byte, 64*1024) // 64KB buffer
    },
}

func processData(data []byte) {
    buf := bufferPool.Get().([]byte)
    defer bufferPool.Put(buf)

    // Use buf for processing
}
```

## Documentation

### Package Comments
Every package must have a package comment.

```go
// Package crypto provides client-side encryption for S3 objects.
//
// It implements AES-256-GCM encryption with PBKDF2 key derivation
// for secure, authenticated encryption of object data.
package crypto
```

### Exported Function/Type Comments
All exported functions, types, and methods must have comments.

```go
// NewEncryptionEngine creates a new encryption engine with the given password.
//
// The password is used to derive encryption keys using PBKDF2 with
// 100,000 iterations and a random salt per object.
func NewEncryptionEngine(password string) *EncryptionEngine {
    // ...
}

// EncryptionEngine handles encryption and decryption of data streams.
//
// It uses AES-256-GCM for authenticated encryption and supports
// streaming operations for memory efficiency with large objects.
type EncryptionEngine struct {
    // ... fields
}
```

## Testing Patterns

### Table-Driven Tests
Use table-driven tests for multiple test cases.

```go
func TestEncryptionEngine_Encrypt(t *testing.T) {
    tests := []struct {
        name     string
        input    []byte
        password string
        wantErr  bool
    }{
        {"valid encryption", []byte("test"), "password", false},
        {"empty password", []byte("test"), "", true},
        {"empty input", []byte(""), "password", false},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            engine := NewEncryptionEngine(tt.password)

            reader := bytes.NewReader(tt.input)
            encrypted, err := engine.Encrypt(reader)

            if tt.wantErr {
                assert.Error(t, err)
                return
            }

            assert.NoError(t, err)
            assert.NotNil(t, encrypted)
        })
    }
}
```

### Mock Interfaces
Use interfaces to enable mocking in tests.

```go
type S3Client interface {
    PutObject(bucket, key string, reader io.Reader) error
    GetObject(bucket, key string) (io.Reader, error)
}

type mockS3Client struct {
    objects map[string][]byte
}

func (m *mockS3Client) PutObject(bucket, key string, reader io.Reader) error {
    data, err := io.ReadAll(reader)
    if err != nil {
        return err
    }
    m.objects[key] = data
    return nil
}
```

## Common Anti-Patterns to Avoid

### Ignoring Errors
```go
// Bad
data, _ := ioutil.ReadFile("config.yaml")  // Ignores error

// Good
data, err := ioutil.ReadFile("config.yaml")
if err != nil {
    return fmt.Errorf("failed to read config: %w", err)
}
```

### Naked Returns
```go
// Avoid naked returns in multi-return functions
func process(data []byte) (result []byte, err error) {
    if len(data) == 0 {
        return // What does this return?
    }
    result = processData(data)
    return result, nil
}
```

### Global Variables
Avoid global state. Pass dependencies explicitly.

```go
// Bad
var globalConfig *Config

// Good
func NewHandler(config *Config) *Handler {
    return &Handler{config: config}
}
```

### Panic Usage
Don't use panic for normal error handling.

```go
// Bad - crashes the program
if len(data) == 0 {
    panic("empty data")
}

// Good - return error
if len(data) == 0 {
    return errors.New("data cannot be empty")
}
```

Follow these conventions to maintain consistent, readable, and maintainable Go code.