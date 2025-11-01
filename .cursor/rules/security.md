# Security Guidelines

## Cryptographic Security

### Encryption Requirements
- **Algorithm**: Use AES-256-GCM exclusively for authenticated encryption
- **Key derivation**: PBKDF2 with minimum 100,000 iterations
- **Salt**: Unique 32-byte random salt per object
- **IV/Nonce**: Unique 12-byte random IV per encryption
- **Authentication**: Always verify GCM tags on decryption

### Key Management
```go
// Correct key derivation
func deriveKey(password string, salt []byte) []byte {
    return pbkdf2.Key([]byte(password), salt, 100000, 32, sha256.New)
}

// Generate cryptographically secure random values
func generateSalt() ([]byte, error) {
    salt := make([]byte, 32)
    if _, err := rand.Read(salt); err != nil {
        return nil, fmt.Errorf("failed to generate salt: %w", err)
    }
    return salt, nil
}
```

### Data Protection
- **Never log**: Passwords, encryption keys, decrypted content
- **Zero sensitive data**: Overwrite keys and plaintext after use
- **Secure memory**: Avoid keeping sensitive data in heap longer than necessary
- **Streaming**: Process large files without full decryption in memory

```go
// Secure cleanup
func processKey(key []byte) {
    defer func() {
        for i := range key {
            key[i] = 0 // Zero out key
        }
    }()
    // Use key...
}

// Secure logging - never log sensitive data
logger.Info("Processing encryption request", "bucket", bucket, "key", key)
// NEVER: logger.Info("Decrypting", "password", password)
```

## Input Validation

### Cryptographic Inputs
- **Validate key lengths**: Ensure proper key sizes before use
- **Check algorithm parameters**: Validate IV, salt, and tag sizes
- **Sanitize inputs**: Remove or reject malicious input data

```go
func validateEncryptionInputs(password string, data []byte) error {
    if len(password) < 12 {
        return errors.New("password must be at least 12 characters")
    }
    if len(data) == 0 {
        return errors.New("data cannot be empty")
    }
    return nil
}
```

### HTTP Request Validation
- **Validate S3 parameters**: Bucket names, object keys
- **Check content lengths**: Prevent oversized requests
- **Sanitize headers**: Validate and clean request headers

## Error Handling Security

### Information Disclosure
- **Generic error messages**: Don't leak internal details
- **No stack traces**: Avoid exposing implementation details
- **Timing attacks**: Use constant-time operations for comparisons

```go
// Good - generic error
if !authenticated {
    return errors.New("authentication failed")
}

// Bad - reveals information
if userNotFound {
    return errors.New("user does not exist")
}
```

### Secure Error Types
```go
type SecureError struct {
    message string // Internal message
    public  string // Safe public message
}

func (e *SecureError) Error() string {
    return e.public // Always return safe message
}

func (e *SecureError) Internal() string {
    return e.message // For internal logging only
}
```

## Network Security

### TLS Configuration
- **Minimum TLS 1.2**: Reject older TLS versions
- **Certificate validation**: Always verify server certificates
- **Cipher suites**: Use only secure cipher suites

### Request Limits
- **Rate limiting**: Prevent abuse and DoS attacks
- **Size limits**: Maximum request/response sizes
- **Timeout enforcement**: Prevent slow loris attacks

```go
// Request size limiting
const maxRequestSize = 100 * 1024 * 1024 // 100MB

func (h *Handler) handleRequest(w http.ResponseWriter, r *http.Request) {
    r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
    // Process request...
}
```

## Access Control

### Authentication
- **Validate credentials**: Properly verify S3 credentials
- **Session management**: No sessions - each request independent
- **Authorization**: Check permissions for operations

### Least Privilege
- **Minimal permissions**: Backend S3 client has only necessary permissions
- **Container security**: Run as non-root user
- **Network policies**: Restrict network access

## Secure Coding Practices

### Memory Safety
- **Bounds checking**: Always validate array/slice bounds
- **Buffer overflows**: Use safe buffer operations
- **Memory leaks**: Properly close resources

```go
// Safe buffer operations
func processBuffer(data []byte, offset int) error {
    if offset < 0 || offset >= len(data) {
        return errors.New("invalid offset")
    }
    // Process safely...
}
```

### Concurrency Safety
- **Race conditions**: Protect shared state with mutexes
- **Deadlocks**: Avoid lock ordering issues
- **Goroutine leaks**: Ensure goroutines terminate

```go
type SafeCounter struct {
    mu    sync.Mutex
    count int
}

func (c *SafeCounter) Increment() {
    c.mu.Lock()
    defer c.mu.Unlock()
    c.count++
}
```

## Security Testing

### Cryptographic Testing
- **Algorithm correctness**: Test against known test vectors
- **Key derivation**: Validate PBKDF2 implementation
- **Round-trip encryption**: Encrypt → Decrypt → Verify identical

### Penetration Testing
- **Input fuzzing**: Test with malformed inputs
- **Boundary testing**: Test edge cases and limits
- **Error injection**: Test failure scenarios

### Security Audit
- **Code review**: Security-focused code reviews
- **Dependency scanning**: Check for vulnerable dependencies
- **Static analysis**: Use security-focused linters

## Compliance Considerations

### Data Protection
- **Encryption at rest**: All data encrypted before storage
- **Encryption in transit**: TLS for all network communication
- **Key management**: Secure key derivation and handling

### Audit Logging
- **Operation logging**: Log encryption operations (without sensitive data)
- **Access logging**: Log who accessed what (anonymized)
- **Error logging**: Log security-relevant errors

```go
// Audit logging example
type AuditLogger struct {
    logger *logrus.Logger
}

func (a *AuditLogger) LogEncryption(bucket, key string, operation string) {
    a.logger.WithFields(logrus.Fields{
        "operation": operation,
        "bucket":    bucket,
        "key":       key, // Consider hashing if sensitive
        "timestamp": time.Now().UTC(),
    }).Info("Encryption operation")
}
```

## Incident Response

### Breach Detection
- **Anomaly detection**: Monitor for unusual patterns
- **Integrity checks**: Verify encrypted data integrity
- **Alert thresholds**: Define and monitor security metrics

### Data Recovery
- **Backup encryption**: Ensure backups are also encrypted
- **Key recovery**: Document key recovery procedures
- **Data restoration**: Secure restore processes

### Communication
- **Stakeholder notification**: Defined incident response plan
- **Documentation**: Security incident procedures
- **Post-mortem**: Learn from security incidents

Remember: Security is not a checkbox - it's an ongoing process. Always consider security implications in every design and implementation decision.