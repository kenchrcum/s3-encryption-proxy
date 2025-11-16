# ADR 0001: Range Optimization for Chunked Encryption

## Status
Accepted

## Context

The S3 Encryption Gateway provides client-side encryption while maintaining full S3 API compatibility. A key requirement is supporting HTTP range requests efficiently for large encrypted objects. Without optimization, range requests would require downloading and decrypting the entire object, which defeats the purpose of range requests for large files.

## Problem Statement

Traditional client-side encryption approaches encrypt entire objects as single units, making range requests inefficient. For a 1GB object with a 16KB range request, the client would need to:
1. Download the entire 1GB encrypted object
2. Decrypt the entire 1GB
3. Extract the requested 16KB range

This approach is unacceptable for performance and cost reasons.

## Decision

Implement chunked encryption with range-aware decryption optimization.

### Key Design Decisions

#### 1. Chunked Encryption Format
- **Decision**: Encrypt objects in fixed-size chunks (default 64KB) with independent authentication
- **Rationale**: Allows selective decryption of only required chunks
- **Trade-offs**: Slightly larger encrypted objects due to per-chunk overhead (16 bytes GCM auth tag per chunk)

#### 2. IV Derivation Strategy
- **Decision**: Use deterministic IV derivation based on chunk index XOR'd with base IV
- **Rationale**: Ensures unique IVs per chunk while allowing streaming encryption without pre-knowledge of chunk count
- **Security**: Maintains nonce uniqueness requirements for AES-GCM

#### 3. Range Request Optimization
- **Decision**: Calculate required chunks from plaintext byte ranges, fetch only those encrypted chunks from S3
- **Rationale**: Minimizes network transfer and decryption overhead
- **Implementation**: Convert plaintext ranges to encrypted byte ranges using chunk size + auth tag size

#### 4. Content-Range Header Mapping
- **Decision**: Translate encrypted object ranges back to original plaintext ranges in HTTP responses
- **Rationale**: Maintain S3 API compatibility and client expectations
- **Implementation**: Track plaintext size and return appropriate Content-Range headers

#### 5. Authentication Verification
- **Decision**: Verify authentication tags for all chunks involved in range requests
- **Rationale**: Maintains security guarantees - cannot bypass authentication by requesting partial ranges
- **Performance**: Only verifies accessed chunks, not entire object

## Implementation Details

### Chunk Manifest
```go
type ChunkManifest struct {
    Version    int      // Format version
    ChunkSize  int      // Size of each chunk in bytes
    ChunkCount int      // Total number of chunks
    BaseIV     string   // Base64-encoded base IV
}
```

### Range Calculation Algorithm
```go
// Calculate which chunks contain the requested plaintext range
startChunk = plaintextStart / chunkSize
endChunk = plaintextEnd / chunkSize

// Calculate encrypted byte range for S3 request
encryptedChunkSize = chunkSize + tagSize  // 16 bytes for GCM
encryptedStart = startChunk * encryptedChunkSize
encryptedEnd = (endChunk + 1) * encryptedChunkSize - 1
```

### IV Derivation
```go
// Derive unique IV per chunk while maintaining determinism
func deriveChunkIV(baseIV []byte, chunkIndex int) []byte {
    iv := copy(baseIV)
    indexBytes := bigEndian.PutUint32(chunkIndex)
    // XOR last 4 bytes with chunk index
    for i := 0; i < 4; i++ {
        iv[len(iv)-1-i] ^= indexBytes[3-i]
    }
    return iv
}
```

## Performance Characteristics

### Benefits
- **Network reduction**: For N-byte range in M-byte object, transfer ~64KB instead of M bytes
- **Compute reduction**: Decrypt only required chunks instead of entire object
- **Latency improvement**: Time-to-first-byte bounded by single chunk decryption time

### Worst-case Overhead
- **Extra chunk reads**: At most 1 additional chunk when ranges span boundaries
- **Memory usage**: Bounded by chunk size (default 64KB + overhead)
- **Authentication**: All touched chunks verified (security requirement)

### Example Performance
For a 1GB object with 16KB range request:
- **Traditional**: 1GB transfer + 1GB decryption
- **Optimized**: ~64KB transfer + ~64KB decryption
- **Improvement**: ~99.99% reduction in both network and compute

## Security Considerations

### Authentication Integrity
- All chunks involved in range requests have authentication tags verified
- Prevents attacks that attempt to bypass integrity checks via partial reads
- Maintains GCM's authenticated encryption guarantees

### IV Uniqueness
- Deterministic but unique IV derivation ensures no IV reuse
- Each chunk has cryptographically unique nonce
- Resists nonce reuse attacks

### Chunk Boundary Security
- Range optimization respects chunk boundaries for decryption
- Prevents attacks exploiting misaligned decryption
- Maintains confidentiality across chunk boundaries

## Alternatives Considered

### Alternative 1: Single-chunk Encryption
- **Pros**: Simpler implementation, smaller overhead
- **Cons**: No range optimization possible, poor performance for large objects
- **Decision**: Rejected due to performance requirements

### Alternative 2: Explicit IV Storage
- **Pros**: More flexible IV management
- **Cons**: Increases metadata size, complicates implementation
- **Decision**: Rejected in favor of deterministic derivation

### Alternative 3: Variable Chunk Sizes
- **Pros**: Could optimize for different access patterns
- **Cons**: Increases complexity, unpredictable performance
- **Decision**: Fixed chunks chosen for simplicity and predictable performance

## Testing Strategy

### Unit Tests
- Chunk range calculations for edge cases
- IV derivation correctness
- Encrypted range mapping
- Content-Range header generation

### Integration Tests
- Range requests across chunk boundaries
- Suffix range requests (HTTP spec)
- Cross-provider compatibility (AWS, MinIO, etc.)

### Performance Benchmarks
- Time-to-first-byte for various range sizes
- Network transfer reduction metrics
- Memory usage under load

## Migration Strategy

### Backward Compatibility
- Range optimization is transparent to existing encrypted objects
- Falls back to full-object decryption for non-chunked format
- No changes required to existing client code

### Versioning
- Chunk manifest includes version field for future format changes
- Allows gradual rollout and rollback capabilities

## Future Considerations

### Adaptive Chunk Sizing
- Could dynamically adjust chunk sizes based on access patterns
- Would require additional metadata and complexity

### Parallel Decryption
- Multiple chunks could be decrypted in parallel
- Would require concurrent processing framework

### Compression Integration
- Pre-encryption compression could be chunk-aware
- Optimize compression boundaries with encryption chunks

## References

- [RFC 7233 - Hypertext Transfer Protocol (HTTP/1.1): Range Requests](https://tools.ietf.org/html/rfc7233)
- [AES-GCM specification](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nvlpubs800-38d.pdf)
- S3 API Range Request documentation
