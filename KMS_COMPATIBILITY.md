# KMS Compatibility Guide

This document explains how to create a Key Management Service (KMS) compatible with the S3 Encryption Gateway, or how to integrate with existing KMS solutions.

## Overview

The S3 Encryption Gateway supports two key management modes:

1. **Single Password Mode** (default): Uses a single password for all encryption operations
   - Simple and backward compatible
   - No key rotation support
   - Suitable for small deployments

2. **Key Manager (KMS) Mode**: Uses a KeyManager interface for advanced key management
   - Supports key rotation
   - Multiple key versions for backward compatibility
   - Suitable for enterprise deployments

## Key Manager Interface

The gateway uses the `KeyManager` interface from `internal/crypto/keymanager.go`:

```go
type KeyManager interface {
    // GetActiveKey returns the currently active encryption key.
    GetActiveKey() (string, int, error)
    
    // GetAllKeys returns all encryption keys (for decryption of old objects).
    GetAllKeys() map[int]string
    
    // RotateKey creates a new key version and optionally deactivates the old key.
    RotateKey(newPassword string, deactivateOld bool) error
    
    // GetKeyVersion returns the key for a specific version.
    GetKeyVersion(version int) (string, error)
}
```

## Implementing a Custom KMS

To create a KMS-compatible system, implement the `KeyManager` interface. Here's how:

### Step 1: Implement the Interface

```go
package yourkms

import (
    "github.com/kenneth/s3-encryption-gateway/internal/crypto"
)

type YourKMS struct {
    // Add your KMS-specific fields
    endpoint string
    credentials string
    // ... other fields
}

// GetActiveKey returns the currently active encryption key
func (k *YourKMS) GetActiveKey() (string, int, error) {
    // 1. Query your KMS for the active key
    // 2. Return the key material (password) and version number
    // Example:
    key, version, err := k.queryKMSForActiveKey()
    if err != nil {
        return "", 0, err
    }
    return key, version, nil
}

// GetAllKeys returns all encryption keys for backward compatibility
func (k *YourKMS) GetAllKeys() map[int]string {
    // Return all keys that can decrypt old objects
    // Format: map[version]password
    keys := make(map[int]string)
    allKeys := k.queryKMSForAllKeys()
    for version, key := range allKeys {
        keys[version] = key
    }
    return keys
}

// RotateKey creates a new key version
func (k *YourKMS) RotateKey(newPassword string, deactivateOld bool) error {
    // 1. Validate new password (min 12 chars)
    if len(newPassword) < 12 {
        return fmt.Errorf("password must be at least 12 characters")
    }
    
    // 2. Create new key version in your KMS
    // 3. Optionally deactivate old keys
    return k.createNewKeyVersion(newPassword, deactivateOld)
}

// GetKeyVersion returns a specific key version
func (k *YourKMS) GetKeyVersion(version int) (string, error) {
    // Query your KMS for a specific key version
    return k.queryKMSForKeyVersion(version)
}
```

### Step 2: Integration Points

The gateway calls the KeyManager in these scenarios:

1. **Encryption**: Calls `GetActiveKey()` to get the current password
2. **Decryption**: Uses `GetKeyVersion()` to retrieve keys for old objects
3. **Key Rotation**: Uses `RotateKey()` when keys need to be rotated

### Step 3: Key Versioning Strategy

The gateway stores key version information in object metadata:

- **Metadata Key**: `x-amz-meta-encryption-key-version`
- **Format**: Integer version number (1, 2, 3, ...)

Your KMS should:
- Assign sequential version numbers
- Track which version is active
- Retain old versions for decryption
- Support deactivating old versions

### Step 4: Password/Key Format

The gateway expects:
- **Type**: String (UTF-8)
- **Length**: Minimum 12 characters
- **Usage**: Used as-is for PBKDF2 key derivation

Your KMS can:
- Generate random passwords automatically
- Use passwords provided by administrators
- Derive passwords from other sources (master keys, etc.)

## Example: AWS KMS Integration

Here's a conceptual example of integrating with AWS KMS:

```go
package awskms

import (
    "github.com/aws/aws-sdk-go-v2/service/kms"
    "github.com/kenneth/s3-encryption-gateway/internal/crypto"
)

type AWSKMSManager struct {
    client     *kms.Client
    keyID      string
    keyVersions map[int]string
    currentVersion int
}

func (k *AWSKMSManager) GetActiveKey() (string, int, error) {
    // Decrypt the current version's key from AWS KMS
    result, err := k.client.Decrypt(context.TODO(), &kms.DecryptInput{
        CiphertextBlob: k.getCiphertextForVersion(k.currentVersion),
    })
    if err != nil {
        return "", 0, err
    }
    
    return string(result.Plaintext), k.currentVersion, nil
}

func (k *AWSKMSManager) RotateKey(newPassword string, deactivateOld bool) error {
    // Encrypt new password with AWS KMS
    encryptResult, err := k.client.Encrypt(context.TODO(), &kms.EncryptInput{
        KeyId:     &k.keyID,
        Plaintext: []byte(newPassword),
    })
    if err != nil {
        return err
    }
    
    // Store new version
    newVersion := k.currentVersion + 1
    k.keyVersions[newVersion] = base64.StdEncoding.EncodeToString(encryptResult.CiphertextBlob)
    k.currentVersion = newVersion
    
    // Optionally disable old versions in AWS KMS
    if deactivateOld {
        // Implement key alias rotation or disable old keys
    }
    
    return nil
}
```

## Example: HashiCorp Vault Integration

```go
package vaultkms

import (
    "github.com/hashicorp/vault/api"
    "github.com/kenneth/s3-encryption-gateway/internal/crypto"
)

type VaultKMSManager struct {
    client *api.Client
    path   string // e.g., "secret/data/s3-gateway-keys"
}

func (v *VaultKMSManager) GetActiveKey() (string, int, error) {
    secret, err := v.client.Logical().Read(v.path + "/active")
    if err != nil {
        return "", 0, err
    }
    
    password := secret.Data["password"].(string)
    version := int(secret.Data["version"].(float64))
    
    return password, version, nil
}
```

## Example: Database-Backed KMS

```go
package dbkms

import (
    "database/sql"
    "github.com/kenneth/s3-encryption-gateway/internal/crypto"
)

type DatabaseKMSManager struct {
    db *sql.DB
}

func (d *DatabaseKMSManager) GetActiveKey() (string, int, error) {
    var password string
    var version int
    
    err := d.db.QueryRow(`
        SELECT password, version 
        FROM encryption_keys 
        WHERE active = true 
        ORDER BY version DESC 
        LIMIT 1
    `).Scan(&password, &version)
    
    return password, version, err
}

func (d *DatabaseKMSManager) RotateKey(newPassword string, deactivateOld bool) error {
    tx, err := d.db.Begin()
    if err != nil {
        return err
    }
    defer tx.Rollback()
    
    // Get next version
    var maxVersion int
    tx.QueryRow("SELECT COALESCE(MAX(version), 0) FROM encryption_keys").Scan(&maxVersion)
    newVersion := maxVersion + 1
    
    // Insert new key
    _, err = tx.Exec(`
        INSERT INTO encryption_keys (version, password, active, created_at)
        VALUES ($1, $2, true, NOW())
    `, newVersion, newPassword)
    if err != nil {
        return err
    }
    
    // Deactivate old keys if requested
    if deactivateOld {
        _, err = tx.Exec(`
            UPDATE encryption_keys 
            SET active = false, rotated_at = NOW()
            WHERE active = true AND version < $1
        `, newVersion)
        if err != nil {
            return err
        }
    }
    
    return tx.Commit()
}
```

## Configuration

Enable KMS mode in your configuration:

```yaml
encryption:
  password: "initial-password-or-kms-master-key"  # Still required for initialization
  key_manager:
    enabled: true  # Enable KMS mode
```

Or via environment variable:

```bash
export KEY_MANAGER_ENABLED=true
export ENCRYPTION_PASSWORD="your-initial-password"
```

## Key Rotation Workflow

When using KMS mode, the rotation workflow is:

1. **Current State**: All objects encrypted with key version 1
2. **Rotate Key**: Call `RotateKey("new-password", false)` 
   - Creates key version 2
   - Version 1 remains active for decryption
3. **New Objects**: Encrypted with version 2
4. **Old Objects**: Still decryptable with version 1
5. **Optional Deactivation**: After migration, call `RotateKey("next-password", true)` to deactivate old keys

## Best Practices

### Security
- **Never log passwords**: Keys should be encrypted at rest
- **Use secure storage**: Store keys in encrypted databases, HSMs, or cloud KMS
- **Access control**: Implement proper access controls for key retrieval
- **Audit logging**: Log all key access and rotation events

### Performance
- **Key caching**: Cache active keys in memory (with TTL)
- **Connection pooling**: For database-backed KMS
- **Retry logic**: Handle transient failures gracefully

### Operations
- **Key rotation schedule**: Establish regular rotation schedule
- **Backup keys**: Always backup keys before rotation
- **Version retention**: Keep old versions until all objects are migrated
- **Monitoring**: Monitor key usage and rotation status

## Testing Your KMS

Create a test to verify your KMS implementation:

```go
func TestYourKMS(t *testing.T) {
    kms := NewYourKMS(...)
    
    // Test GetActiveKey
    key, version, err := kms.GetActiveKey()
    assert.NoError(t, err)
    assert.GreaterOrEqual(t, len(key), 12)
    assert.Greater(t, version, 0)
    
    // Test RotateKey
    err = kms.RotateKey("new-password-123", false)
    assert.NoError(t, err)
    
    // Verify new key is active
    newKey, newVersion, err := kms.GetActiveKey()
    assert.NoError(t, err)
    assert.Equal(t, "new-password-123", newKey)
    assert.Greater(t, newVersion, version)
    
    // Test GetKeyVersion
    oldKey, err := kms.GetKeyVersion(version)
    assert.NoError(t, err)
    assert.Equal(t, key, oldKey) // Old key still retrievable
}
```

## Migration from Single Password Mode

To migrate from single password to KMS mode:

1. **Backup**: Ensure you have backups of all encrypted objects
2. **Enable KMS**: Set `key_manager.enabled: true` in config
3. **Initialize**: Start with your current password
4. **Rotate**: After verifying everything works, rotate to a new key
5. **Monitor**: Watch for decryption failures (indicates version issues)

The gateway will continue to work with objects encrypted with the original password, and new objects will use the new key.

## Troubleshooting

### "no active key found"
- Check that your KMS is returning valid keys
- Verify the key meets minimum length requirements (12 chars)

### Decryption failures after rotation
- Ensure old key versions are still accessible
- Check that `GetKeyVersion()` returns the correct key
- Verify metadata includes correct version number

### Performance issues
- Implement key caching in your KMS
- Use connection pooling for remote KMS services
- Monitor KMS response times

## Additional Resources

- See `internal/crypto/keymanager.go` for the reference implementation
- See `internal/crypto/keymanager_test.go` for test examples
- See `PHASE5_ADVANCED_FEATURES.md` for more details on key rotation
