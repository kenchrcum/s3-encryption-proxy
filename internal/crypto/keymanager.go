package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sync"
	"time"
)

// KeyVersion represents a version of an encryption key.
type KeyVersion struct {
	Version    int
	Password   string
	CreatedAt  time.Time
	Active     bool
	RotatedAt  *time.Time
}

// KeyManager manages multiple encryption keys with versioning support.
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

// keyManager implements KeyManager interface.
type keyManager struct {
	mu        sync.RWMutex
	keys      map[int]*KeyVersion
	nextVersion int
}

// NewKeyManager creates a new key manager with an initial key.
func NewKeyManager(initialPassword string) (KeyManager, error) {
	if initialPassword == "" {
		return nil, fmt.Errorf("initial password cannot be empty")
	}
	
	if len(initialPassword) < 12 {
		return nil, fmt.Errorf("initial password must be at least 12 characters")
	}
	
	km := &keyManager{
		keys: make(map[int]*KeyVersion),
		nextVersion: 1,
	}
	
	// Create initial key version
	km.keys[1] = &KeyVersion{
		Version:   1,
		Password:  initialPassword,
		CreatedAt: time.Now(),
		Active:    true,
	}
	km.nextVersion = 2 // Next version after initial key
	
	return km, nil
}

// GetActiveKey returns the currently active encryption key and its version.
func (km *keyManager) GetActiveKey() (string, int, error) {
	km.mu.RLock()
	defer km.mu.RUnlock()
	
	// Find the highest version active key
	maxVersion := 0
	for version := range km.keys {
		if version > maxVersion {
			maxVersion = version
		}
	}
	
	// Search from highest to lowest for active key
	for version := maxVersion; version >= 1; version-- {
		if key, ok := km.keys[version]; ok && key.Active {
			// If RotatedAt is set, the key was deactivated, skip it
			if key.RotatedAt != nil {
				continue
			}
			return key.Password, key.Version, nil
		}
	}
	
	return "", 0, fmt.Errorf("no active key found")
}

// GetAllKeys returns all encryption keys for decryption of old objects.
func (km *keyManager) GetAllKeys() map[int]string {
	km.mu.RLock()
	defer km.mu.RUnlock()
	
	keys := make(map[int]string)
	for version, key := range km.keys {
		keys[version] = key.Password
	}
	return keys
}

// RotateKey creates a new key version and optionally deactivates the old key.
func (km *keyManager) RotateKey(newPassword string, deactivateOld bool) error {
	if newPassword == "" {
		return fmt.Errorf("new password cannot be empty")
	}
	
	if len(newPassword) < 12 {
		return fmt.Errorf("new password must be at least 12 characters")
	}
	
	km.mu.Lock()
	defer km.mu.Unlock()
	
	// Deactivate old keys if requested
	if deactivateOld {
		for _, key := range km.keys {
			if key.Active {
				now := time.Now()
				key.Active = false
				key.RotatedAt = &now
			}
		}
	}
	
	// Create new key version
	version := km.nextVersion
	km.keys[version] = &KeyVersion{
		Version:   version,
		Password:  newPassword,
		CreatedAt: time.Now(),
		Active:    true,
	}
	km.nextVersion++
	
	return nil
}

// GetKeyVersion returns the key for a specific version.
func (km *keyManager) GetKeyVersion(version int) (string, error) {
	km.mu.RLock()
	defer km.mu.RUnlock()
	
	key, ok := km.keys[version]
	if !ok {
		return "", fmt.Errorf("key version %d not found", version)
	}
	
	return key.Password, nil
}

// KeyVersionMetadata holds key version information in metadata.
const (
	MetaKeyVersion = "x-amz-meta-encryption-key-version"
)

// GenerateKeyID generates a unique key identifier for metadata.
func GenerateKeyID() (string, error) {
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return "", fmt.Errorf("failed to generate key ID: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(id), nil
}
