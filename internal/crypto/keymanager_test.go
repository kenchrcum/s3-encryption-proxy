package crypto

import (
	"strings"
	"testing"
)

func TestNewKeyManager(t *testing.T) {
	tests := []struct {
		name        string
		password    string
		wantErr     bool
		errContains string
	}{
		{
			name:     "valid password",
			password:  "valid-password-123",
			wantErr:  false,
		},
		{
			name:        "empty password",
			password:    "",
			wantErr:     true,
			errContains: "cannot be empty",
		},
		{
			name:        "short password",
			password:    "short",
			wantErr:     true,
			errContains: "at least 12 characters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			km, err := NewKeyManager(tt.password)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Fatalf("expected error to contain %q, got %q", tt.errContains, err.Error())
				}
				return
			}
			
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			
			if km == nil {
				t.Fatal("key manager is nil")
			}
			
			// Verify initial key is active
			password, version, err := km.GetActiveKey()
			if err != nil {
				t.Fatalf("failed to get active key: %v", err)
			}
			
			if password != tt.password {
				t.Fatalf("expected password %q, got %q", tt.password, password)
			}
			
			if version != 1 {
				t.Fatalf("expected version 1, got %d", version)
			}
		})
	}
}

func TestKeyManager_RotateKey(t *testing.T) {
	initialPassword := "initial-password-123"
	km, err := NewKeyManager(initialPassword)
	if err != nil {
		t.Fatalf("failed to create key manager: %v", err)
	}
	
	// Get initial key
	password1, version1, err := km.GetActiveKey()
	if err != nil {
		t.Fatalf("failed to get initial key: %v", err)
	}
	
	if password1 != initialPassword || version1 != 1 {
		t.Fatalf("initial key mismatch: got password=%q version=%d", password1, version1)
	}
	
	// Rotate to new key without deactivating old
	newPassword := "new-password-456"
	err = km.RotateKey(newPassword, false)
	if err != nil {
		t.Fatalf("failed to rotate key: %v", err)
	}
	
	// Both keys should be active
	password2, version2, err := km.GetActiveKey()
	if err != nil {
		t.Fatalf("failed to get active key after rotation: %v", err)
	}
	
	if password2 != newPassword || version2 != 2 {
		t.Fatalf("new key mismatch: got password=%q version=%d", password2, version2)
	}
	
	// Verify old key is still available
	oldKey, err := km.GetKeyVersion(1)
	if err != nil {
		t.Fatalf("failed to get old key: %v", err)
	}
	
	if oldKey != initialPassword {
		t.Fatalf("old key mismatch: expected %q, got %q", initialPassword, oldKey)
	}
	
	// Rotate with deactivation
	newerPassword := "newer-password-789"
	err = km.RotateKey(newerPassword, true)
	if err != nil {
		t.Fatalf("failed to rotate key with deactivation: %v", err)
	}
	
	// Only new key should be active
	password3, version3, err := km.GetActiveKey()
	if err != nil {
		t.Fatalf("failed to get active key after second rotation: %v", err)
	}
	
	if password3 != newerPassword || version3 != 3 {
		t.Fatalf("new key mismatch: got password=%q version=%d", password3, version3)
	}
}

func TestKeyManager_GetAllKeys(t *testing.T) {
	km, err := NewKeyManager("initial-password-123")
	if err != nil {
		t.Fatalf("failed to create key manager: %v", err)
	}
	
	err = km.RotateKey("new-password-456", false)
	if err != nil {
		t.Fatalf("failed to rotate key: %v", err)
	}
	
	allKeys := km.GetAllKeys()
	
	if len(allKeys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(allKeys))
	}
	
	if allKeys[1] != "initial-password-123" {
		t.Fatalf("key version 1 mismatch")
	}
	
	if allKeys[2] != "new-password-456" {
		t.Fatalf("key version 2 mismatch")
	}
}

func TestGenerateKeyID(t *testing.T) {
	id1, err := GenerateKeyID()
	if err != nil {
		t.Fatalf("failed to generate key ID: %v", err)
	}
	
	if id1 == "" {
		t.Fatal("generated key ID is empty")
	}
	
	// Generate another ID and verify it's different
	id2, err := GenerateKeyID()
	if err != nil {
		t.Fatalf("failed to generate second key ID: %v", err)
	}
	
	if id1 == id2 {
		t.Fatal("generated identical key IDs")
	}
}

