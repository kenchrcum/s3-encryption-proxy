package crypto

import (
	"crypto/rand"
	"testing"
)

func TestCreateAEADCipher_AES256GCM(t *testing.T) {
	key := make([]byte, aesKeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	
	cipher, err := createAEADCipher(AlgorithmAES256GCM, key)
	if err != nil {
		t.Fatalf("failed to create AES-GCM cipher: %v", err)
	}
	
	if cipher.Algorithm() != AlgorithmAES256GCM {
		t.Fatalf("expected algorithm %s, got %s", AlgorithmAES256GCM, cipher.Algorithm())
	}
}

func TestCreateAEADCipher_ChaCha20Poly1305(t *testing.T) {
	key := make([]byte, chacha20KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	
	cipher, err := createAEADCipher(AlgorithmChaCha20Poly1305, key)
	if err != nil {
		t.Fatalf("failed to create ChaCha20-Poly1305 cipher: %v", err)
	}
	
	if cipher.Algorithm() != AlgorithmChaCha20Poly1305 {
		t.Fatalf("expected algorithm %s, got %s", AlgorithmChaCha20Poly1305, cipher.Algorithm())
	}
}

func TestCreateAEADCipher_InvalidAlgorithm(t *testing.T) {
	key := make([]byte, aesKeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	
	_, err := createAEADCipher("INVALID", key)
	if err == nil {
		t.Fatal("expected error for invalid algorithm")
	}
}

func TestCreateAEADCipher_InvalidKeySize(t *testing.T) {
	key := make([]byte, 16) // Wrong size
	
	_, err := createAEADCipher(AlgorithmAES256GCM, key)
	if err == nil {
		t.Fatal("expected error for invalid key size")
	}
}

func TestGetNonceSize(t *testing.T) {
	tests := []struct {
		algorithm string
		expected  int
		wantErr   bool
	}{
		{
			algorithm: AlgorithmAES256GCM,
			expected:  nonceSize,
			wantErr:   false,
		},
		{
			algorithm: AlgorithmChaCha20Poly1305,
			expected:  chacha20NonceSize,
			wantErr:   false,
		},
		{
			algorithm: "INVALID",
			expected:  0,
			wantErr:   true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.algorithm, func(t *testing.T) {
			size, err := getNonceSize(tt.algorithm)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			
			if size != tt.expected {
				t.Fatalf("expected nonce size %d, got %d", tt.expected, size)
			}
		})
	}
}

func TestIsAlgorithmSupported(t *testing.T) {
	tests := []struct {
		name      string
		algorithm string
		supported []string
		expected  bool
	}{
		{
			name:      "AES256-GCM in supported list",
			algorithm: AlgorithmAES256GCM,
			supported: []string{AlgorithmAES256GCM, AlgorithmChaCha20Poly1305},
			expected:  true,
		},
		{
			name:      "ChaCha20-Poly1305 in supported list",
			algorithm: AlgorithmChaCha20Poly1305,
			supported: []string{AlgorithmAES256GCM, AlgorithmChaCha20Poly1305},
			expected:  true,
		},
		{
			name:      "algorithm not in supported list",
			algorithm: AlgorithmAES256GCM,
			supported: []string{AlgorithmChaCha20Poly1305},
			expected:  false,
		},
		{
			name:      "empty supported list defaults to all",
			algorithm: AlgorithmAES256GCM,
			supported: []string{},
			expected:  true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isAlgorithmSupported(tt.algorithm, tt.supported)
			if result != tt.expected {
				t.Fatalf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}
