package main

import (
	"fmt"
	"log"

	"github.com/kenneth/s3-encryption-gateway/internal/crypto"
)

func main() {
	// Test our KMIP implementation directly
	manager, err := crypto.NewCosmianKMIPManager(crypto.CosmianKMIPOptions{
		Endpoint: "http://localhost:9998",
		Keys: []crypto.KMIPKeyReference{
			{ID: "b64a5b5e-e52a-4a66-b01c-fd1f930c83d4", Version: 1},
		},
		Provider: "cosmian",
	})
	if err != nil {
		log.Fatal("Failed to create manager:", err)
	}
	defer manager.Close(nil)

	// Test wrap/unwrap
	plaintext := []byte("test key data")
	fmt.Printf("Original key: %x\n", plaintext)

	envelope, err := manager.WrapKey(nil, plaintext, nil)
	if err != nil {
		log.Fatal("Failed to wrap key:", err)
	}

	fmt.Printf("Wrapped key ID: %s\n", envelope.KeyID)
	fmt.Printf("Wrapped key version: %d\n", envelope.KeyVersion)
	fmt.Printf("Wrapped ciphertext length: %d\n", len(envelope.Ciphertext))

	unwrapped, err := manager.UnwrapKey(nil, envelope, nil)
	if err != nil {
		log.Fatal("Failed to unwrap key:", err)
	}

	fmt.Printf("Unwrapped key: %x\n", unwrapped)

	if string(unwrapped) == string(plaintext) {
		fmt.Println("SUCCESS: Wrap/unwrap works correctly!")
	} else {
		fmt.Println("FAILURE: Wrap/unwrap returned wrong key!")
	}
}
