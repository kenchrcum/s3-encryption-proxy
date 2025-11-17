package main

import (
	"encoding/base64"
	"fmt"
	"log"

	"github.com/kenneth/s3-encryption-gateway/internal/crypto"
)

func main() {
	// Test unwrapping the specific wrapped key from the gateway test
	manager, err := crypto.NewCosmianKMIPManager(crypto.CosmianKMIPOptions{
		Endpoint: "http://localhost:9998",
		Keys: []crypto.KMIPKeyReference{
			{ID: "ea1cf634-2f6f-4608-9bac-2d23996199a5", Version: 1},
		},
		Provider: "cosmian",
	})
	if err != nil {
		log.Fatal("Failed to create manager:", err)
	}
	defer manager.Close(nil)

	// The wrapped key from the gateway test
	wrappedB64 := "Bcsfrq1mJRW7345uLDqT7AptgbrKOM0syW4Z0sZEb+/M4Ios5SWQoQ=="
	wrapped, err := base64.StdEncoding.DecodeString(wrappedB64)
	if err != nil {
		log.Fatal("Failed to decode wrapped key:", err)
	}

	fmt.Printf("Wrapped key: %x\n", wrapped)

	// Create a KeyEnvelope - need to check the correct type
	env := &crypto.KeyEnvelope{
		KeyID:      "ea1cf634-2f6f-4608-9bac-2d23996199a5",
		KeyVersion: 1,
		Provider:   "cosmian",
		Ciphertext: wrapped,
	}

	unwrapped, err := manager.UnwrapKey(nil, env, nil)
	if err != nil {
		log.Fatal("Failed to unwrap key:", err)
	}

	fmt.Printf("Unwrapped key: %x\n", unwrapped)
	fmt.Printf("Unwrapped key length: %d\n", len(unwrapped))
}
