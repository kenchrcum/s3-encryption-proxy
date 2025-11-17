package main

import (
	"bytes"
	"fmt"
	"io"
	"log"

	"github.com/kenneth/s3-encryption-gateway/internal/crypto"
)

func main() {
	// Simulate the gateway flow: encrypt -> S3 storage simulation -> decrypt
	manager, err := crypto.NewCosmianKMIPManager(crypto.CosmianKMIPOptions{
		Endpoint: "http://localhost:9998",
		Keys: []crypto.KMIPKeyReference{
			{ID: "659d7582-4462-400c-ba67-3193879a6071", Version: 1},
		},
		Provider: "cosmian",
	})
	if err != nil {
		log.Fatal("Failed to create manager:", err)
	}
	defer manager.Close(nil)

	// Create encryption engine (like the gateway does)
	engine, err := crypto.NewEngineWithCompression("fallback-password-123456", nil)
	if err != nil {
		log.Fatal("Failed to create engine:", err)
	}
	crypto.SetKeyManager(engine, manager)

	// Test data
	plaintext := []byte("Hello from simulated gateway!")

	// Step 1: Encrypt (like the gateway PUT request)
	fmt.Println("Step 1: Encrypting data")
	encReader, encMetadata, err := engine.Encrypt(bytes.NewReader(plaintext), map[string]string{
		"Content-Type": "text/plain",
	})
	if err != nil {
		log.Fatal("Failed to encrypt:", err)
	}

	// Read the encrypted data
	encryptedData, err := io.ReadAll(encReader)
	if err != nil {
		log.Fatal("Failed to read encrypted data:", err)
	}

	fmt.Printf("Encrypted data length: %d\n", len(encryptedData))
	fmt.Printf("Encryption metadata keys: ")
	for k := range encMetadata {
		fmt.Printf("%s ", k)
	}
	fmt.Println()

	// Step 2: Simulate S3 storage (compaction/expansion)
	fmt.Println("Step 2: Simulating S3 storage with metadata compaction")
	compactor := crypto.NewMetadataCompactor(crypto.GetProviderProfile("minio"))

	// Compact metadata (like S3 storage)
	compacted, err := compactor.CompactMetadata(encMetadata)
	if err != nil {
		log.Fatal("Failed to compact metadata:", err)
	}

	fmt.Printf("Compacted metadata keys: ")
	for k := range compacted {
		fmt.Printf("%s ", k)
	}
	fmt.Println()

	// Expand metadata (like S3 retrieval)
	expanded, err := compactor.ExpandMetadata(compacted)
	if err != nil {
		log.Fatal("Failed to expand metadata:", err)
	}

	fmt.Printf("Expanded metadata keys: ")
	for k := range expanded {
		fmt.Printf("%s ", k)
	}
	fmt.Println()

	// Step 3: Decrypt (like the gateway GET request)
	fmt.Println("Step 3: Decrypting data")
	decReader, _, err := engine.Decrypt(bytes.NewReader(encryptedData), expanded)
	if err != nil {
		log.Fatal("Failed to decrypt:", err)
	}

	decryptedData, err := io.ReadAll(decReader)
	if err != nil {
		log.Fatal("Failed to read decrypted data:", err)
	}

	fmt.Printf("Decrypted data: %s\n", string(decryptedData))

	if string(decryptedData) == string(plaintext) {
		fmt.Println("SUCCESS: Gateway flow simulation works!")
	} else {
		fmt.Println("FAILURE: Gateway flow simulation failed!")
	}
}
