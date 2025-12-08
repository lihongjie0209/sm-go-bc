package main

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/lihongjie0209/sm-go-bc/crypto/digests"
	"github.com/lihongjie0209/sm-go-bc/crypto/macs"
	"github.com/lihongjie0209/sm-go-bc/crypto/params"
)

func main() {
	fmt.Println("=== HMAC-SM3 Demo ===\n")

	// Example 1: Basic HMAC usage
	fmt.Println("Example 1: Basic HMAC-SM3")
	fmt.Println("--------------------------")
	basicHMACExample()

	// Example 2: Message Authentication
	fmt.Println("\nExample 2: Message Authentication")
	fmt.Println("-----------------------------------")
	messageAuthenticationExample()

	// Example 3: Key Derivation (simple)
	fmt.Println("\nExample 3: HMAC for Key Derivation")
	fmt.Println("------------------------------------")
	keyDerivationExample()

	// Example 4: Incremental Updates
	fmt.Println("\nExample 4: Incremental Message Processing")
	fmt.Println("-------------------------------------------")
	incrementalUpdateExample()

	// Example 5: Different Key Lengths
	fmt.Println("\nExample 5: Different Key Lengths")
	fmt.Println("----------------------------------")
	keyLengthExample()
}

func basicHMACExample() {
	// Create HMAC with SM3 digest
	hmac := macs.NewHMac(digests.NewSM3Digest())

	// Set up key
	key := []byte("my-secret-key")
	err := hmac.Init(params.NewKeyParameter(key))
	if err != nil {
		fmt.Printf("Error initializing HMAC: %v\n", err)
		return
	}

	// Process message
	message := []byte("Hello, HMAC-SM3!")
	hmac.UpdateArray(message, 0, len(message))

	// Compute MAC
	mac := make([]byte, hmac.GetMacSize())
	n, err := hmac.DoFinal(mac, 0)
	if err != nil {
		fmt.Printf("Error computing MAC: %v\n", err)
		return
	}

	fmt.Printf("Message: %s\n", string(message))
	fmt.Printf("Key: %s\n", string(key))
	fmt.Printf("MAC (%d bytes): %s\n", n, hex.EncodeToString(mac))
}

func messageAuthenticationExample() {
	// Simulate sender and receiver
	sharedKey := []byte("shared-secret-key-between-parties")

	// Sender creates MAC
	message := []byte("Transfer $100 to account 12345")
	mac := computeMAC(sharedKey, message)

	fmt.Printf("Sender:\n")
	fmt.Printf("  Message: %s\n", string(message))
	fmt.Printf("  MAC: %s\n", hex.EncodeToString(mac))

	// Receiver verifies MAC
	fmt.Printf("\nReceiver:\n")
	receivedMAC := computeMAC(sharedKey, message)
	if verifyMAC(mac, receivedMAC) {
		fmt.Printf("  ✓ MAC verification PASSED - Message is authentic\n")
	} else {
		fmt.Printf("  ✗ MAC verification FAILED - Message may be tampered\n")
	}

	// Attempt with tampered message
	fmt.Printf("\nAttempting with tampered message:\n")
	tamperedMessage := []byte("Transfer $999 to account 12345")
	tamperedMAC := computeMAC(sharedKey, tamperedMessage)
	fmt.Printf("  Original MAC:  %s\n", hex.EncodeToString(mac))
	fmt.Printf("  Tampered MAC:  %s\n", hex.EncodeToString(tamperedMAC))
	if verifyMAC(mac, tamperedMAC) {
		fmt.Printf("  ✓ MAC verification PASSED\n")
	} else {
		fmt.Printf("  ✗ MAC verification FAILED - Detected tampering!\n")
	}
}

func keyDerivationExample() {
	// Use HMAC to derive keys from a master secret
	masterSecret := []byte("master-secret-key-material")

	// Derive different keys for different purposes
	key1 := deriveKey(masterSecret, []byte("encryption-key"))
	key2 := deriveKey(masterSecret, []byte("authentication-key"))
	key3 := deriveKey(masterSecret, []byte("session-key-1"))

	fmt.Printf("Master Secret: %s\n", string(masterSecret))
	fmt.Printf("\nDerived Keys:\n")
	fmt.Printf("  Encryption Key:     %s\n", hex.EncodeToString(key1[:16]))
	fmt.Printf("  Authentication Key: %s\n", hex.EncodeToString(key2[:16]))
	fmt.Printf("  Session Key 1:      %s\n", hex.EncodeToString(key3[:16]))

	fmt.Printf("\nNote: Each derived key is unique despite using the same master secret\n")
}

func incrementalUpdateExample() {
	hmac := macs.NewHMac(digests.NewSM3Digest())
	key := []byte("test-key")
	err := hmac.Init(params.NewKeyParameter(key))
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	// Process large message in chunks (simulating streaming)
	chunks := []string{
		"This is the first chunk of data. ",
		"This is the second chunk of data. ",
		"This is the third chunk of data.",
	}

	fmt.Println("Processing message in chunks:")
	for i, chunk := range chunks {
		fmt.Printf("  Chunk %d: %s\n", i+1, chunk)
		data := []byte(chunk)
		hmac.UpdateArray(data, 0, len(data))
	}

	// Compute final MAC
	mac := make([]byte, hmac.GetMacSize())
	hmac.DoFinal(mac, 0)

	fmt.Printf("\nFinal MAC: %s\n", hex.EncodeToString(mac))

	// Verify it's same as processing all at once
	hmac2 := macs.NewHMac(digests.NewSM3Digest())
	hmac2.Init(params.NewKeyParameter(key))
	fullMessage := []byte(chunks[0] + chunks[1] + chunks[2])
	hmac2.UpdateArray(fullMessage, 0, len(fullMessage))
	mac2 := make([]byte, hmac2.GetMacSize())
	hmac2.DoFinal(mac2, 0)

	fmt.Printf("MAC (all at once): %s\n", hex.EncodeToString(mac2))
	fmt.Printf("MACs match: %v\n", hex.EncodeToString(mac) == hex.EncodeToString(mac2))
}

func keyLengthExample() {
	message := []byte("Test message")

	// Test with different key lengths
	shortKey := []byte("short")           // 5 bytes
	mediumKey := make([]byte, 32)         // 32 bytes
	longKey := make([]byte, 100)          // 100 bytes (> block size of 64)

	// Fill medium and long keys with different patterns
	for i := range mediumKey {
		mediumKey[i] = byte(i)
	}
	for i := range longKey {
		longKey[i] = byte(i % 256)
	}

	mac1 := computeMAC(shortKey, message)
	mac2 := computeMAC(mediumKey, message)
	mac3 := computeMAC(longKey, message)

	fmt.Printf("Short key (5 bytes):   MAC = %s\n", hex.EncodeToString(mac1[:8]))
	fmt.Printf("Medium key (32 bytes): MAC = %s\n", hex.EncodeToString(mac2[:8]))
	fmt.Printf("Long key (100 bytes):  MAC = %s\n", hex.EncodeToString(mac3[:8]))
	fmt.Printf("\nNote: HMAC handles keys of any length by hashing keys longer than the block size\n")
}

// Helper function to compute MAC
func computeMAC(key []byte, message []byte) []byte {
	hmac := macs.NewHMac(digests.NewSM3Digest())
	err := hmac.Init(params.NewKeyParameter(key))
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	hmac.UpdateArray(message, 0, len(message))
	mac := make([]byte, hmac.GetMacSize())
	_, err = hmac.DoFinal(mac, 0)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	return mac
}

// Helper function to verify MAC
func verifyMAC(mac1 []byte, mac2 []byte) bool {
	if len(mac1) != len(mac2) {
		return false
	}
	for i := range mac1 {
		if mac1[i] != mac2[i] {
			return false
		}
	}
	return true
}

// Helper function to derive key using HMAC
func deriveKey(secret []byte, purpose []byte) []byte {
	hmac := macs.NewHMac(digests.NewSM3Digest())
	err := hmac.Init(params.NewKeyParameter(secret))
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	hmac.UpdateArray(purpose, 0, len(purpose))
	derived := make([]byte, hmac.GetMacSize())
	_, err = hmac.DoFinal(derived, 0)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	return derived
}
