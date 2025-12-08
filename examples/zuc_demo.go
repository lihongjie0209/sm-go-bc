package main

import (
	"encoding/hex"
	"fmt"

	"github.com/lihongjie0209/sm-go-bc/crypto/engines"
	"github.com/lihongjie0209/sm-go-bc/crypto/params"
)

func main() {
	fmt.Println("=== ZUC-128 Stream Cipher Demo ===\n")

	// Example 1: Basic ZUC usage
	fmt.Println("Example 1: Basic ZUC-128 Encryption")
	fmt.Println("------------------------------------")
	basicZUCExample()

	// Example 2: Encrypt and Decrypt
	fmt.Println("\nExample 2: Encryption and Decryption")
	fmt.Println("--------------------------------------")
	encryptDecryptExample()

	// Example 3: Streaming Data
	fmt.Println("\nExample 3: Streaming Data Processing")
	fmt.Println("--------------------------------------")
	streamingExample()

	// Example 4: Different Keys Produce Different Ciphertexts
	fmt.Println("\nExample 4: Key Sensitivity")
	fmt.Println("---------------------------")
	keySensitivityExample()
}

func basicZUCExample() {
	// Create ZUC engine
	engine := engines.NewZUCEngine()

	// Set up key and IV (both 128 bits = 16 bytes)
	key := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	}
	iv := []byte{
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	}

	// Initialize the engine
	p := params.NewParametersWithIV(params.NewKeyParameter(key), iv)
	err := engine.Init(true, p)
	if err != nil {
		fmt.Printf("Error initializing ZUC: %v\n", err)
		return
	}

	// Encrypt data
	plaintext := []byte("Hello, ZUC!")
	ciphertext := make([]byte, len(plaintext))
	n, err := engine.ProcessBytes(plaintext, 0, len(plaintext), ciphertext, 0)
	if err != nil {
		fmt.Printf("Error encrypting: %v\n", err)
		return
	}

	fmt.Printf("Plaintext:  %s\n", string(plaintext))
	fmt.Printf("Key:        %s\n", hex.EncodeToString(key))
	fmt.Printf("IV:         %s\n", hex.EncodeToString(iv))
	fmt.Printf("Ciphertext: %s (%d bytes)\n", hex.EncodeToString(ciphertext), n)
}

func encryptDecryptExample() {
	key := []byte{
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
	}
	iv := []byte{
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
	}

	message := []byte("This is a secret message for 3GPP LTE/5G encryption")

	fmt.Printf("Original message: %s\n", string(message))

	// Encrypt
	encryptEngine := engines.NewZUCEngine()
	encryptEngine.Init(true, params.NewParametersWithIV(params.NewKeyParameter(key), iv))
	ciphertext := make([]byte, len(message))
	encryptEngine.ProcessBytes(message, 0, len(message), ciphertext, 0)

	fmt.Printf("Encrypted:        %s\n", hex.EncodeToString(ciphertext[:32])) // Show first 32 bytes

	// Decrypt (re-initialize with same key and IV)
	decryptEngine := engines.NewZUCEngine()
	decryptEngine.Init(false, params.NewParametersWithIV(params.NewKeyParameter(key), iv))
	decrypted := make([]byte, len(ciphertext))
	decryptEngine.ProcessBytes(ciphertext, 0, len(ciphertext), decrypted, 0)

	fmt.Printf("Decrypted:        %s\n", string(decrypted))

	// Verify
	if string(message) == string(decrypted) {
		fmt.Println("✓ Decryption successful!")
	} else {
		fmt.Println("✗ Decryption failed!")
	}
}

func streamingExample() {
	key := make([]byte, 16)
	iv := make([]byte, 16)
	for i := 0; i < 16; i++ {
		key[i] = byte(i)
		iv[i] = byte(16 + i)
	}

	engine := engines.NewZUCEngine()
	engine.Init(true, params.NewParametersWithIV(params.NewKeyParameter(key), iv))

	// Process data in chunks (simulating streaming)
	chunks := []string{
		"Chunk 1: ",
		"Chunk 2: ",
		"Chunk 3: ",
		"End.",
	}

	fmt.Println("Processing data in chunks:")
	totalCiphertext := []byte{}

	for i, chunk := range chunks {
		plaintext := []byte(chunk)
		ciphertext := make([]byte, len(plaintext))
		engine.ProcessBytes(plaintext, 0, len(plaintext), ciphertext, 0)

		fmt.Printf("  Chunk %d: %s -> %s\n", i+1, chunk, hex.EncodeToString(ciphertext))
		totalCiphertext = append(totalCiphertext, ciphertext...)
	}

	// Decrypt all at once
	engine.Reset()
	decrypted := make([]byte, len(totalCiphertext))
	engine.ProcessBytes(totalCiphertext, 0, len(totalCiphertext), decrypted, 0)

	fullMessage := ""
	for _, chunk := range chunks {
		fullMessage += chunk
	}

	fmt.Printf("\nOriginal:  %s\n", fullMessage)
	fmt.Printf("Decrypted: %s\n", string(decrypted))
	fmt.Printf("Match: %v\n", fullMessage == string(decrypted))
}

func keySensitivityExample() {
	message := []byte("Sensitive data")

	key1 := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	key2 := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // Only last bit different
	}
	iv := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}

	// Encrypt with key1
	engine1 := engines.NewZUCEngine()
	engine1.Init(true, params.NewParametersWithIV(params.NewKeyParameter(key1), iv))
	ciphertext1 := make([]byte, len(message))
	engine1.ProcessBytes(message, 0, len(message), ciphertext1, 0)

	// Encrypt with key2 (only 1 bit different)
	engine2 := engines.NewZUCEngine()
	engine2.Init(true, params.NewParametersWithIV(params.NewKeyParameter(key2), iv))
	ciphertext2 := make([]byte, len(message))
	engine2.ProcessBytes(message, 0, len(message), ciphertext2, 0)

	fmt.Printf("Message:       %s\n", string(message))
	fmt.Printf("Key 1:         %s\n", hex.EncodeToString(key1))
	fmt.Printf("Key 2:         %s (1 bit different)\n", hex.EncodeToString(key2))
	fmt.Printf("Ciphertext 1:  %s\n", hex.EncodeToString(ciphertext1))
	fmt.Printf("Ciphertext 2:  %s\n", hex.EncodeToString(ciphertext2))

	// Count different bytes
	differentBytes := 0
	for i := range ciphertext1 {
		if ciphertext1[i] != ciphertext2[i] {
			differentBytes++
		}
	}

	fmt.Printf("\nDifferent bytes: %d out of %d (%.1f%%)\n",
		differentBytes, len(ciphertext1), 100.0*float64(differentBytes)/float64(len(ciphertext1)))
	fmt.Println("Note: Even 1-bit key difference produces completely different ciphertext (avalanche effect)")
}
