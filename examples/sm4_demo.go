// Package main demonstrates SM4 block cipher usage.
package main

import (
	"encoding/hex"
	"fmt"
	"github.com/lihongjie0209/sm-go-bc/crypto/engines"
	"github.com/lihongjie0209/sm-go-bc/crypto/params"
)

func main() {
	fmt.Println("=== SM4 Block Cipher Demo ===")
	
	// Example 1: Basic encryption
	fmt.Println("\n1. Basic Encryption:")
	basicEncryption()
	
	// Example 2: Encryption and decryption
	fmt.Println("\n2. Encryption and Decryption:")
	encryptDecrypt()
	
	// Example 3: Multiple blocks
	fmt.Println("\n3. Multiple Block Processing:")
	multipleBlocks()
	
	// Example 4: Different keys produce different outputs
	fmt.Println("\n4. Different Keys:")
	differentKeys()
}

func basicEncryption() {
	// Using standard test vector
	key, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	plaintext, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	
	engine := engines.NewSM4Engine()
	engine.Init(true, params.NewKeyParameter(key))
	
	ciphertext := make([]byte, 16)
	engine.ProcessBlock(plaintext, 0, ciphertext, 0)
	
	fmt.Printf("   Key:        %s\n", hex.EncodeToString(key))
	fmt.Printf("   Plaintext:  %s\n", hex.EncodeToString(plaintext))
	fmt.Printf("   Ciphertext: %s\n", hex.EncodeToString(ciphertext))
}

func encryptDecrypt() {
	key, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	plaintext := []byte("Hello, SM4! 1234") // 16 bytes
	
	fmt.Printf("   Original:   %s\n", string(plaintext))
	fmt.Printf("   Hex:        %s\n", hex.EncodeToString(plaintext))
	
	// Encrypt
	encEngine := engines.NewSM4Engine()
	encEngine.Init(true, params.NewKeyParameter(key))
	ciphertext := make([]byte, 16)
	encEngine.ProcessBlock(plaintext, 0, ciphertext, 0)
	
	fmt.Printf("   Encrypted:  %s\n", hex.EncodeToString(ciphertext))
	
	// Decrypt
	decEngine := engines.NewSM4Engine()
	decEngine.Init(false, params.NewKeyParameter(key))
	decrypted := make([]byte, 16)
	decEngine.ProcessBlock(ciphertext, 0, decrypted, 0)
	
	fmt.Printf("   Decrypted:  %s\n", string(decrypted))
	fmt.Printf("   Hex:        %s\n", hex.EncodeToString(decrypted))
	
	// Verify
	if hex.EncodeToString(plaintext) == hex.EncodeToString(decrypted) {
		fmt.Println("   ✓ Decryption successful!")
	} else {
		fmt.Println("   ✗ Decryption failed!")
	}
}

func multipleBlocks() {
	key, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	
	// Simulate processing multiple blocks (in real use, you'd use cipher modes)
	blocks := []string{
		"Block 1 16 bytes",
		"Block 2 16 bytes",
		"Block 3 16 bytes",
	}
	
	engine := engines.NewSM4Engine()
	engine.Init(true, params.NewKeyParameter(key))
	
	fmt.Println("   Encrypting multiple blocks:")
	for i, block := range blocks {
		plaintext := []byte(block)
		ciphertext := make([]byte, 16)
		engine.ProcessBlock(plaintext, 0, ciphertext, 0)
		
		fmt.Printf("   Block %d: %s -> %s\n", i+1, block, hex.EncodeToString(ciphertext)[:16]+"...")
	}
	
	fmt.Println("   Note: For real multi-block encryption, use cipher modes (CBC, CTR, etc.)")
}

func differentKeys() {
	plaintext, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	
	keys := []struct {
		name string
		key  string
	}{
		{"Key 1", "0123456789abcdeffedcba9876543210"},
		{"Key 2", "fedcba98765432100123456789abcdef"},
		{"Key 3", "00112233445566778899aabbccddeeff"},
	}
	
	fmt.Println("   Same plaintext with different keys:")
	fmt.Printf("   Plaintext: %s\n", hex.EncodeToString(plaintext))
	
	for _, kc := range keys {
		key, _ := hex.DecodeString(kc.key)
		engine := engines.NewSM4Engine()
		engine.Init(true, params.NewKeyParameter(key))
		
		ciphertext := make([]byte, 16)
		engine.ProcessBlock(plaintext, 0, ciphertext, 0)
		
		fmt.Printf("   %s: %s\n", kc.name, hex.EncodeToString(ciphertext))
	}
	
	fmt.Println("   ✓ Different keys produce different ciphertexts")
}
