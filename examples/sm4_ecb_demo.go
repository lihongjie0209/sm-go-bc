package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/lihongjie0209/sm-go-bc/crypto/engines"
	"github.com/lihongjie0209/sm-go-bc/crypto/modes"
	"github.com/lihongjie0209/sm-go-bc/crypto/params"
)

func main() {
	fmt.Println("=== SM4-ECB Mode Demo ===")
	fmt.Println()
	fmt.Println("⚠️  WARNING: ECB mode is NOT SECURE!")
	fmt.Println("   This demo is for educational purposes only.")
	fmt.Println("   DO NOT use ECB mode in production!")
	fmt.Println()

	// Generate random key
	key := make([]byte, 16) // 128-bit key
	rand.Read(key)

	fmt.Printf("Key: %s\n\n", hex.EncodeToString(key))

	// Demo 1: Basic encryption/decryption
	fmt.Println("--- Basic ECB Encryption ---")
	demoBasicECB(key)

	// Demo 2: Pattern leakage demonstration
	fmt.Println("\n--- ECB Pattern Leakage (Security Issue) ---")
	demoPatternLeakage(key)

	// Demo 3: Multiple blocks
	fmt.Println("\n--- Multiple Blocks ---")
	demoMultipleBlocks(key)
}

func demoBasicECB(key []byte) {
	plaintext := []byte("1234567890123456") // Exactly 16 bytes
	fmt.Printf("Plaintext: %s\n", string(plaintext))

	// Create SM4 engine and ECB cipher
	engine := engines.NewSM4Engine()
	ecb := modes.NewECBBlockCipher(engine)

	// Encrypt
	keyParam := params.NewKeyParameter(key)
	ecb.Init(true, keyParam)

	ciphertext := make([]byte, len(plaintext))
	ecb.ProcessBlock(plaintext, 0, ciphertext, 0)

	fmt.Printf("Ciphertext: %s\n", hex.EncodeToString(ciphertext))

	// Decrypt
	ecb.Init(false, keyParam)
	decrypted := make([]byte, len(ciphertext))
	ecb.ProcessBlock(ciphertext, 0, decrypted, 0)

	fmt.Printf("Decrypted: %s\n", string(decrypted))

	if string(plaintext) == string(decrypted) {
		fmt.Println("✓ Encryption/Decryption successful!")
	} else {
		fmt.Println("✗ Encryption/Decryption failed!")
	}
}

func demoPatternLeakage(key []byte) {
	// This demonstrates why ECB is insecure
	block1 := []byte("AAAAAAAAAAAAAAAA") // 16 A's
	block2 := []byte("AAAAAAAAAAAAAAAA") // Same 16 A's
	block3 := []byte("BBBBBBBBBBBBBBBB") // 16 B's

	engine := engines.NewSM4Engine()
	ecb := modes.NewECBBlockCipher(engine)

	keyParam := params.NewKeyParameter(key)
	ecb.Init(true, keyParam)

	// Encrypt all three blocks
	cipher1 := make([]byte, 16)
	cipher2 := make([]byte, 16)
	cipher3 := make([]byte, 16)

	ecb.ProcessBlock(block1, 0, cipher1, 0)
	ecb.ProcessBlock(block2, 0, cipher2, 0)
	ecb.ProcessBlock(block3, 0, cipher3, 0)

	fmt.Printf("Block 1 (AAAA...): %s\n", hex.EncodeToString(cipher1))
	fmt.Printf("Block 2 (AAAA...): %s\n", hex.EncodeToString(cipher2))
	fmt.Printf("Block 3 (BBBB...): %s\n", hex.EncodeToString(cipher3))

	if hex.EncodeToString(cipher1) == hex.EncodeToString(cipher2) {
		fmt.Println("\n⚠️  SECURITY WARNING!")
		fmt.Println("   Identical plaintext blocks produce identical ciphertext!")
		fmt.Println("   This leaks information about patterns in your data.")
		fmt.Println("   An attacker can see which blocks are identical.")
	}

	if hex.EncodeToString(cipher1) != hex.EncodeToString(cipher3) {
		fmt.Println("   (Different plaintext blocks produce different ciphertext - as expected)")
	}

	fmt.Println("\n   ❌ This is why ECB mode is insecure!")
	fmt.Println("   ✅ Use CBC, CTR, or GCM modes instead.")
}

func demoMultipleBlocks(key []byte) {
	// Encrypt multiple blocks
	plaintext := []byte("1234567890123456ABCDEFGHIJKLMNOP") // 32 bytes (2 blocks)
	fmt.Printf("Plaintext: %s (%d bytes)\n", string(plaintext), len(plaintext))

	engine := engines.NewSM4Engine()
	ecb := modes.NewECBBlockCipher(engine)

	keyParam := params.NewKeyParameter(key)
	ecb.Init(true, keyParam)

	// Encrypt block by block
	ciphertext := make([]byte, len(plaintext))
	blockSize := ecb.GetBlockSize()
	for i := 0; i < len(plaintext); i += blockSize {
		ecb.ProcessBlock(plaintext, i, ciphertext, i)
	}

	fmt.Printf("Ciphertext: %s\n", hex.EncodeToString(ciphertext))

	// Decrypt
	ecb.Init(false, keyParam)
	decrypted := make([]byte, len(ciphertext))
	for i := 0; i < len(ciphertext); i += blockSize {
		ecb.ProcessBlock(ciphertext, i, decrypted, i)
	}

	fmt.Printf("Decrypted: %s\n", string(decrypted))

	if string(plaintext) == string(decrypted) {
		fmt.Println("✓ Multi-block encryption successful!")
	} else {
		fmt.Println("✗ Multi-block encryption failed!")
	}
}
