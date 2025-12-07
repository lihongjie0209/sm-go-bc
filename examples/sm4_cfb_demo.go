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
	fmt.Println("=== SM4-CFB Mode Demo ===\n")

	// Generate random key and IV
	key := make([]byte, 16) // 128-bit key
	iv := make([]byte, 16)  // 128-bit IV
	rand.Read(key)
	rand.Read(iv)

	fmt.Printf("Key: %s\n", hex.EncodeToString(key))
	fmt.Printf("IV:  %s\n\n", hex.EncodeToString(iv))

	// Demo 1: CFB128 mode (full block)
	fmt.Println("--- CFB128 Mode (Full Block Feedback) ---")
	demoCFB128(key, iv)

	// Demo 2: CFB8 mode (byte-by-byte)
	fmt.Println("\n--- CFB8 Mode (Byte Feedback) ---")
	demoCFB8(key, iv)

	// Demo 3: CFB64 mode
	fmt.Println("\n--- CFB64 Mode (8-byte Feedback) ---")
	demoCFB64(key, iv)

	// Demo 4: Stream-like encryption
	fmt.Println("\n--- Stream-like Encryption ---")
	demoStreamEncryption(key, iv)
}

func demoCFB128(key, iv []byte) {
	plaintext := []byte("Hello, SM4-CFB128 mode! This is a test message.")
	fmt.Printf("Plaintext: %s\n", string(plaintext))

	// Create SM4 engine and CFB128 cipher
	engine := engines.NewSM4Engine()
	cfb := modes.NewCFBBlockCipher(engine, 128) // 128-bit block

	// Encrypt
	keyParam := params.NewKeyParameter(key)
	ivParam := params.NewParametersWithIV(keyParam, iv)
	cfb.Init(true, ivParam)

	ciphertext := make([]byte, len(plaintext))
	cfb.ProcessBytes(plaintext, 0, len(plaintext), ciphertext, 0)

	fmt.Printf("Ciphertext: %s\n", hex.EncodeToString(ciphertext))

	// Decrypt
	cfb.Init(false, ivParam)
	decrypted := make([]byte, len(ciphertext))
	cfb.ProcessBytes(ciphertext, 0, len(ciphertext), decrypted, 0)

	fmt.Printf("Decrypted: %s\n", string(decrypted))

	if string(plaintext) == string(decrypted) {
		fmt.Println("✓ Encryption/Decryption successful!")
	} else {
		fmt.Println("✗ Encryption/Decryption failed!")
	}
}

func demoCFB8(key, iv []byte) {
	plaintext := []byte("CFB8 encrypts byte-by-byte!")
	fmt.Printf("Plaintext: %s\n", string(plaintext))

	// Create SM4 engine and CFB8 cipher
	engine := engines.NewSM4Engine()
	cfb := modes.NewCFBBlockCipher(engine, 8) // 8-bit (1 byte) at a time

	// Encrypt
	keyParam := params.NewKeyParameter(key)
	ivParam := params.NewParametersWithIV(keyParam, iv)
	cfb.Init(true, ivParam)

	ciphertext := make([]byte, len(plaintext))
	for i := 0; i < len(plaintext); i++ {
		cfb.ProcessBlock(plaintext, i, ciphertext, i)
	}

	fmt.Printf("Ciphertext: %s\n", hex.EncodeToString(ciphertext))

	// Decrypt
	cfb.Init(false, ivParam)
	decrypted := make([]byte, len(ciphertext))
	for i := 0; i < len(ciphertext); i++ {
		cfb.ProcessBlock(ciphertext, i, decrypted, i)
	}

	fmt.Printf("Decrypted: %s\n", string(decrypted))

	if string(plaintext) == string(decrypted) {
		fmt.Println("✓ CFB8 encryption successful!")
	} else {
		fmt.Println("✗ CFB8 encryption failed!")
	}
}

func demoCFB64(key, iv []byte) {
	plaintext := []byte("CFB64 mode uses 8-byte feedback blocks!")
	fmt.Printf("Plaintext: %s\n", string(plaintext))

	// Create SM4 engine and CFB64 cipher
	engine := engines.NewSM4Engine()
	cfb := modes.NewCFBBlockCipher(engine, 64) // 64-bit (8 bytes) at a time

	// Encrypt
	keyParam := params.NewKeyParameter(key)
	ivParam := params.NewParametersWithIV(keyParam, iv)
	cfb.Init(true, ivParam)

	ciphertext := make([]byte, len(plaintext))
	cfb.ProcessBytes(plaintext, 0, len(plaintext), ciphertext, 0)

	fmt.Printf("Ciphertext: %s\n", hex.EncodeToString(ciphertext))

	// Decrypt
	cfb.Init(false, ivParam)
	decrypted := make([]byte, len(ciphertext))
	cfb.ProcessBytes(ciphertext, 0, len(ciphertext), decrypted, 0)

	fmt.Printf("Decrypted: %s\n", string(decrypted))

	if string(plaintext) == string(decrypted) {
		fmt.Println("✓ CFB64 encryption successful!")
	} else {
		fmt.Println("✗ CFB64 encryption failed!")
	}
}

func demoStreamEncryption(key, iv []byte) {
	plaintext := []byte("CFB mode can encrypt data of any length without padding!")
	fmt.Printf("Plaintext length: %d bytes\n", len(plaintext))
	fmt.Printf("Plaintext: %s\n", string(plaintext))

	// Create SM4 engine and CFB8 cipher (stream-like)
	engine := engines.NewSM4Engine()
	cfb := modes.NewCFBBlockCipher(engine, 8) // Byte-by-byte for stream encryption

	// Encrypt
	keyParam := params.NewKeyParameter(key)
	ivParam := params.NewParametersWithIV(keyParam, iv)
	cfb.Init(true, ivParam)

	ciphertext := make([]byte, len(plaintext))
	cfb.ProcessBytes(plaintext, 0, len(plaintext), ciphertext, 0)

	fmt.Printf("Ciphertext: %s\n", hex.EncodeToString(ciphertext))
	fmt.Printf("Ciphertext length: %d bytes (no padding needed!)\n", len(ciphertext))

	// Decrypt
	cfb.Init(false, ivParam)
	decrypted := make([]byte, len(ciphertext))
	cfb.ProcessBytes(ciphertext, 0, len(ciphertext), decrypted, 0)

	fmt.Printf("Decrypted: %s\n", string(decrypted))

	if string(plaintext) == string(decrypted) {
		fmt.Println("✓ Stream encryption successful!")
	} else {
		fmt.Println("✗ Stream encryption failed!")
	}
}
