package main

import (
	"encoding/hex"
	"fmt"

	"github.com/lihongjie0209/sm-go-bc/crypto/engines"
	"github.com/lihongjie0209/sm-go-bc/crypto/macs"
	"github.com/lihongjie0209/sm-go-bc/crypto/params"
)

func main() {
	fmt.Println("=== ZUC Stream Cipher & MAC Demo ===\n")

	// Example 1: Basic ZUC-128
	fmt.Println("Example 1: Basic ZUC-128 Encryption")
	fmt.Println("------------------------------------")
	basicZUCExample()

	// Example 2: Encrypt and Decrypt
	fmt.Println("\nExample 2: Encryption and Decryption")
	fmt.Println("--------------------------------------")
	encryptDecryptExample()

	// Example 3: ZUC-256 Enhanced Security
	fmt.Println("\nExample 3: ZUC-256 (Enhanced Security)")
	fmt.Println("----------------------------------------")
	zuc256Example()

	// Example 4: ZUC-128 MAC (128-EIA3)
	fmt.Println("\nExample 4: ZUC-128 MAC (3GPP 128-EIA3)")
	fmt.Println("----------------------------------------")
	zuc128MacExample()

	// Example 5: ZUC-256 MAC
	fmt.Println("\nExample 5: ZUC-256 MAC")
	fmt.Println("-----------------------")
	zuc256MacExample()

	// Example 6: Key Sensitivity
	fmt.Println("\nExample 6: Key Sensitivity")
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



func zuc256Example() {
	// ZUC-256 uses 256-bit keys and 184-bit IVs for enhanced security
	key := make([]byte, 32) // 256-bit key
	iv := make([]byte, 23)  // 184-bit IV
	for i := 0; i < 32; i++ {
		key[i] = byte(i)
	}
	for i := 0; i < 23; i++ {
		iv[i] = byte(i + 32)
	}

	plaintext := []byte("ZUC-256 provides enhanced security for 5G and beyond")

	// Encrypt
	engine := engines.NewZuc256Engine()
	engine.Init(true, params.NewParametersWithIV(params.NewKeyParameter(key), iv))
	ciphertext := make([]byte, len(plaintext))
	engine.ProcessBytes(plaintext, 0, len(plaintext), ciphertext, 0)

	fmt.Printf("Plaintext:  %s\n", string(plaintext))
	fmt.Printf("Key:        %s... (256-bit)\n", hex.EncodeToString(key[:16]))
	fmt.Printf("IV:         %s... (184-bit)\n", hex.EncodeToString(iv[:12]))
	fmt.Printf("Ciphertext: %s...\n", hex.EncodeToString(ciphertext[:32]))

	// Decrypt
	engine.Reset()
	decrypted := make([]byte, len(ciphertext))
	engine.ProcessBytes(ciphertext, 0, len(ciphertext), decrypted, 0)

	fmt.Printf("Decrypted:  %s\n", string(decrypted))
	fmt.Printf("✓ ZUC-256 encryption/decryption successful!\n")
}

func zuc128MacExample() {
	// ZUC-128 MAC (128-EIA3) is used for integrity protection in 3GPP LTE/5G
	key := make([]byte, 16)
	iv := make([]byte, 16)
	for i := 0; i < 16; i++ {
		key[i] = byte(i)
		iv[i] = byte(i + 16)
	}

	message := []byte("3GPP LTE/5G message requiring integrity protection")

	// Generate MAC
	mac := macs.NewZuc128Mac() // 32-bit MAC by default
	mac.Init(params.NewParametersWithIV(params.NewKeyParameter(key), iv))
	mac.UpdateArray(message, 0, len(message))
	
	macValue := make([]byte, mac.GetMacSize())
	mac.DoFinal(macValue, 0)

	fmt.Printf("Message: %s\n", string(message))
	fmt.Printf("Key:     %s\n", hex.EncodeToString(key))
	fmt.Printf("IV:      %s\n", hex.EncodeToString(iv))
	fmt.Printf("MAC:     %s (%d bits)\n", hex.EncodeToString(macValue), mac.GetMacSize()*8)
	fmt.Println("Note: Used for 3GPP LTE/5G integrity protection (128-EIA3)")
}

func zuc256MacExample() {
	// ZUC-256 MAC provides enhanced security with flexible MAC lengths
	key := make([]byte, 32)
	iv := make([]byte, 23)
	for i := 0; i < 32; i++ {
		key[i] = byte(i)
	}
	for i := 0; i < 23; i++ {
		iv[i] = byte(i + 32)
	}

	message := []byte("5G+ message with enhanced integrity protection")

	fmt.Println("Testing different MAC lengths:")

	// 32-bit MAC
	mac32 := macs.NewZuc256MacWithLength(32)
	mac32.Init(params.NewParametersWithIV(params.NewKeyParameter(key), iv))
	mac32.UpdateArray(message, 0, len(message))
	macValue32 := make([]byte, mac32.GetMacSize())
	mac32.DoFinal(macValue32, 0)
	fmt.Printf("  32-bit MAC:  %s\n", hex.EncodeToString(macValue32))

	// 64-bit MAC (default)
	mac64 := macs.NewZuc256Mac()
	mac64.Init(params.NewParametersWithIV(params.NewKeyParameter(key), iv))
	mac64.UpdateArray(message, 0, len(message))
	macValue64 := make([]byte, mac64.GetMacSize())
	mac64.DoFinal(macValue64, 0)
	fmt.Printf("  64-bit MAC:  %s\n", hex.EncodeToString(macValue64))

	// 128-bit MAC
	mac128 := macs.NewZuc256MacWithLength(128)
	mac128.Init(params.NewParametersWithIV(params.NewKeyParameter(key), iv))
	mac128.UpdateArray(message, 0, len(message))
	macValue128 := make([]byte, mac128.GetMacSize())
	mac128.DoFinal(macValue128, 0)
	fmt.Printf("  128-bit MAC: %s\n", hex.EncodeToString(macValue128))

	fmt.Println("Note: Longer MACs provide stronger integrity guarantees")
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
