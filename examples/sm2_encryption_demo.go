package main

import (
	"fmt"
	"math/big"
	"github.com/lihongjie0209/sm-go-bc/crypto/sm2"
)

func main() {
	fmt.Println("=== SM2 Public Key Encryption Demo ===\n")
	
	// Generate a key pair
	fmt.Println("1. Key Pair Generation:")
	privateKey := big.NewInt(123456789)
	publicKey := sm2.GetG().Multiply(privateKey)
	
	pkStr := privateKey.String()
	if len(pkStr) > 20 {
		pkStr = pkStr[:20] + "..."
	}
	pubStr := publicKey.String()
	if len(pubStr) > 40 {
		pubStr = pubStr[:40] + "..."
	}
	fmt.Printf("   Private Key: %s\n", pkStr)
	fmt.Printf("   Public Key:  %s\n", pubStr)
	
	// Validate keys
	if sm2.ValidatePrivateKey(privateKey) && sm2.ValidatePublicKey(publicKey) {
		fmt.Println("   ✓ Keys are valid\n")
	}
	
	// Create encryption engine
	fmt.Println("2. Encryption:")
	engine := sm2.NewSM2Engine()
	err := engine.Init(true, publicKey, nil)
	if err != nil {
		fmt.Printf("   ✗ Init failed: %v\n", err)
		return
	}
	
	plaintext := []byte("Hello, SM2 Encryption!")
	fmt.Printf("   Plaintext: %s\n", string(plaintext))
	
	ciphertext, err := engine.Encrypt(plaintext)
	if err != nil {
		fmt.Printf("   ✗ Encryption failed: %v\n", err)
		return
	}
	
	fmt.Printf("   Ciphertext length: %d bytes\n", len(ciphertext))
	fmt.Printf("   Ciphertext (hex): %x...\n", ciphertext[:32])
	fmt.Println("   ✓ Encryption successful\n")
	
	// Decrypt
	fmt.Println("3. Decryption:")
	engine2 := sm2.NewSM2Engine()
	err = engine2.Init(false, nil, privateKey)
	if err != nil {
		fmt.Printf("   ✗ Init failed: %v\n", err)
		return
	}
	
	decrypted, err := engine2.Decrypt(ciphertext)
	if err != nil {
		fmt.Printf("   ✗ Decryption failed: %v\n", err)
		return
	}
	
	fmt.Printf("   Decrypted: %s\n", string(decrypted))
	
	if string(decrypted) == string(plaintext) {
		fmt.Println("   ✓ Decryption successful - matches original!\n")
	} else {
		fmt.Println("   ✗ Decryption mismatch\n")
		return
	}
	
	// Test different message sizes
	fmt.Println("4. Testing Different Message Sizes:")
	
	testMessages := []struct {
		name string
		data []byte
	}{
		{"Empty", []byte("")},
		{"Short", []byte("Hi")},
		{"Medium", []byte("This is a medium length message for testing SM2 encryption.")},
		{"Long (256 bytes)", make([]byte, 256)},
	}
	
	// Fill long message with data
	for i := range testMessages[3].data {
		testMessages[3].data[i] = byte(i % 256)
	}
	
	for _, test := range testMessages {
		engine := sm2.NewSM2Engine()
		engine.Init(true, publicKey, nil)
		
		ct, err := engine.Encrypt(test.data)
		if err != nil {
			fmt.Printf("   ✗ %s: encryption failed: %v\n", test.name, err)
			continue
		}
		
		engine2 := sm2.NewSM2Engine()
		engine2.Init(false, nil, privateKey)
		
		pt, err := engine2.Decrypt(ct)
		if err != nil {
			fmt.Printf("   ✗ %s: decryption failed: %v\n", test.name, err)
			continue
		}
		
		if string(pt) == string(test.data) {
			fmt.Printf("   ✓ %s: %d bytes -> %d bytes ciphertext\n", 
				test.name, len(test.data), len(ct))
		} else {
			fmt.Printf("   ✗ %s: mismatch\n", test.name)
		}
	}
	
	// Test different modes
	fmt.Println("\n5. Testing Output Modes:")
	
	// C1C3C2 mode (new standard)
	engine = sm2.NewSM2Engine()
	engine.SetMode(sm2.Mode_C1C3C2)
	engine.Init(true, publicKey, nil)
	ct1, _ := engine.Encrypt([]byte("Mode test"))
	fmt.Printf("   C1C3C2 mode (new): %d bytes\n", len(ct1))
	
	// C1C2C3 mode (old standard)
	engine = sm2.NewSM2Engine()
	engine.SetMode(sm2.Mode_C1C2C3)
	engine.Init(true, publicKey, nil)
	ct2, _ := engine.Encrypt([]byte("Mode test"))
	fmt.Printf("   C1C2C3 mode (old): %d bytes\n", len(ct2))
	
	fmt.Println("\n✅ SM2 encryption/decryption complete!")
	fmt.Println("\nFormat: C1 || C3 || C2 (new standard)")
	fmt.Println("  C1 = Ephemeral public key (65 bytes uncompressed)")
	fmt.Println("  C3 = MAC/Hash (32 bytes SM3)")
	fmt.Println("  C2 = Encrypted message (same length as plaintext)")
}
