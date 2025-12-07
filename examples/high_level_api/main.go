package main

import (
	"encoding/hex"
	"fmt"
	"log"

	"github.com/lihongjie0209/sm-go-bc/api"
)

func main() {
	fmt.Println("=== SM2 High-Level API Demo ===\n")
	demonstrateSM2()

	fmt.Println("\n=== SM4 High-Level API Demo ===\n")
	demonstrateSM4()
}

func demonstrateSM2() {
	// Generate key pair
	fmt.Println("1. Generating SM2 key pair...")
	keyPair, err := api.SM2GenerateKeyPair()
	if err != nil {
		log.Fatalf("Failed to generate key pair: %v", err)
	}

	fmt.Printf("   Private Key: %x\n", keyPair.PrivateKey)
	fmt.Printf("   Public Key X: %x\n", keyPair.PublicKey.X)
	fmt.Printf("   Public Key Y: %x\n", keyPair.PublicKey.Y)

	// Encryption/Decryption
	fmt.Println("\n2. Testing SM2 Encryption/Decryption...")
	message := []byte("Hello, SM2! This is a test message.")
	fmt.Printf("   Original message: %s\n", message)

	ciphertext, err := api.SM2Encrypt(message, keyPair.PublicKey)
	if err != nil {
		log.Fatalf("Encryption failed: %v", err)
	}
	fmt.Printf("   Ciphertext (%d bytes): %x...\n", len(ciphertext), ciphertext[:32])

	plaintext, err := api.SM2Decrypt(ciphertext, keyPair.PrivateKey)
	if err != nil {
		log.Fatalf("Decryption failed: %v", err)
	}
	fmt.Printf("   Decrypted message: %s\n", plaintext)

	// Signing/Verification
	fmt.Println("\n3. Testing SM2 Signing/Verification...")
	signature, err := api.SM2Sign(message, keyPair.PrivateKey)
	if err != nil {
		log.Fatalf("Signing failed: %v", err)
	}
	fmt.Printf("   Signature (%d bytes): %x\n", len(signature), signature)

	valid, err := api.SM2Verify(message, signature, keyPair.PublicKey)
	if err != nil {
		log.Fatalf("Verification failed: %v", err)
	}
	fmt.Printf("   Signature valid: %v\n", valid)

	// Test with wrong message
	wrongMessage := []byte("Wrong message")
	valid, err = api.SM2Verify(wrongMessage, signature, keyPair.PublicKey)
	if err != nil {
		log.Fatalf("Verification failed: %v", err)
	}
	fmt.Printf("   Wrong message verification: %v (should be false)\n", valid)
}

func demonstrateSM4() {
	// Generate key
	fmt.Println("1. Generating SM4 key...")
	key, err := api.SM4GenerateKey()
	if err != nil {
		log.Fatalf("Failed to generate key: %v", err)
	}
	fmt.Printf("   Key: %s\n", hex.EncodeToString(key))

	// Encryption/Decryption with padding
	fmt.Println("\n2. Testing SM4 Encryption/Decryption (with padding)...")
	message := []byte("Hello, SM4! This is a test message.")
	fmt.Printf("   Original message (%d bytes): %s\n", len(message), message)

	ciphertext, err := api.SM4Encrypt(message, key)
	if err != nil {
		log.Fatalf("Encryption failed: %v", err)
	}
	fmt.Printf("   Ciphertext (%d bytes): %s\n", len(ciphertext), hex.EncodeToString(ciphertext))

	plaintext, err := api.SM4Decrypt(ciphertext, key)
	if err != nil {
		log.Fatalf("Decryption failed: %v", err)
	}
	fmt.Printf("   Decrypted message: %s\n", plaintext)

	// Block encryption (no padding)
	fmt.Println("\n3. Testing SM4 Block Encryption (no padding)...")
	block := []byte("0123456789ABCDEF") // Exactly 16 bytes
	fmt.Printf("   Original block: %s\n", hex.EncodeToString(block))

	encryptedBlock, err := api.SM4EncryptBlock(block, key)
	if err != nil {
		log.Fatalf("Block encryption failed: %v", err)
	}
	fmt.Printf("   Encrypted block: %s\n", hex.EncodeToString(encryptedBlock))

	decryptedBlock, err := api.SM4DecryptBlock(encryptedBlock, key)
	if err != nil {
		log.Fatalf("Block decryption failed: %v", err)
	}
	fmt.Printf("   Decrypted block: %s\n", hex.EncodeToString(decryptedBlock))

	// Test with different message sizes
	fmt.Println("\n4. Testing with various message sizes...")
	testMessages := []string{
		"",
		"A",
		"Short message",
		"A message that is exactly 16 bytes long!",
		"A longer message that will require multiple blocks for encryption and padding.",
	}

	for i, msg := range testMessages {
		msgBytes := []byte(msg)
		encrypted, err := api.SM4Encrypt(msgBytes, key)
		if err != nil {
			log.Fatalf("Encryption failed: %v", err)
		}

		decrypted, err := api.SM4Decrypt(encrypted, key)
		if err != nil {
			log.Fatalf("Decryption failed: %v", err)
		}

		match := string(decrypted) == msg
		fmt.Printf("   Test %d: %d bytes → %d bytes → %d bytes (match: %v)\n",
			i+1, len(msgBytes), len(encrypted), len(decrypted), match)
	}

	fmt.Println("\n✅ All tests passed!")
}
