package main

import (
	"encoding/hex"
	"fmt"
	"log"

	smbc "github.com/lihongjie0209/sm-go-bc"
)

func main() {
	fmt.Println("=== SM-BC High-Level API Examples ===\n")

	// SM3 Example
	sm3Example()
	
	// SM4 Example
	sm4Example()
	
	// SM2 Example
	sm2Example()
}

func sm3Example() {
	fmt.Println("--- SM3 Hash Example ---")
	
	sm3 := &smbc.SM3{}
	
	data := []byte("Hello, SM3!")
	hash := sm3.Hash(data)
	
	fmt.Printf("Data: %s\n", data)
	fmt.Printf("SM3 Hash: %s\n", hex.EncodeToString(hash))
	fmt.Println()
}

func sm4Example() {
	fmt.Println("--- SM4 Encryption Example ---")
	
	sm4 := &smbc.SM4{}
	
	// Generate a random key
	key, err := sm4.GenerateKey()
	if err != nil {
		log.Fatalf("Failed to generate key: %v", err)
	}
	fmt.Printf("Generated Key: %s\n", hex.EncodeToString(key))
	
	// Encrypt
	plaintext := []byte("Hello, SM4! This is a secret message.")
	fmt.Printf("Plaintext: %s\n", plaintext)
	
	ciphertext, err := sm4.Encrypt(plaintext, key)
	if err != nil {
		log.Fatalf("Encryption failed: %v", err)
	}
	fmt.Printf("Ciphertext: %s\n", hex.EncodeToString(ciphertext))
	
	// Decrypt
	decrypted, err := sm4.Decrypt(ciphertext, key)
	if err != nil {
		log.Fatalf("Decryption failed: %v", err)
	}
	fmt.Printf("Decrypted: %s\n", decrypted)
	fmt.Println()
}

func sm2Example() {
	fmt.Println("--- SM2 Signature and Encryption Example ---")
	
	sm2 := &smbc.SM2{}
	
	// Generate key pair
	keyPair, err := sm2.GenerateKeyPair()
	if err != nil {
		log.Fatalf("Failed to generate key pair: %v", err)
	}
	fmt.Printf("Private Key: %s\n", hex.EncodeToString(keyPair.PrivateKey))
	fmt.Printf("Public Key: %s\n", hex.EncodeToString(keyPair.PublicKey))
	
	// Sign and Verify
	message := []byte("Hello, SM2!")
	userID := []byte("testuser@example.com")
	
	signature, err := sm2.Sign(message, keyPair.PrivateKey, userID)
	if err != nil {
		log.Fatalf("Signing failed: %v", err)
	}
	fmt.Printf("\nMessage: %s\n", message)
	fmt.Printf("Signature: %s\n", hex.EncodeToString(signature))
	
	valid, err := sm2.Verify(message, signature, keyPair.PublicKey, userID)
	if err != nil {
		log.Fatalf("Verification failed: %v", err)
	}
	fmt.Printf("Signature Valid: %v\n", valid)
	
	// Encrypt and Decrypt
	plaintext := []byte("This is a secret message!")
	fmt.Printf("\nPlaintext: %s\n", plaintext)
	
	ciphertext, err := sm2.Encrypt(plaintext, keyPair.PublicKey)
	if err != nil {
		log.Fatalf("Encryption failed: %v", err)
	}
	fmt.Printf("Ciphertext: %s\n", hex.EncodeToString(ciphertext))
	
	decrypted, err := sm2.Decrypt(ciphertext, keyPair.PrivateKey)
	if err != nil {
		log.Fatalf("Decryption failed: %v", err)
	}
	fmt.Printf("Decrypted: %s\n", decrypted)
	fmt.Println()
}
