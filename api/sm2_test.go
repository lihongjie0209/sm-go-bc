package api

import (
	"bytes"
	"testing"
)

func TestSM2GenerateKeyPair(t *testing.T) {
	keyPair, err := SM2GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	if keyPair.PrivateKey == nil {
		t.Fatal("Private key is nil")
	}

	if keyPair.PublicKey == nil {
		t.Fatal("Public key is nil")
	}

	if keyPair.PublicKey.X == nil || keyPair.PublicKey.Y == nil {
		t.Fatal("Public key coordinates are nil")
	}

	// Verify private key is in valid range
	if keyPair.PrivateKey.Sign() <= 0 || keyPair.PrivateKey.Cmp(sm2N) >= 0 {
		t.Fatal("Private key out of range")
	}
}

func TestSM2EncryptDecrypt(t *testing.T) {
	// Generate key pair
	keyPair, err := SM2GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Test message
	message := []byte("Hello, SM2!")

	// Encrypt
	ciphertext, err := SM2Encrypt(message, keyPair.PublicKey)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Verify ciphertext is different from plaintext
	if bytes.Equal(ciphertext, message) {
		t.Fatal("Ciphertext equals plaintext")
	}

	// Decrypt
	plaintext, err := SM2Decrypt(ciphertext, keyPair.PrivateKey)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	// Verify
	if !bytes.Equal(plaintext, message) {
		t.Fatalf("Decrypted text doesn't match original.\nExpected: %s\nGot: %s", message, plaintext)
	}
}

func TestSM2SignVerify(t *testing.T) {
	// Generate key pair
	keyPair, err := SM2GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Test message
	message := []byte("Hello, SM2!")

	// Sign
	signature, err := SM2Sign(message, keyPair.PrivateKey)
	if err != nil {
		t.Fatalf("Signing failed: %v", err)
	}

	// Verify signature length (should be around 64-72 bytes for DER encoding)
	if len(signature) < 64 || len(signature) > 80 {
		t.Fatalf("Unexpected signature length: %d", len(signature))
	}

	// Verify
	valid, err := SM2Verify(message, signature, keyPair.PublicKey)
	if err != nil {
		t.Fatalf("Verification failed: %v", err)
	}

	if !valid {
		t.Fatal("Signature verification failed")
	}

	// Test with wrong message
	wrongMessage := []byte("Wrong message")
	valid, err = SM2Verify(wrongMessage, signature, keyPair.PublicKey)
	if err != nil {
		t.Fatalf("Verification failed: %v", err)
	}

	if valid {
		t.Fatal("Signature should not verify with wrong message")
	}
}

func TestSM2EncryptMultipleMessages(t *testing.T) {
	keyPair, err := SM2GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	messages := []string{
		"Short",
		"Medium length message",
		"A much longer message that spans multiple lines and contains various characters: 你好，世界！",
		"",
	}

	for _, msg := range messages {
		message := []byte(msg)

		ciphertext, err := SM2Encrypt(message, keyPair.PublicKey)
		if err != nil {
			t.Fatalf("Encryption failed for message '%s': %v", msg, err)
		}

		plaintext, err := SM2Decrypt(ciphertext, keyPair.PrivateKey)
		if err != nil {
			t.Fatalf("Decryption failed for message '%s': %v", msg, err)
		}

		if !bytes.Equal(plaintext, message) {
			t.Fatalf("Mismatch for message '%s'", msg)
		}
	}
}
