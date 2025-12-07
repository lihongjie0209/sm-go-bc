package smgobc

import (
	"bytes"
	"testing"
)

func TestSM2_GenerateKeyPair(t *testing.T) {
	sm2 := &SM2{}
	
	keyPair, err := sm2.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}
	
	if len(keyPair.PrivateKey) != 32 {
		t.Errorf("Expected private key length 32, got %d", len(keyPair.PrivateKey))
	}
	
	if len(keyPair.PublicKey) != 65 {
		t.Errorf("Expected public key length 65, got %d", len(keyPair.PublicKey))
	}
	
	if keyPair.PublicKey[0] != 0x04 {
		t.Errorf("Expected uncompressed point format (0x04), got 0x%02x", keyPair.PublicKey[0])
	}
	
	// Generate another key pair and ensure they're different
	keyPair2, err := sm2.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate second key pair: %v", err)
	}
	
	if bytes.Equal(keyPair.PrivateKey, keyPair2.PrivateKey) {
		t.Error("Generated private keys should be different")
	}
}

func TestSM2_SignVerify(t *testing.T) {
	sm2 := &SM2{}
	
	// Generate key pair
	keyPair, err := sm2.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}
	
	message := []byte("Hello, SM2! This is a test message.")
	userID := []byte("testuser@example.com")
	
	// Sign
	signature, err := sm2.Sign(message, keyPair.PrivateKey, userID)
	if err != nil {
		t.Fatalf("Signing failed: %v", err)
	}
	
	if len(signature) == 0 {
		t.Error("Signature should not be empty")
	}
	
	// Verify with correct key
	valid, err := sm2.Verify(message, signature, keyPair.PublicKey, userID)
	if err != nil {
		t.Fatalf("Verification failed: %v", err)
	}
	
	if !valid {
		t.Error("Signature should be valid")
	}
	
	// Verify with wrong message
	wrongMessage := []byte("Wrong message")
	valid, err = sm2.Verify(wrongMessage, signature, keyPair.PublicKey, userID)
	if err != nil {
		t.Fatalf("Verification failed: %v", err)
	}
	
	if valid {
		t.Error("Signature should be invalid for wrong message")
	}
}

func TestSM2_EncryptDecrypt(t *testing.T) {
	sm2 := &SM2{}
	
	// Generate key pair
	keyPair, err := sm2.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}
	
	plaintext := []byte("Hello, SM2! This is a secret message.")
	
	// Encrypt
	ciphertext, err := sm2.Encrypt(plaintext, keyPair.PublicKey)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}
	
	if len(ciphertext) == 0 {
		t.Error("Ciphertext should not be empty")
	}
	
	// Decrypt
	decrypted, err := sm2.Decrypt(ciphertext, keyPair.PrivateKey)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}
	
	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decrypted text doesn't match original.\nExpected: %s\nGot: %s", plaintext, decrypted)
	}
}

func TestSM2_InvalidPrivateKey(t *testing.T) {
	sm2 := &SM2{}
	
	invalidKey := []byte{0x01, 0x02, 0x03} // Too short
	message := []byte("test")
	
	_, err := sm2.Sign(message, invalidKey, nil)
	if err == nil {
		t.Error("Expected error for invalid private key length")
	}
}

func TestSM2_InvalidPublicKey(t *testing.T) {
	sm2 := &SM2{}
	
	invalidKey := []byte{0x01, 0x02, 0x03} // Too short
	plaintext := []byte("test")
	
	_, err := sm2.Encrypt(plaintext, invalidKey)
	if err == nil {
		t.Error("Expected error for invalid public key")
	}
}
