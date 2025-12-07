package smgobc

import (
	"bytes"
	"testing"
)

func TestSM4_GenerateKey(t *testing.T) {
	sm4 := &SM4{}
	
	key, err := sm4.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	
	if len(key) != 16 {
		t.Errorf("Expected key length 16, got %d", len(key))
	}
	
	// Generate another key and ensure they're different
	key2, err := sm4.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate second key: %v", err)
	}
	
	if bytes.Equal(key, key2) {
		t.Error("Generated keys should be different")
	}
}

func TestSM4_EncryptDecrypt(t *testing.T) {
	sm4 := &SM4{}
	
	key := []byte{
		0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
		0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
	}
	
	plaintext := []byte("Hello, SM4! This is a test message.")
	
	// Encrypt
	ciphertext, err := sm4.Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}
	
	// Ciphertext should be padded to block size
	if len(ciphertext)%16 != 0 {
		t.Errorf("Ciphertext length should be multiple of 16, got %d", len(ciphertext))
	}
	
	// Decrypt
	decrypted, err := sm4.Decrypt(ciphertext, key)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}
	
	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decrypted text doesn't match original.\nExpected: %s\nGot: %s", plaintext, decrypted)
	}
}

func TestSM4_EncryptBlock(t *testing.T) {
	sm4 := &SM4{}
	
	key := []byte{
		0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
		0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
	}
	
	block := []byte{
		0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
		0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
	}
	
	// Encrypt block
	encrypted, err := sm4.EncryptBlock(block, key)
	if err != nil {
		t.Fatalf("Block encryption failed: %v", err)
	}
	
	if len(encrypted) != 16 {
		t.Errorf("Expected encrypted block length 16, got %d", len(encrypted))
	}
	
	// Decrypt block
	decrypted, err := sm4.DecryptBlock(encrypted, key)
	if err != nil {
		t.Fatalf("Block decryption failed: %v", err)
	}
	
	if !bytes.Equal(block, decrypted) {
		t.Error("Decrypted block doesn't match original")
	}
}

func TestSM4_InvalidKey(t *testing.T) {
	sm4 := &SM4{}
	
	invalidKey := []byte{0x01, 0x02, 0x03} // Too short
	plaintext := []byte("test")
	
	_, err := sm4.Encrypt(plaintext, invalidKey)
	if err == nil {
		t.Error("Expected error for invalid key length")
	}
}

func TestSM4_InvalidBlockSize(t *testing.T) {
	sm4 := &SM4{}
	
	key := []byte{
		0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
		0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
	}
	
	invalidBlock := []byte{0x01, 0x02, 0x03} // Not 16 bytes
	
	_, err := sm4.EncryptBlock(invalidBlock, key)
	if err == nil {
		t.Error("Expected error for invalid block size")
	}
}
