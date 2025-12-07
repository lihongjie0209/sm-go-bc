package api

import (
	"bytes"
	"testing"
)

func TestSM4GenerateKey(t *testing.T) {
	key, err := SM4GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	if len(key) != SM4KeySize {
		t.Fatalf("Expected key size %d, got %d", SM4KeySize, len(key))
	}

	// Generate another key and verify they're different
	key2, err := SM4GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate second key: %v", err)
	}

	if bytes.Equal(key, key2) {
		t.Fatal("Generated keys should be different")
	}
}

func TestSM4EncryptDecrypt(t *testing.T) {
	key, err := SM4GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	plaintext := []byte("Hello, SM4!")

	ciphertext, err := SM4Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Verify ciphertext is different
	if bytes.Equal(ciphertext, plaintext) {
		t.Fatal("Ciphertext equals plaintext")
	}

	// Verify ciphertext length is a multiple of block size
	if len(ciphertext)%SM4BlockSize != 0 {
		t.Fatalf("Ciphertext length not a multiple of block size: %d", len(ciphertext))
	}

	decrypted, err := SM4Decrypt(ciphertext, key)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("Decrypted text doesn't match.\nExpected: %s\nGot: %s", plaintext, decrypted)
	}
}

func TestSM4EncryptDecryptBlock(t *testing.T) {
	key, err := SM4GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Create a 16-byte block
	block := []byte("0123456789ABCDEF")

	encrypted, err := SM4EncryptBlock(block, key)
	if err != nil {
		t.Fatalf("Block encryption failed: %v", err)
	}

	if len(encrypted) != SM4BlockSize {
		t.Fatalf("Expected encrypted size %d, got %d", SM4BlockSize, len(encrypted))
	}

	decrypted, err := SM4DecryptBlock(encrypted, key)
	if err != nil {
		t.Fatalf("Block decryption failed: %v", err)
	}

	if !bytes.Equal(decrypted, block) {
		t.Fatalf("Decrypted block doesn't match.\nExpected: %v\nGot: %v", block, decrypted)
	}
}

func TestSM4EncryptMultipleSizes(t *testing.T) {
	key, err := SM4GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	testCases := []struct {
		name string
		data []byte
	}{
		{"Empty", []byte{}},
		{"1 byte", []byte{0x01}},
		{"15 bytes", []byte("123456789012345")},
		{"16 bytes", []byte("0123456789ABCDEF")},
		{"17 bytes", []byte("0123456789ABCDEFG")},
		{"32 bytes", []byte("0123456789ABCDEF0123456789ABCDEF")},
		{"100 bytes", bytes.Repeat([]byte("A"), 100)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ciphertext, err := SM4Encrypt(tc.data, key)
			if err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}

			plaintext, err := SM4Decrypt(ciphertext, key)
			if err != nil {
				t.Fatalf("Decryption failed: %v", err)
			}

			if !bytes.Equal(plaintext, tc.data) {
				t.Fatalf("Mismatch for %s", tc.name)
			}
		})
	}
}

func TestSM4InvalidKeySize(t *testing.T) {
	plaintext := []byte("test")

	// Test with wrong key size
	shortKey := []byte("short")
	_, err := SM4Encrypt(plaintext, shortKey)
	if err == nil {
		t.Fatal("Expected error with short key")
	}

	longKey := bytes.Repeat([]byte("A"), 32)
	_, err = SM4Encrypt(plaintext, longKey)
	if err == nil {
		t.Fatal("Expected error with long key")
	}
}

func TestSM4InvalidBlockSize(t *testing.T) {
	key, _ := SM4GenerateKey()

	// Test block encryption with wrong size
	shortBlock := []byte("short")
	_, err := SM4EncryptBlock(shortBlock, key)
	if err == nil {
		t.Fatal("Expected error with short block")
	}

	longBlock := bytes.Repeat([]byte("A"), 32)
	_, err = SM4EncryptBlock(longBlock, key)
	if err == nil {
		t.Fatal("Expected error with long block")
	}
}

func TestPKCS7Padding(t *testing.T) {
	testCases := []struct {
		name     string
		input    []byte
		expected int // expected length after padding
	}{
		{"Empty", []byte{}, 16},
		{"1 byte", []byte{0x01}, 16},
		{"15 bytes", bytes.Repeat([]byte{0x01}, 15), 16},
		{"16 bytes", bytes.Repeat([]byte{0x01}, 16), 32},
		{"17 bytes", bytes.Repeat([]byte{0x01}, 17), 32},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			padded := pkcs7Pad(tc.input, SM4BlockSize)
			if len(padded) != tc.expected {
				t.Fatalf("Expected length %d, got %d", tc.expected, len(padded))
			}

			unpadded, err := pkcs7Unpad(padded)
			if err != nil {
				t.Fatalf("Unpadding failed: %v", err)
			}

			if !bytes.Equal(unpadded, tc.input) {
				t.Fatal("Unpadded data doesn't match original")
			}
		})
	}
}
