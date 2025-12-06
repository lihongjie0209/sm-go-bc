package sm2

import (
	"bytes"
	"math/big"
	"testing"
)

func TestKDF(t *testing.T) {
	// Test with known input
	z := []byte("test input for KDF")
	
	// Test different lengths
	k16 := KDF(z, 16)
	if len(k16) != 16 {
		t.Errorf("Expected 16 bytes, got %d", len(k16))
	}
	
	k32 := KDF(z, 32)
	if len(k32) != 32 {
		t.Errorf("Expected 32 bytes, got %d", len(k32))
	}
	
	k64 := KDF(z, 64)
	if len(k64) != 64 {
		t.Errorf("Expected 64 bytes, got %d", len(k64))
	}
	
	// Test determinism
	k32_again := KDF(z, 32)
	if !bytes.Equal(k32, k32_again) {
		t.Error("KDF should be deterministic")
	}
	
	// Test empty input
	k0 := KDF(z, 0)
	if len(k0) != 0 {
		t.Error("KDF with klen=0 should return empty")
	}
}

func TestSM2EngineBasic(t *testing.T) {
	// Create a key pair
	privateKey := big.NewInt(123456789)
	publicKey := GetG().Multiply(privateKey)
	
	// Create engine
	engine := NewSM2Engine()
	
	// Test encryption
	err := engine.Init(true, publicKey, nil)
	if err != nil {
		t.Fatalf("Failed to init for encryption: %v", err)
	}
	
	plaintext := []byte("Hello, SM2!")
	ciphertext, err := engine.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}
	
	// Ciphertext should be longer than plaintext
	// C1 (65) + C3 (32) + C2 (len(plaintext))
	expectedLen := 65 + 32 + len(plaintext)
	if len(ciphertext) != expectedLen {
		t.Errorf("Expected ciphertext length %d, got %d", expectedLen, len(ciphertext))
	}
	
	// Test decryption
	engine2 := NewSM2Engine()
	err = engine2.Init(false, nil, privateKey)
	if err != nil {
		t.Fatalf("Failed to init for decryption: %v", err)
	}
	
	decrypted, err := engine2.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}
	
	// Verify plaintext
	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decrypted text doesn't match.\nExpected: %s\nGot: %s", 
			string(plaintext), string(decrypted))
	}
}

func TestSM2EngineEmptyMessage(t *testing.T) {
	privateKey := big.NewInt(987654321)
	publicKey := GetG().Multiply(privateKey)
	
	engine := NewSM2Engine()
	engine.Init(true, publicKey, nil)
	
	plaintext := []byte("")
	ciphertext, err := engine.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encryption of empty message failed: %v", err)
	}
	
	engine2 := NewSM2Engine()
	engine2.Init(false, nil, privateKey)
	
	decrypted, err := engine2.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}
	
	if !bytes.Equal(plaintext, decrypted) {
		t.Error("Empty message decryption failed")
	}
}

func TestSM2EngineLongMessage(t *testing.T) {
	privateKey := big.NewInt(111222333)
	publicKey := GetG().Multiply(privateKey)
	
	engine := NewSM2Engine()
	engine.Init(true, publicKey, nil)
	
	// 1KB message
	plaintext := make([]byte, 1024)
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}
	
	ciphertext, err := engine.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}
	
	engine2 := NewSM2Engine()
	engine2.Init(false, nil, privateKey)
	
	decrypted, err := engine2.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}
	
	if !bytes.Equal(plaintext, decrypted) {
		t.Error("Long message decryption failed")
	}
}

func TestSM2EngineC1C2C3Mode(t *testing.T) {
	privateKey := big.NewInt(444555666)
	publicKey := GetG().Multiply(privateKey)
	
	// Test old C1C2C3 mode
	engine := NewSM2Engine()
	engine.SetMode(Mode_C1C2C3)
	engine.Init(true, publicKey, nil)
	
	plaintext := []byte("Test C1C2C3 mode")
	ciphertext, err := engine.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}
	
	engine2 := NewSM2Engine()
	engine2.SetMode(Mode_C1C2C3)
	engine2.Init(false, nil, privateKey)
	
	decrypted, err := engine2.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}
	
	if !bytes.Equal(plaintext, decrypted) {
		t.Error("C1C2C3 mode decryption failed")
	}
}

func TestSM2EngineInvalidKey(t *testing.T) {
	engine := NewSM2Engine()
	
	// Test with nil public key
	err := engine.Init(true, nil, nil)
	if err == nil {
		t.Error("Should fail with nil public key")
	}
	
	// Test with infinity point
	inf := GetG().Multiply(GetN())
	err = engine.Init(true, inf, nil)
	if err == nil {
		t.Error("Should fail with infinity public key")
	}
	
	// Test with nil private key
	err = engine.Init(false, nil, nil)
	if err == nil {
		t.Error("Should fail with nil private key")
	}
	
	// Test with invalid private key (0)
	err = engine.Init(false, nil, big.NewInt(0))
	if err == nil {
		t.Error("Should fail with zero private key")
	}
	
	// Test with invalid private key (>= n)
	err = engine.Init(false, nil, GetN())
	if err == nil {
		t.Error("Should fail with private key >= n")
	}
}

func TestSM2EngineInvalidCiphertext(t *testing.T) {
	privateKey := big.NewInt(777888999)
	
	engine := NewSM2Engine()
	engine.Init(false, nil, privateKey)
	
	// Test with too short ciphertext
	_, err := engine.Decrypt([]byte{0x04})
	if err == nil {
		t.Error("Should fail with too short ciphertext")
	}
	
	// Test with invalid C1 format
	invalid := make([]byte, 100)
	invalid[0] = 0xFF // Invalid format byte
	_, err = engine.Decrypt(invalid)
	if err == nil {
		t.Error("Should fail with invalid C1 format")
	}
}

func TestSM2EngineWrongKey(t *testing.T) {
	// Encrypt with one key
	privateKey1 := big.NewInt(123456)
	publicKey1 := GetG().Multiply(privateKey1)
	
	engine := NewSM2Engine()
	engine.Init(true, publicKey1, nil)
	
	plaintext := []byte("Secret message")
	ciphertext, err := engine.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}
	
	// Try to decrypt with different key
	privateKey2 := big.NewInt(654321)
	engine2 := NewSM2Engine()
	engine2.Init(false, nil, privateKey2)
	
	_, err = engine2.Decrypt(ciphertext)
	if err == nil {
		t.Error("Should fail to decrypt with wrong key")
	}
}

func TestSM2EngineMultipleMessages(t *testing.T) {
	privateKey := big.NewInt(999888777)
	publicKey := GetG().Multiply(privateKey)
	
	messages := []string{
		"First message",
		"Second message",
		"Third message with more content",
		"短信息",
		"A",
	}
	
	for _, msg := range messages {
		plaintext := []byte(msg)
		
		// Encrypt
		engine := NewSM2Engine()
		engine.Init(true, publicKey, nil)
		ciphertext, err := engine.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("Encryption failed for '%s': %v", msg, err)
		}
		
		// Decrypt
		engine2 := NewSM2Engine()
		engine2.Init(false, nil, privateKey)
		decrypted, err := engine2.Decrypt(ciphertext)
		if err != nil {
			t.Fatalf("Decryption failed for '%s': %v", msg, err)
		}
		
		if !bytes.Equal(plaintext, decrypted) {
			t.Errorf("Mismatch for '%s'", msg)
		}
	}
}
