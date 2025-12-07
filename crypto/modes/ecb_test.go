package modes

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/lihongjie0209/sm-go-bc/crypto/engines"
	"github.com/lihongjie0209/sm-go-bc/crypto/params"
)

// Test basic ECB encryption and decryption
func TestECBBlockCipher_Basic(t *testing.T) {
	key, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	plaintext := []byte("1234567890123456") // Exactly 16 bytes

	// Create cipher
	engine := engines.NewSM4Engine()
	ecb := NewECBBlockCipher(engine)

	// Encrypt
	keyParam := params.NewKeyParameter(key)
	ecb.Init(true, keyParam)

	ciphertext := make([]byte, len(plaintext))
	ecb.ProcessBlock(plaintext, 0, ciphertext, 0)

	t.Logf("Plaintext:  %s", plaintext)
	t.Logf("Ciphertext: %x", ciphertext)

	// Decrypt
	ecb.Init(false, keyParam)
	decrypted := make([]byte, len(ciphertext))
	ecb.ProcessBlock(ciphertext, 0, decrypted, 0)

	// Verify
	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("ECB decryption failed\nExpected: %s\nGot: %s", plaintext, decrypted)
	}
}

// Test ECB with multiple blocks
func TestECBBlockCipher_MultipleBlocks(t *testing.T) {
	key, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	plaintext := []byte("1234567890123456ABCDEFGHIJKLMNOP") // 32 bytes (2 blocks)

	engine := engines.NewSM4Engine()
	ecb := NewECBBlockCipher(engine)

	keyParam := params.NewKeyParameter(key)
	ecb.Init(true, keyParam)

	// Encrypt block by block
	ciphertext := make([]byte, len(plaintext))
	blockSize := ecb.GetBlockSize()
	for i := 0; i < len(plaintext); i += blockSize {
		ecb.ProcessBlock(plaintext, i, ciphertext, i)
	}

	t.Logf("Ciphertext: %x", ciphertext)

	// Decrypt
	ecb.Init(false, keyParam)
	decrypted := make([]byte, len(ciphertext))
	for i := 0; i < len(ciphertext); i += blockSize {
		ecb.ProcessBlock(ciphertext, i, decrypted, i)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Multi-block decryption failed")
	}
}

// Test ECB pattern leakage (demonstrates why ECB is insecure)
func TestECBBlockCipher_PatternLeakage(t *testing.T) {
	key, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")

	// Two identical plaintext blocks
	plaintext1 := []byte("1234567890123456")
	plaintext2 := []byte("1234567890123456") // Same as plaintext1

	engine := engines.NewSM4Engine()
	ecb := NewECBBlockCipher(engine)

	keyParam := params.NewKeyParameter(key)
	ecb.Init(true, keyParam)

	// Encrypt both blocks
	ciphertext1 := make([]byte, len(plaintext1))
	ecb.ProcessBlock(plaintext1, 0, ciphertext1, 0)

	ciphertext2 := make([]byte, len(plaintext2))
	ecb.ProcessBlock(plaintext2, 0, ciphertext2, 0)

	// ⚠️ WARNING: In ECB mode, identical plaintext blocks produce identical ciphertext!
	// This is a security vulnerability.
	if !bytes.Equal(ciphertext1, ciphertext2) {
		t.Error("Expected identical ciphertexts for identical plaintexts (ECB pattern leakage)")
	} else {
		t.Logf("⚠️  SECURITY WARNING: ECB mode leaks patterns!")
		t.Logf("    Identical plaintexts produce identical ciphertexts: %x", ciphertext1)
	}
}

// Test ECB algorithm name
func TestECBBlockCipher_AlgorithmName(t *testing.T) {
	engine := engines.NewSM4Engine()
	ecb := NewECBBlockCipher(engine)

	expected := "SM4/ECB"
	name := ecb.GetAlgorithmName()

	if name != expected {
		t.Errorf("Algorithm name mismatch\nExpected: %s\nGot: %s", expected, name)
	}
}

// Test ECB block size
func TestECBBlockCipher_BlockSize(t *testing.T) {
	engine := engines.NewSM4Engine()
	ecb := NewECBBlockCipher(engine)

	expectedSize := 16 // SM4 block size
	actualSize := ecb.GetBlockSize()

	if actualSize != expectedSize {
		t.Errorf("Block size mismatch\nExpected: %d\nGot: %d", expectedSize, actualSize)
	}
}

// Test ECB reset
func TestECBBlockCipher_Reset(t *testing.T) {
	key, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	plaintext := []byte("1234567890123456")

	engine := engines.NewSM4Engine()
	ecb := NewECBBlockCipher(engine)

	keyParam := params.NewKeyParameter(key)
	ecb.Init(true, keyParam)

	// First encryption
	ciphertext1 := make([]byte, len(plaintext))
	ecb.ProcessBlock(plaintext, 0, ciphertext1, 0)

	// Reset and encrypt again
	ecb.Reset()
	ciphertext2 := make([]byte, len(plaintext))
	ecb.ProcessBlock(plaintext, 0, ciphertext2, 0)

	// Results should be identical (ECB is stateless)
	if !bytes.Equal(ciphertext1, ciphertext2) {
		t.Errorf("Reset test failed: ciphertexts differ\nFirst:  %x\nSecond: %x",
			ciphertext1, ciphertext2)
	}
}

// Test ECB with different keys
func TestECBBlockCipher_DifferentKeys(t *testing.T) {
	key1, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	key2, _ := hex.DecodeString("FEDCBA98765432100123456789ABCDEF")
	plaintext := []byte("1234567890123456")

	engine := engines.NewSM4Engine()
	ecb := NewECBBlockCipher(engine)

	// Encrypt with key1
	keyParam1 := params.NewKeyParameter(key1)
	ecb.Init(true, keyParam1)
	ciphertext1 := make([]byte, len(plaintext))
	ecb.ProcessBlock(plaintext, 0, ciphertext1, 0)

	// Encrypt with key2
	keyParam2 := params.NewKeyParameter(key2)
	ecb.Init(true, keyParam2)
	ciphertext2 := make([]byte, len(plaintext))
	ecb.ProcessBlock(plaintext, 0, ciphertext2, 0)

	// Ciphertexts should be different
	if bytes.Equal(ciphertext1, ciphertext2) {
		t.Error("Expected different ciphertexts with different keys")
	}
}

// Test ECB underlying cipher
func TestECBBlockCipher_UnderlyingCipher(t *testing.T) {
	engine := engines.NewSM4Engine()
	ecb := NewECBBlockCipher(engine)

	underlying := ecb.GetUnderlyingCipher()
	if underlying != engine {
		t.Error("GetUnderlyingCipher returned wrong cipher")
	}
}

// Benchmark ECB encryption
func BenchmarkECBBlockCipher_Encrypt(b *testing.B) {
	key, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	plaintext := make([]byte, 1024) // 64 blocks

	engine := engines.NewSM4Engine()
	ecb := NewECBBlockCipher(engine)

	keyParam := params.NewKeyParameter(key)
	ecb.Init(true, keyParam)

	ciphertext := make([]byte, len(plaintext))
	blockSize := ecb.GetBlockSize()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := 0; j < len(plaintext); j += blockSize {
			ecb.ProcessBlock(plaintext, j, ciphertext, j)
		}
	}
}

// Benchmark ECB decryption
func BenchmarkECBBlockCipher_Decrypt(b *testing.B) {
	key, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	ciphertext := make([]byte, 1024) // 64 blocks

	engine := engines.NewSM4Engine()
	ecb := NewECBBlockCipher(engine)

	keyParam := params.NewKeyParameter(key)
	ecb.Init(false, keyParam)

	plaintext := make([]byte, len(ciphertext))
	blockSize := ecb.GetBlockSize()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := 0; j < len(ciphertext); j += blockSize {
			ecb.ProcessBlock(ciphertext, j, plaintext, j)
		}
	}
}
