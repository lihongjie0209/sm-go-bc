package modes

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/lihongjie0209/sm-go-bc/crypto/engines"
	"github.com/lihongjie0209/sm-go-bc/crypto/params"
)

// Test vectors for SM4-CFB mode
func TestCFBBlockCipher_Basic(t *testing.T) {
	// Test key and IV
	key, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	iv, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	plaintext := []byte("Hello, SM4-CFB mode encryption!")

	// Pad plaintext to block size multiple
	blockSize := 16
	paddingLen := blockSize - (len(plaintext) % blockSize)
	if paddingLen != blockSize {
		plaintext = append(plaintext, bytes.Repeat([]byte{byte(paddingLen)}, paddingLen)...)
	}

	// Create cipher
	engine := engines.NewSM4Engine()
	cfb := NewCFBBlockCipher(engine, 128) // CFB128 - full block

	// Encrypt
	keyParam := params.NewKeyParameter(key)
	ivParam := params.NewParametersWithIV(keyParam, iv)
	cfb.Init(true, ivParam)

	ciphertext := make([]byte, len(plaintext))
	for i := 0; i < len(plaintext); i += blockSize {
		cfb.ProcessBlock(plaintext, i, ciphertext, i)
	}

	// Decrypt
	cfb.Init(false, ivParam)
	decrypted := make([]byte, len(ciphertext))
	for i := 0; i < len(ciphertext); i += blockSize {
		cfb.ProcessBlock(ciphertext, i, decrypted, i)
	}

	// Verify
	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("CFB decryption failed\nExpected: %x\nGot: %x", plaintext, decrypted)
	}
}

func TestCFBBlockCipher_CFB8(t *testing.T) {
	// Test CFB8 mode (1 byte at a time)
	key, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	iv, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	plaintext := []byte("Test CFB8 mode!")

	// Create cipher
	engine := engines.NewSM4Engine()
	cfb := NewCFBBlockCipher(engine, 8) // CFB8 - 1 byte at a time

	// Encrypt
	keyParam := params.NewKeyParameter(key)
	ivParam := params.NewParametersWithIV(keyParam, iv)
	cfb.Init(true, ivParam)

	ciphertext := make([]byte, len(plaintext))
	for i := 0; i < len(plaintext); i++ {
		cfb.ProcessBlock(plaintext, i, ciphertext, i)
	}

	// Decrypt
	cfb.Init(false, ivParam)
	decrypted := make([]byte, len(ciphertext))
	for i := 0; i < len(ciphertext); i++ {
		cfb.ProcessBlock(ciphertext, i, decrypted, i)
	}

	// Verify
	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("CFB8 decryption failed\nExpected: %x\nGot: %x", plaintext, decrypted)
	}
}

func TestCFBBlockCipher_CFB64(t *testing.T) {
	// Test CFB64 mode (8 bytes at a time)
	key, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	iv, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	plaintext := []byte("Test CFB64 mode! This is longer...")

	// Pad to 8-byte boundary
	blockSize := 8
	paddingLen := blockSize - (len(plaintext) % blockSize)
	if paddingLen != blockSize {
		plaintext = append(plaintext, bytes.Repeat([]byte{byte(paddingLen)}, paddingLen)...)
	}

	// Create cipher
	engine := engines.NewSM4Engine()
	cfb := NewCFBBlockCipher(engine, 64) // CFB64 - 8 bytes at a time

	// Encrypt
	keyParam := params.NewKeyParameter(key)
	ivParam := params.NewParametersWithIV(keyParam, iv)
	cfb.Init(true, ivParam)

	ciphertext := make([]byte, len(plaintext))
	for i := 0; i < len(plaintext); i += blockSize {
		cfb.ProcessBlock(plaintext, i, ciphertext, i)
	}

	// Decrypt
	cfb.Init(false, ivParam)
	decrypted := make([]byte, len(ciphertext))
	for i := 0; i < len(ciphertext); i += blockSize {
		cfb.ProcessBlock(ciphertext, i, decrypted, i)
	}

	// Verify
	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("CFB64 decryption failed\nExpected: %x\nGot: %x", plaintext, decrypted)
	}
}

func TestCFBBlockCipher_EmptyPlaintext(t *testing.T) {
	key, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	iv, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	plaintext := []byte{}

	engine := engines.NewSM4Engine()
	cfb := NewCFBBlockCipher(engine, 128)

	keyParam := params.NewKeyParameter(key)
	ivParam := params.NewParametersWithIV(keyParam, iv)
	cfb.Init(true, ivParam)

	ciphertext := make([]byte, len(plaintext))
	// No blocks to process

	cfb.Init(false, ivParam)
	decrypted := make([]byte, len(ciphertext))
	// No blocks to process

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Empty plaintext test failed")
	}
}

func TestCFBBlockCipher_Reset(t *testing.T) {
	key, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	iv, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	plaintext := []byte("Test Reset functionality")

	blockSize := 16
	paddingLen := blockSize - (len(plaintext) % blockSize)
	if paddingLen != blockSize {
		plaintext = append(plaintext, bytes.Repeat([]byte{byte(paddingLen)}, paddingLen)...)
	}

	engine := engines.NewSM4Engine()
	cfb := NewCFBBlockCipher(engine, 128)

	keyParam := params.NewKeyParameter(key)
	ivParam := params.NewParametersWithIV(keyParam, iv)
	cfb.Init(true, ivParam)

	// First encryption
	ciphertext1 := make([]byte, len(plaintext))
	for i := 0; i < len(plaintext); i += blockSize {
		cfb.ProcessBlock(plaintext, i, ciphertext1, i)
	}

	// Reset and encrypt again
	cfb.Reset()
	ciphertext2 := make([]byte, len(plaintext))
	for i := 0; i < len(plaintext); i += blockSize {
		cfb.ProcessBlock(plaintext, i, ciphertext2, i)
	}

	// Both ciphertexts should be identical
	if !bytes.Equal(ciphertext1, ciphertext2) {
		t.Errorf("Reset test failed: ciphertexts differ\nFirst:  %x\nSecond: %x", ciphertext1, ciphertext2)
	}
}

func TestCFBBlockCipher_IVChange(t *testing.T) {
	key, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	iv1, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	iv2, _ := hex.DecodeString("FEDCBA98765432100123456789ABCDEF")
	plaintext := []byte("Test IV change!!")

	engine := engines.NewSM4Engine()
	cfb := NewCFBBlockCipher(engine, 128)

	keyParam := params.NewKeyParameter(key)

	// Encrypt with IV1
	ivParam1 := params.NewParametersWithIV(keyParam, iv1)
	cfb.Init(true, ivParam1)
	ciphertext1 := make([]byte, len(plaintext))
	cfb.ProcessBlock(plaintext, 0, ciphertext1, 0)

	// Encrypt with IV2
	ivParam2 := params.NewParametersWithIV(keyParam, iv2)
	cfb.Init(true, ivParam2)
	ciphertext2 := make([]byte, len(plaintext))
	cfb.ProcessBlock(plaintext, 0, ciphertext2, 0)

	// Ciphertexts should be different
	if bytes.Equal(ciphertext1, ciphertext2) {
		t.Errorf("IV change test failed: ciphertexts are identical")
	}
}

func TestCFBBlockCipher_ProcessBytes(t *testing.T) {
	key, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	iv, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	plaintext := []byte("Test ProcessBytes method!")

	engine := engines.NewSM4Engine()
	cfb := NewCFBBlockCipher(engine, 128)

	keyParam := params.NewKeyParameter(key)
	ivParam := params.NewParametersWithIV(keyParam, iv)

	// Encrypt using ProcessBytes
	cfb.Init(true, ivParam)
	ciphertext := make([]byte, len(plaintext))
	cfb.ProcessBytes(plaintext, 0, len(plaintext), ciphertext, 0)

	// Decrypt using ProcessBytes
	cfb.Init(false, ivParam)
	decrypted := make([]byte, len(ciphertext))
	cfb.ProcessBytes(ciphertext, 0, len(ciphertext), decrypted, 0)

	// Verify
	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("ProcessBytes test failed\nExpected: %x\nGot: %x", plaintext, decrypted)
	}
}

func TestCFBBlockCipher_GetCurrentIV(t *testing.T) {
	key, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	iv, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")

	engine := engines.NewSM4Engine()
	cfb := NewCFBBlockCipher(engine, 128)

	keyParam := params.NewKeyParameter(key)
	ivParam := params.NewParametersWithIV(keyParam, iv)
	cfb.Init(true, ivParam)

	// Get initial IV
	currentIV := cfb.GetCurrentIV()
	if !bytes.Equal(iv, currentIV) {
		t.Errorf("GetCurrentIV test failed\nExpected: %x\nGot: %x", iv, currentIV)
	}
}

func TestCFBBlockCipher_AlgorithmName(t *testing.T) {
	engine := engines.NewSM4Engine()
	cfb := NewCFBBlockCipher(engine, 128)

	name := cfb.GetAlgorithmName()

	// Check if name starts with SM4/CFB
	if len(name) < 7 || name[:7] != "SM4/CFB" {
		t.Errorf("Algorithm name incorrect: %s", name)
	}
}

// Benchmark tests
func BenchmarkCFBBlockCipher_Encrypt(b *testing.B) {
	key, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	iv, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	plaintext := make([]byte, 1024)

	engine := engines.NewSM4Engine()
	cfb := NewCFBBlockCipher(engine, 128)

	keyParam := params.NewKeyParameter(key)
	ivParam := params.NewParametersWithIV(keyParam, iv)
	cfb.Init(true, ivParam)

	ciphertext := make([]byte, len(plaintext))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cfb.Reset()
		for j := 0; j < len(plaintext); j += 16 {
			cfb.ProcessBlock(plaintext, j, ciphertext, j)
		}
	}
}

func BenchmarkCFBBlockCipher_Decrypt(b *testing.B) {
	key, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	iv, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	ciphertext := make([]byte, 1024)

	engine := engines.NewSM4Engine()
	cfb := NewCFBBlockCipher(engine, 128)

	keyParam := params.NewKeyParameter(key)
	ivParam := params.NewParametersWithIV(keyParam, iv)
	cfb.Init(false, ivParam)

	plaintext := make([]byte, len(ciphertext))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cfb.Reset()
		for j := 0; j < len(ciphertext); j += 16 {
			cfb.ProcessBlock(ciphertext, j, plaintext, j)
		}
	}
}
