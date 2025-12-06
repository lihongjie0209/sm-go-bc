package modes

import (
	"encoding/hex"
	"testing"
	
	"github.com/lihongjie0209/sm-go-bc/crypto/engines"
	"github.com/lihongjie0209/sm-go-bc/crypto/params"
)

func TestCTRGetAlgorithmName(t *testing.T) {
	engine := engines.NewSM4Engine()
	ctr := NewCTRBlockCipher(engine)
	
	expectedName := "SM4/CTR"
	if ctr.GetAlgorithmName() != expectedName {
		t.Errorf("Expected algorithm name '%s', got '%s'", expectedName, ctr.GetAlgorithmName())
	}
}

func TestCTRGetBlockSize(t *testing.T) {
	engine := engines.NewSM4Engine()
	ctr := NewCTRBlockCipher(engine)
	
	if ctr.GetBlockSize() != 16 {
		t.Errorf("Expected block size 16, got %d", ctr.GetBlockSize())
	}
}

func TestCTREncryptDecryptSingleBlock(t *testing.T) {
	key, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	iv, _ := hex.DecodeString("00112233445566778899aabbccddeeff")
	plaintext, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	
	// Encrypt
	engine := engines.NewSM4Engine()
	ctr := NewCTRBlockCipher(engine)
	keyParam := params.NewKeyParameter(key)
	ivParam := params.NewParametersWithIV(keyParam, iv)
	ctr.Init(true, ivParam)
	
	ciphertext := make([]byte, 16)
	ctr.ProcessBlock(plaintext, 0, ciphertext, 0)
	
	// Decrypt (CTR uses same operation for both)
	engine2 := engines.NewSM4Engine()
	ctr2 := NewCTRBlockCipher(engine2)
	ctr2.Init(false, ivParam) // forEncryption doesn't matter for CTR
	
	decrypted := make([]byte, 16)
	ctr2.ProcessBlock(ciphertext, 0, decrypted, 0)
	
	if hex.EncodeToString(plaintext) != hex.EncodeToString(decrypted) {
		t.Errorf("Decryption failed\nExpected: %s\nGot:      %s",
			hex.EncodeToString(plaintext), hex.EncodeToString(decrypted))
	}
}

func TestCTRMultipleBlocks(t *testing.T) {
	key, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	iv, _ := hex.DecodeString("00112233445566778899aabbccddeeff")
	
	// Create 3 blocks of plaintext
	plaintext := make([]byte, 48)
	for i := range plaintext {
		plaintext[i] = byte(i)
	}
	
	// Encrypt
	engine := engines.NewSM4Engine()
	ctr := NewCTRBlockCipher(engine)
	keyParam := params.NewKeyParameter(key)
	ivParam := params.NewParametersWithIV(keyParam, iv)
	ctr.Init(true, ivParam)
	
	ciphertext := make([]byte, 48)
	for i := 0; i < 3; i++ {
		ctr.ProcessBlock(plaintext, i*16, ciphertext, i*16)
	}
	
	// Decrypt
	engine2 := engines.NewSM4Engine()
	ctr2 := NewCTRBlockCipher(engine2)
	ctr2.Init(false, ivParam)
	
	decrypted := make([]byte, 48)
	for i := 0; i < 3; i++ {
		ctr2.ProcessBlock(ciphertext, i*16, decrypted, i*16)
	}
	
	if hex.EncodeToString(plaintext) != hex.EncodeToString(decrypted) {
		t.Errorf("Multi-block decryption failed")
	}
}

func TestCTRStreamMode(t *testing.T) {
	// CTR can process byte-by-byte (stream mode)
	key, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	iv, _ := hex.DecodeString("00112233445566778899aabbccddeeff")
	plaintext := []byte("Hello, CTR mode!") // 16 bytes
	
	// Encrypt
	engine := engines.NewSM4Engine()
	ctr := NewCTRBlockCipher(engine)
	keyParam := params.NewKeyParameter(key)
	ivParam := params.NewParametersWithIV(keyParam, iv)
	ctr.Init(true, ivParam)
	
	ciphertext := make([]byte, len(plaintext))
	ctr.ProcessBlock(plaintext, 0, ciphertext, 0)
	
	// Decrypt
	engine2 := engines.NewSM4Engine()
	ctr2 := NewCTRBlockCipher(engine2)
	ctr2.Init(false, ivParam)
	
	decrypted := make([]byte, len(ciphertext))
	ctr2.ProcessBlock(ciphertext, 0, decrypted, 0)
	
	if string(plaintext) != string(decrypted) {
		t.Errorf("Stream mode failed\nExpected: %s\nGot:      %s",
			string(plaintext), string(decrypted))
	}
}

func TestCTRDifferentIVs(t *testing.T) {
	// Test that different IVs produce different outputs
	key, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	plaintext, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	
	// Encrypt with IV1
	iv1, _ := hex.DecodeString("00000000000000000000000000000000")
	engine1 := engines.NewSM4Engine()
	ctr1 := NewCTRBlockCipher(engine1)
	keyParam := params.NewKeyParameter(key)
	ivParam1 := params.NewParametersWithIV(keyParam, iv1)
	ctr1.Init(true, ivParam1)
	
	ciphertext1 := make([]byte, 16)
	ctr1.ProcessBlock(plaintext, 0, ciphertext1, 0)
	
	// Encrypt with IV2
	iv2, _ := hex.DecodeString("11111111111111111111111111111111")
	engine2 := engines.NewSM4Engine()
	ctr2 := NewCTRBlockCipher(engine2)
	ivParam2 := params.NewParametersWithIV(keyParam, iv2)
	ctr2.Init(true, ivParam2)
	
	ciphertext2 := make([]byte, 16)
	ctr2.ProcessBlock(plaintext, 0, ciphertext2, 0)
	
	// Different IVs should produce different ciphertexts
	if hex.EncodeToString(ciphertext1) == hex.EncodeToString(ciphertext2) {
		t.Errorf("Different IVs produced same ciphertext")
	}
}

func TestCTRCounterIncrement(t *testing.T) {
	// Test that counter increments properly across blocks
	key, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	iv, _ := hex.DecodeString("00000000000000000000000000000000")
	
	// Create two identical blocks
	plaintext := make([]byte, 32)
	for i := range plaintext {
		plaintext[i] = 0xAA
	}
	
	// Encrypt
	engine := engines.NewSM4Engine()
	ctr := NewCTRBlockCipher(engine)
	keyParam := params.NewKeyParameter(key)
	ivParam := params.NewParametersWithIV(keyParam, iv)
	ctr.Init(true, ivParam)
	
	ciphertext := make([]byte, 32)
	ctr.ProcessBlock(plaintext, 0, ciphertext, 0)
	ctr.ProcessBlock(plaintext, 16, ciphertext, 16)
	
	// In CTR mode, identical plaintext blocks should produce different ciphertexts
	// because the counter increments
	if hex.EncodeToString(ciphertext[:16]) == hex.EncodeToString(ciphertext[16:]) {
		t.Errorf("Counter increment failed: identical plaintext blocks produced identical ciphertext")
	}
}

func TestCTRReset(t *testing.T) {
	key, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	iv, _ := hex.DecodeString("00112233445566778899aabbccddeeff")
	plaintext, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	
	engine := engines.NewSM4Engine()
	ctr := NewCTRBlockCipher(engine)
	keyParam := params.NewKeyParameter(key)
	ivParam := params.NewParametersWithIV(keyParam, iv)
	ctr.Init(true, ivParam)
	
	// Encrypt once
	ciphertext1 := make([]byte, 16)
	ctr.ProcessBlock(plaintext, 0, ciphertext1, 0)
	
	// Reset and encrypt again
	ctr.Reset()
	ciphertext2 := make([]byte, 16)
	ctr.ProcessBlock(plaintext, 0, ciphertext2, 0)
	
	// Should produce same ciphertext
	if hex.EncodeToString(ciphertext1) != hex.EncodeToString(ciphertext2) {
		t.Errorf("Reset failed: different ciphertexts produced")
	}
}

func TestCTRSymmetry(t *testing.T) {
	// CTR mode is symmetric: encryption and decryption are the same operation
	key, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	iv, _ := hex.DecodeString("00112233445566778899aabbccddeeff")
	plaintext, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	
	// "Encrypt"
	engine1 := engines.NewSM4Engine()
	ctr1 := NewCTRBlockCipher(engine1)
	keyParam := params.NewKeyParameter(key)
	ivParam := params.NewParametersWithIV(keyParam, iv)
	ctr1.Init(true, ivParam)
	
	ciphertext := make([]byte, 16)
	ctr1.ProcessBlock(plaintext, 0, ciphertext, 0)
	
	// "Decrypt" (same operation)
	engine2 := engines.NewSM4Engine()
	ctr2 := NewCTRBlockCipher(engine2)
	ctr2.Init(true, ivParam) // Note: using encryption mode for decryption
	
	decrypted := make([]byte, 16)
	ctr2.ProcessBlock(ciphertext, 0, decrypted, 0)
	
	if hex.EncodeToString(plaintext) != hex.EncodeToString(decrypted) {
		t.Errorf("CTR symmetry test failed")
	}
}

// Benchmark tests
func BenchmarkCTREncrypt(b *testing.B) {
	key, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	iv, _ := hex.DecodeString("00112233445566778899aabbccddeeff")
	plaintext, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	output := make([]byte, 16)
	
	engine := engines.NewSM4Engine()
	ctr := NewCTRBlockCipher(engine)
	keyParam := params.NewKeyParameter(key)
	ivParam := params.NewParametersWithIV(keyParam, iv)
	ctr.Init(true, ivParam)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctr.ProcessBlock(plaintext, 0, output, 0)
	}
}
