package modes

import (
	"encoding/hex"
	"testing"
	
	"github.com/lihongjie0209/sm-go-bc/crypto/engines"
	"github.com/lihongjie0209/sm-go-bc/crypto/params"
)

func TestOFBGetAlgorithmName(t *testing.T) {
	engine := engines.NewSM4Engine()
	ofb := NewOFBBlockCipher(engine, 128) // 128-bit = 16-byte blocks
	
	expectedName := "SM4/OFB128"
	if ofb.GetAlgorithmName() != expectedName {
		t.Errorf("Expected algorithm name '%s', got '%s'", expectedName, ofb.GetAlgorithmName())
	}
}

func TestOFBGetBlockSize(t *testing.T) {
	engine := engines.NewSM4Engine()
	ofb := NewOFBBlockCipher(engine, 128)
	
	if ofb.GetBlockSize() != 16 {
		t.Errorf("Expected block size 16, got %d", ofb.GetBlockSize())
	}
}

func TestOFBEncryptDecryptSingleBlock(t *testing.T) {
	key, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	iv, _ := hex.DecodeString("00112233445566778899aabbccddeeff")
	plaintext, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	
	// Encrypt
	engine := engines.NewSM4Engine()
	ofb := NewOFBBlockCipher(engine, 128)
	keyParam := params.NewKeyParameter(key)
	ivParam := params.NewParametersWithIV(keyParam, iv)
	ofb.Init(true, ivParam)
	
	ciphertext := make([]byte, 16)
	ofb.ProcessBlock(plaintext, 0, ciphertext, 0)
	
	// Decrypt (OFB uses same operation for both)
	engine2 := engines.NewSM4Engine()
	ofb2 := NewOFBBlockCipher(engine2, 128)
	ofb2.Init(false, ivParam) // forEncryption doesn't matter for OFB
	
	decrypted := make([]byte, 16)
	ofb2.ProcessBlock(ciphertext, 0, decrypted, 0)
	
	if hex.EncodeToString(plaintext) != hex.EncodeToString(decrypted) {
		t.Errorf("Decryption failed\nExpected: %s\nGot:      %s",
			hex.EncodeToString(plaintext), hex.EncodeToString(decrypted))
	}
}

func TestOFBMultipleBlocks(t *testing.T) {
	key, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	iv, _ := hex.DecodeString("00112233445566778899aabbccddeeff")
	
	// Create 3 blocks of plaintext
	plaintext := make([]byte, 48)
	for i := range plaintext {
		plaintext[i] = byte(i)
	}
	
	// Encrypt
	engine := engines.NewSM4Engine()
	ofb := NewOFBBlockCipher(engine, 128)
	keyParam := params.NewKeyParameter(key)
	ivParam := params.NewParametersWithIV(keyParam, iv)
	ofb.Init(true, ivParam)
	
	ciphertext := make([]byte, 48)
	for i := 0; i < 3; i++ {
		ofb.ProcessBlock(plaintext, i*16, ciphertext, i*16)
	}
	
	// Decrypt
	engine2 := engines.NewSM4Engine()
	ofb2 := NewOFBBlockCipher(engine2, 128)
	ofb2.Init(false, ivParam)
	
	decrypted := make([]byte, 48)
	for i := 0; i < 3; i++ {
		ofb2.ProcessBlock(ciphertext, i*16, decrypted, i*16)
	}
	
	if hex.EncodeToString(plaintext) != hex.EncodeToString(decrypted) {
		t.Errorf("Multi-block decryption failed")
	}
}

func TestOFBStreamMode(t *testing.T) {
	// OFB can process byte-by-byte (stream mode)
	key, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	iv, _ := hex.DecodeString("00112233445566778899aabbccddeeff")
	plaintext := []byte("Hello, OFB mode!")
	
	// Encrypt
	engine := engines.NewSM4Engine()
	ofb := NewOFBBlockCipher(engine, 128)
	keyParam := params.NewKeyParameter(key)
	ivParam := params.NewParametersWithIV(keyParam, iv)
	ofb.Init(true, ivParam)
	
	ciphertext := make([]byte, len(plaintext))
	ofb.ProcessBlock(plaintext, 0, ciphertext, 0)
	
	// Decrypt
	engine2 := engines.NewSM4Engine()
	ofb2 := NewOFBBlockCipher(engine2, 128)
	ofb2.Init(false, ivParam)
	
	decrypted := make([]byte, len(ciphertext))
	ofb2.ProcessBlock(ciphertext, 0, decrypted, 0)
	
	if string(plaintext) != string(decrypted) {
		t.Errorf("Stream mode failed\nExpected: %s\nGot:      %s",
			string(plaintext), string(decrypted))
	}
}

func TestOFBDifferentIVs(t *testing.T) {
	// Test that different IVs produce different outputs
	key, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	plaintext, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	
	// Encrypt with IV1
	iv1, _ := hex.DecodeString("00000000000000000000000000000000")
	engine1 := engines.NewSM4Engine()
	ofb1 := NewOFBBlockCipher(engine1, 128)
	keyParam := params.NewKeyParameter(key)
	ivParam1 := params.NewParametersWithIV(keyParam, iv1)
	ofb1.Init(true, ivParam1)
	
	ciphertext1 := make([]byte, 16)
	ofb1.ProcessBlock(plaintext, 0, ciphertext1, 0)
	
	// Encrypt with IV2
	iv2, _ := hex.DecodeString("11111111111111111111111111111111")
	engine2 := engines.NewSM4Engine()
	ofb2 := NewOFBBlockCipher(engine2, 128)
	ivParam2 := params.NewParametersWithIV(keyParam, iv2)
	ofb2.Init(true, ivParam2)
	
	ciphertext2 := make([]byte, 16)
	ofb2.ProcessBlock(plaintext, 0, ciphertext2, 0)
	
	// Different IVs should produce different ciphertexts
	if hex.EncodeToString(ciphertext1) == hex.EncodeToString(ciphertext2) {
		t.Errorf("Different IVs produced same ciphertext")
	}
}

func TestOFBReset(t *testing.T) {
	key, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	iv, _ := hex.DecodeString("00112233445566778899aabbccddeeff")
	plaintext, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	
	engine := engines.NewSM4Engine()
	ofb := NewOFBBlockCipher(engine, 128)
	keyParam := params.NewKeyParameter(key)
	ivParam := params.NewParametersWithIV(keyParam, iv)
	ofb.Init(true, ivParam)
	
	// Encrypt once
	ciphertext1 := make([]byte, 16)
	ofb.ProcessBlock(plaintext, 0, ciphertext1, 0)
	
	// Reset and encrypt again
	ofb.Reset()
	ciphertext2 := make([]byte, 16)
	ofb.ProcessBlock(plaintext, 0, ciphertext2, 0)
	
	// Should produce same ciphertext
	if hex.EncodeToString(ciphertext1) != hex.EncodeToString(ciphertext2) {
		t.Errorf("Reset failed: different ciphertexts produced")
	}
}

func TestOFBSymmetry(t *testing.T) {
	// OFB mode is symmetric: encryption and decryption are the same operation
	key, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	iv, _ := hex.DecodeString("00112233445566778899aabbccddeeff")
	plaintext, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	
	// "Encrypt"
	engine1 := engines.NewSM4Engine()
	ofb1 := NewOFBBlockCipher(engine1, 128)
	keyParam := params.NewKeyParameter(key)
	ivParam := params.NewParametersWithIV(keyParam, iv)
	ofb1.Init(true, ivParam)
	
	ciphertext := make([]byte, 16)
	ofb1.ProcessBlock(plaintext, 0, ciphertext, 0)
	
	// "Decrypt" (same operation)
	engine2 := engines.NewSM4Engine()
	ofb2 := NewOFBBlockCipher(engine2, 128)
	ofb2.Init(true, ivParam) // Note: using encryption mode for decryption
	
	decrypted := make([]byte, 16)
	ofb2.ProcessBlock(ciphertext, 0, decrypted, 0)
	
	if hex.EncodeToString(plaintext) != hex.EncodeToString(decrypted) {
		t.Errorf("OFB symmetry test failed")
	}
}

func TestOFBErrorPropagation(t *testing.T) {
	// Test that OFB does not propagate errors
	key, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	iv, _ := hex.DecodeString("00112233445566778899aabbccddeeff")
	plaintext := make([]byte, 48)
	for i := range plaintext {
		plaintext[i] = byte(i)
	}
	
	// Encrypt
	engine := engines.NewSM4Engine()
	ofb := NewOFBBlockCipher(engine, 128)
	keyParam := params.NewKeyParameter(key)
	ivParam := params.NewParametersWithIV(keyParam, iv)
	ofb.Init(true, ivParam)
	
	ciphertext := make([]byte, 48)
	for i := 0; i < 3; i++ {
		ofb.ProcessBlock(plaintext, i*16, ciphertext, i*16)
	}
	
	// Corrupt one byte in the middle block
	ciphertext[20] ^= 0xFF
	
	// Decrypt
	engine2 := engines.NewSM4Engine()
	ofb2 := NewOFBBlockCipher(engine2, 128)
	ofb2.Init(false, ivParam)
	
	decrypted := make([]byte, 48)
	for i := 0; i < 3; i++ {
		ofb2.ProcessBlock(ciphertext, i*16, decrypted, i*16)
	}
	
	// Only the corrupted byte should be wrong
	errorCount := 0
	for i := range plaintext {
		if plaintext[i] != decrypted[i] {
			errorCount++
		}
	}
	
	if errorCount != 1 {
		t.Errorf("Expected 1 error, got %d (OFB should not propagate errors)", errorCount)
	}
	
	// The corrupted byte should be at position 20
	if plaintext[20] == decrypted[20] {
		t.Errorf("Expected error at position 20, but byte was correct")
	}
}

func TestOFBDifferentBlockSizes(t *testing.T) {
	// Test OFB with 64-bit (8-byte) block size
	key, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	iv, _ := hex.DecodeString("00112233445566778899aabbccddeeff")
	plaintext, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	
	engine := engines.NewSM4Engine()
	ofb := NewOFBBlockCipher(engine, 64) // 64-bit blocks
	keyParam := params.NewKeyParameter(key)
	ivParam := params.NewParametersWithIV(keyParam, iv)
	ofb.Init(true, ivParam)
	
	if ofb.GetBlockSize() != 8 {
		t.Errorf("Expected block size 8, got %d", ofb.GetBlockSize())
	}
	
	ciphertext := make([]byte, 16)
	ofb.ProcessBlock(plaintext, 0, ciphertext, 0)
	ofb.ProcessBlock(plaintext, 8, ciphertext, 8)
	
	// Decrypt
	engine2 := engines.NewSM4Engine()
	ofb2 := NewOFBBlockCipher(engine2, 64)
	ofb2.Init(false, ivParam)
	
	decrypted := make([]byte, 16)
	ofb2.ProcessBlock(ciphertext, 0, decrypted, 0)
	ofb2.ProcessBlock(ciphertext, 8, decrypted, 8)
	
	if hex.EncodeToString(plaintext) != hex.EncodeToString(decrypted) {
		t.Errorf("OFB64 failed")
	}
}

// Benchmark tests
func BenchmarkOFBEncrypt(b *testing.B) {
	key, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	iv, _ := hex.DecodeString("00112233445566778899aabbccddeeff")
	plaintext, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	output := make([]byte, 16)
	
	engine := engines.NewSM4Engine()
	ofb := NewOFBBlockCipher(engine, 128)
	keyParam := params.NewKeyParameter(key)
	ivParam := params.NewParametersWithIV(keyParam, iv)
	ofb.Init(true, ivParam)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ofb.ProcessBlock(plaintext, 0, output, 0)
	}
}
