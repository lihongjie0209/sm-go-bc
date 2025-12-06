package engines

import (
	"encoding/hex"
	"testing"
	
	"github.com/lihongjie0209/sm-go-bc/crypto/params"
)

// Test vectors from sm-py-bc and standard SM4 test vectors

func TestSM4AlgorithmName(t *testing.T) {
	engine := NewSM4Engine()
	if engine.GetAlgorithmName() != "SM4" {
		t.Errorf("Expected algorithm name 'SM4', got '%s'", engine.GetAlgorithmName())
	}
}

func TestSM4BlockSize(t *testing.T) {
	engine := NewSM4Engine()
	if engine.GetBlockSize() != 16 {
		t.Errorf("Expected block size 16, got %d", engine.GetBlockSize())
	}
}

func TestSM4UninitializedError(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("Expected panic when processing without initialization")
		}
	}()
	
	engine := NewSM4Engine()
	input := make([]byte, 16)
	output := make([]byte, 16)
	engine.ProcessBlock(input, 0, output, 0)
}

func TestSM4WrongKeyLength(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("Expected panic for wrong key length")
		}
	}()
	
	engine := NewSM4Engine()
	wrongKey := make([]byte, 15) // Wrong length
	engine.Init(true, params.NewKeyParameter(wrongKey))
}

func TestSM4EncryptSingleBlockVector1(t *testing.T) {
	// Standard test vector from SM4 specification
	key, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	plaintext, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	expected, _ := hex.DecodeString("681edf34d206965e86b3e94f536e4246")
	
	engine := NewSM4Engine()
	engine.Init(true, params.NewKeyParameter(key))
	
	output := make([]byte, 16)
	engine.ProcessBlock(plaintext, 0, output, 0)
	
	if hex.EncodeToString(output) != hex.EncodeToString(expected) {
		t.Errorf("Encryption mismatch\nExpected: %s\nGot:      %s",
			hex.EncodeToString(expected), hex.EncodeToString(output))
	}
}

func TestSM4DecryptSingleBlockVector1(t *testing.T) {
	// Standard test vector from SM4 specification
	key, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	ciphertext, _ := hex.DecodeString("681edf34d206965e86b3e94f536e4246")
	expected, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	
	engine := NewSM4Engine()
	engine.Init(false, params.NewKeyParameter(key))
	
	output := make([]byte, 16)
	engine.ProcessBlock(ciphertext, 0, output, 0)
	
	if hex.EncodeToString(output) != hex.EncodeToString(expected) {
		t.Errorf("Decryption mismatch\nExpected: %s\nGot:      %s",
			hex.EncodeToString(expected), hex.EncodeToString(output))
	}
}

func TestSM4EncryptDecryptRoundtrip(t *testing.T) {
	key, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	plaintext, _ := hex.DecodeString("fedcba98765432100123456789abcdef")
	
	// Encrypt
	engine := NewSM4Engine()
	engine.Init(true, params.NewKeyParameter(key))
	ciphertext := make([]byte, 16)
	engine.ProcessBlock(plaintext, 0, ciphertext, 0)
	
	// Decrypt
	engine2 := NewSM4Engine()
	engine2.Init(false, params.NewKeyParameter(key))
	decrypted := make([]byte, 16)
	engine2.ProcessBlock(ciphertext, 0, decrypted, 0)
	
	if hex.EncodeToString(plaintext) != hex.EncodeToString(decrypted) {
		t.Errorf("Roundtrip failed\nOriginal:  %s\nDecrypted: %s",
			hex.EncodeToString(plaintext), hex.EncodeToString(decrypted))
	}
}

func TestSM4MultipleBlocks(t *testing.T) {
	key, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	
	// Test processing multiple different blocks
	testCases := []struct {
		plaintext string
	}{
		{"00000000000000000000000000000000"},
		{"ffffffffffffffffffffffffffffffff"},
		{"0123456789abcdeffedcba9876543210"},
		{"a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"},
	}
	
	engine := NewSM4Engine()
	engine.Init(true, params.NewKeyParameter(key))
	
	for _, tc := range testCases {
		plaintext, _ := hex.DecodeString(tc.plaintext)
		ciphertext := make([]byte, 16)
		engine.ProcessBlock(plaintext, 0, ciphertext, 0)
		
		// Decrypt to verify
		engine2 := NewSM4Engine()
		engine2.Init(false, params.NewKeyParameter(key))
		decrypted := make([]byte, 16)
		engine2.ProcessBlock(ciphertext, 0, decrypted, 0)
		
		if hex.EncodeToString(plaintext) != hex.EncodeToString(decrypted) {
			t.Errorf("Multiple block test failed for %s", tc.plaintext)
		}
	}
}

func TestSM4DifferentKeys(t *testing.T) {
	// Test that different keys produce different outputs
	plaintext, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	
	keys := []string{
		"0123456789abcdeffedcba9876543210",
		"fedcba98765432100123456789abcdef",
		"00112233445566778899aabbccddeeff",
	}
	
	outputs := make(map[string]bool)
	
	for _, keyHex := range keys {
		key, _ := hex.DecodeString(keyHex)
		engine := NewSM4Engine()
		engine.Init(true, params.NewKeyParameter(key))
		
		output := make([]byte, 16)
		engine.ProcessBlock(plaintext, 0, output, 0)
		
		outputHex := hex.EncodeToString(output)
		if outputs[outputHex] {
			t.Errorf("Different keys produced same output: %s", outputHex)
		}
		outputs[outputHex] = true
	}
}

func TestSM4OffsetProcessing(t *testing.T) {
	// Test processing with non-zero offsets
	key, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	plaintext, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	
	engine := NewSM4Engine()
	engine.Init(true, params.NewKeyParameter(key))
	
	// Create buffers with extra space
	input := make([]byte, 32)
	copy(input[8:], plaintext)
	
	output := make([]byte, 32)
	engine.ProcessBlock(input, 8, output, 8)
	
	// Verify encryption is correct
	expected, _ := hex.DecodeString("681edf34d206965e86b3e94f536e4246")
	result := output[8:24]
	
	if hex.EncodeToString(result) != hex.EncodeToString(expected) {
		t.Errorf("Offset processing failed\nExpected: %s\nGot:      %s",
			hex.EncodeToString(expected), hex.EncodeToString(result))
	}
}

// Benchmark tests
func BenchmarkSM4Encrypt(b *testing.B) {
	key, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	plaintext, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	output := make([]byte, 16)
	
	engine := NewSM4Engine()
	engine.Init(true, params.NewKeyParameter(key))
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.ProcessBlock(plaintext, 0, output, 0)
	}
}

func BenchmarkSM4Decrypt(b *testing.B) {
	key, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	ciphertext, _ := hex.DecodeString("681edf34d206965e86b3e94f536e4246")
	output := make([]byte, 16)
	
	engine := NewSM4Engine()
	engine.Init(false, params.NewKeyParameter(key))
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.ProcessBlock(ciphertext, 0, output, 0)
	}
}

func BenchmarkSM4KeyExpansion(b *testing.B) {
	key, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine := NewSM4Engine()
		engine.Init(true, params.NewKeyParameter(key))
	}
}
