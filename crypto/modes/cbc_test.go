package modes

import (
	"encoding/hex"
	"testing"
	
	"github.com/lihongjie0209/sm-go-bc/crypto/engines"
	"github.com/lihongjie0209/sm-go-bc/crypto/paddings"
	"github.com/lihongjie0209/sm-go-bc/crypto/params"
)

func TestCBCGetAlgorithmName(t *testing.T) {
	engine := engines.NewSM4Engine()
	cbc := NewCBCBlockCipher(engine)
	
	expectedName := "SM4/CBC"
	if cbc.GetAlgorithmName() != expectedName {
		t.Errorf("Expected algorithm name '%s', got '%s'", expectedName, cbc.GetAlgorithmName())
	}
}

func TestCBCGetBlockSize(t *testing.T) {
	engine := engines.NewSM4Engine()
	cbc := NewCBCBlockCipher(engine)
	
	if cbc.GetBlockSize() != 16 {
		t.Errorf("Expected block size 16, got %d", cbc.GetBlockSize())
	}
}

func TestCBCEncryptDecryptSingleBlock(t *testing.T) {
	key, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	iv, _ := hex.DecodeString("00000000000000000000000000000000")
	plaintext, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	
	// Encrypt
	engine := engines.NewSM4Engine()
	cbc := NewCBCBlockCipher(engine)
	keyParam := params.NewKeyParameter(key)
	ivParam := params.NewParametersWithIV(keyParam, iv)
	cbc.Init(true, ivParam)
	
	ciphertext := make([]byte, 16)
	cbc.ProcessBlock(plaintext, 0, ciphertext, 0)
	
	// Decrypt
	engine2 := engines.NewSM4Engine()
	cbc2 := NewCBCBlockCipher(engine2)
	cbc2.Init(false, ivParam)
	
	decrypted := make([]byte, 16)
	cbc2.ProcessBlock(ciphertext, 0, decrypted, 0)
	
	if hex.EncodeToString(plaintext) != hex.EncodeToString(decrypted) {
		t.Errorf("Decryption failed\nExpected: %s\nGot:      %s",
			hex.EncodeToString(plaintext), hex.EncodeToString(decrypted))
	}
}

func TestCBCMultipleBlocks(t *testing.T) {
	key, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	iv, _ := hex.DecodeString("00112233445566778899aabbccddeeff")
	
	// Create 3 blocks of plaintext
	plaintext := make([]byte, 48)
	for i := range plaintext {
		plaintext[i] = byte(i)
	}
	
	// Encrypt
	engine := engines.NewSM4Engine()
	cbc := NewCBCBlockCipher(engine)
	keyParam := params.NewKeyParameter(key)
	ivParam := params.NewParametersWithIV(keyParam, iv)
	cbc.Init(true, ivParam)
	
	ciphertext := make([]byte, 48)
	for i := 0; i < 3; i++ {
		cbc.ProcessBlock(plaintext, i*16, ciphertext, i*16)
	}
	
	// Decrypt
	engine2 := engines.NewSM4Engine()
	cbc2 := NewCBCBlockCipher(engine2)
	cbc2.Init(false, ivParam)
	
	decrypted := make([]byte, 48)
	for i := 0; i < 3; i++ {
		cbc2.ProcessBlock(ciphertext, i*16, decrypted, i*16)
	}
	
	if hex.EncodeToString(plaintext) != hex.EncodeToString(decrypted) {
		t.Errorf("Multi-block decryption failed")
	}
}

func TestCBCWithPadding(t *testing.T) {
	key, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	iv, _ := hex.DecodeString("00112233445566778899aabbccddeeff")
	plaintext := []byte("Hello, SM4 with CBC and PKCS7 padding!")
	
	// Encrypt
	engine := engines.NewSM4Engine()
	cbc := NewCBCBlockCipher(engine)
	padding := paddings.NewPKCS7Padding()
	cipher := NewPaddedBufferedBlockCipher(cbc, padding)
	
	keyParam := params.NewKeyParameter(key)
	ivParam := params.NewParametersWithIV(keyParam, iv)
	cipher.Init(true, ivParam)
	
	outSize := cipher.GetOutputSize(len(plaintext))
	ciphertext := make([]byte, outSize)
	
	outLen, _ := cipher.ProcessBytes(plaintext, 0, len(plaintext), ciphertext, 0)
	outLen2, _ := cipher.DoFinal(ciphertext, outLen)
	totalOut := outLen + outLen2
	ciphertext = ciphertext[:totalOut]
	
	// Decrypt
	engine2 := engines.NewSM4Engine()
	cbc2 := NewCBCBlockCipher(engine2)
	cipher2 := NewPaddedBufferedBlockCipher(cbc2, padding)
	cipher2.Init(false, ivParam)
	
	decrypted := make([]byte, len(ciphertext))
	outLen, _ = cipher2.ProcessBytes(ciphertext, 0, len(ciphertext), decrypted, 0)
	outLen2, _ = cipher2.DoFinal(decrypted, outLen)
	totalOut = outLen + outLen2
	decrypted = decrypted[:totalOut]
	
	if string(plaintext) != string(decrypted) {
		t.Errorf("CBC with padding failed\nExpected: %s\nGot:      %s",
			string(plaintext), string(decrypted))
	}
}

func TestCBCChaining(t *testing.T) {
	// Test that blocks are properly chained
	key, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	iv, _ := hex.DecodeString("00000000000000000000000000000000")
	
	// Create two identical plaintext blocks
	plaintext1 := make([]byte, 16)
	plaintext2 := make([]byte, 16)
	for i := range plaintext1 {
		plaintext1[i] = 0xAA
		plaintext2[i] = 0xAA
	}
	
	// Encrypt both blocks
	engine := engines.NewSM4Engine()
	cbc := NewCBCBlockCipher(engine)
	keyParam := params.NewKeyParameter(key)
	ivParam := params.NewParametersWithIV(keyParam, iv)
	cbc.Init(true, ivParam)
	
	ciphertext1 := make([]byte, 16)
	ciphertext2 := make([]byte, 16)
	
	cbc.ProcessBlock(plaintext1, 0, ciphertext1, 0)
	cbc.ProcessBlock(plaintext2, 0, ciphertext2, 0)
	
	// In CBC mode, identical plaintext blocks should produce different ciphertexts
	// due to chaining
	if hex.EncodeToString(ciphertext1) == hex.EncodeToString(ciphertext2) {
		t.Errorf("CBC chaining failed: identical plaintext blocks produced identical ciphertext")
	}
}

func TestCBCReset(t *testing.T) {
	key, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	iv, _ := hex.DecodeString("00112233445566778899aabbccddeeff")
	plaintext, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	
	engine := engines.NewSM4Engine()
	cbc := NewCBCBlockCipher(engine)
	keyParam := params.NewKeyParameter(key)
	ivParam := params.NewParametersWithIV(keyParam, iv)
	cbc.Init(true, ivParam)
	
	// Encrypt once
	ciphertext1 := make([]byte, 16)
	cbc.ProcessBlock(plaintext, 0, ciphertext1, 0)
	
	// Reset and encrypt again
	cbc.Reset()
	ciphertext2 := make([]byte, 16)
	cbc.ProcessBlock(plaintext, 0, ciphertext2, 0)
	
	// Should produce same ciphertext
	if hex.EncodeToString(ciphertext1) != hex.EncodeToString(ciphertext2) {
		t.Errorf("Reset failed: different ciphertexts produced")
	}
}
