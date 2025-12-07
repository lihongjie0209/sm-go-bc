package modes

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/lihongjie0209/sm-go-bc/crypto/engines"
	"github.com/lihongjie0209/sm-go-bc/crypto/params"
)

// Test basic GCM encryption and decryption
func TestGCMBlockCipher_Basic(t *testing.T) {
	key, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	nonce, _ := hex.DecodeString("000000000000000000000000") // 12-byte nonce
	plaintext := []byte("Hello, GCM mode!")

	// Create cipher
	engine := engines.NewSM4Engine()
	gcm := NewGCMBlockCipher(engine)

	// Encrypt
	keyParam := params.NewKeyParameter(key)
	aeadParam := params.NewAEADParameters(keyParam, 128, nonce, nil)
	gcm.Init(true, aeadParam)

	outputSize := gcm.GetOutputSize(len(plaintext))
	ciphertext := make([]byte, outputSize)
	
	processed, err := gcm.ProcessBytes(plaintext, 0, len(plaintext), ciphertext, 0)
	if err != nil {
		t.Fatalf("ProcessBytes failed: %v", err)
	}

	finalLen, err := gcm.DoFinal(ciphertext, processed)
	if err != nil {
		t.Fatalf("DoFinal failed: %v", err)
	}

	totalLen := processed + finalLen
	ciphertext = ciphertext[:totalLen]

	t.Logf("Plaintext:  %s", plaintext)
	t.Logf("Ciphertext: %x", ciphertext)
	t.Logf("MAC: %x", gcm.GetMac())

	// Decrypt
	gcm2 := NewGCMBlockCipher(engines.NewSM4Engine())
	gcm2.Init(false, aeadParam)

	decrypted := make([]byte, len(plaintext))
	processed2, err := gcm2.ProcessBytes(ciphertext, 0, len(ciphertext), decrypted, 0)
	if err != nil {
		t.Fatalf("Decrypt ProcessBytes failed: %v", err)
	}

	finalLen2, err := gcm2.DoFinal(decrypted, processed2)
	if err != nil {
		t.Fatalf("Decrypt DoFinal failed: %v", err)
	}

	decrypted = decrypted[:finalLen2]

	// Verify
	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decryption failed\nExpected: %s\nGot: %s", plaintext, decrypted)
	}
}

// Test GCM with AAD (Additional Authenticated Data)
func TestGCMBlockCipher_WithAAD(t *testing.T) {
	key, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	nonce, _ := hex.DecodeString("000000000000000000000000")
	aad := []byte("Additional data")
	plaintext := []byte("Secret message")

	// Encrypt
	engine := engines.NewSM4Engine()
	gcm := NewGCMBlockCipher(engine)

	keyParam := params.NewKeyParameter(key)
	aeadParam := params.NewAEADParameters(keyParam, 128, nonce, aad)
	gcm.Init(true, aeadParam)

	outputSize := gcm.GetOutputSize(len(plaintext))
	ciphertext := make([]byte, outputSize)

	processed, _ := gcm.ProcessBytes(plaintext, 0, len(plaintext), ciphertext, 0)
	finalLen, _ := gcm.DoFinal(ciphertext, processed)
	ciphertext = ciphertext[:processed+finalLen]

	t.Logf("Ciphertext with AAD: %x", ciphertext)

	// Decrypt with correct AAD
	gcm2 := NewGCMBlockCipher(engines.NewSM4Engine())
	gcm2.Init(false, aeadParam)

	decrypted := make([]byte, len(plaintext))
	processed2, _ := gcm2.ProcessBytes(ciphertext, 0, len(ciphertext), decrypted, 0)
	finalLen2, err := gcm2.DoFinal(decrypted, processed2)
	
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	decrypted = decrypted[:finalLen2]

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decryption with AAD failed")
	}

	// Try to decrypt with wrong AAD (should fail)
	wrongAAD := []byte("Wrong additional data")
	aeadParamWrong := params.NewAEADParameters(keyParam, 128, nonce, wrongAAD)
	
	gcm3 := NewGCMBlockCipher(engines.NewSM4Engine())
	gcm3.Init(false, aeadParamWrong)

	decrypted2 := make([]byte, len(plaintext))
	processed3, _ := gcm3.ProcessBytes(ciphertext, 0, len(ciphertext), decrypted2, 0)
	_, err = gcm3.DoFinal(decrypted2, processed3)

	if err == nil {
		t.Error("Expected MAC verification to fail with wrong AAD, but it succeeded")
	}
}

// Test GCM with empty plaintext
func TestGCMBlockCipher_EmptyPlaintext(t *testing.T) {
	key, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	nonce, _ := hex.DecodeString("000000000000000000000000")
	plaintext := []byte{}

	engine := engines.NewSM4Engine()
	gcm := NewGCMBlockCipher(engine)

	keyParam := params.NewKeyParameter(key)
	aeadParam := params.NewAEADParameters(keyParam, 128, nonce, nil)
	gcm.Init(true, aeadParam)

	outputSize := gcm.GetOutputSize(len(plaintext))
	ciphertext := make([]byte, outputSize)

	processed, _ := gcm.ProcessBytes(plaintext, 0, len(plaintext), ciphertext, 0)
	finalLen, _ := gcm.DoFinal(ciphertext, processed)
	ciphertext = ciphertext[:processed+finalLen]

	// Should only contain MAC (16 bytes)
	if len(ciphertext) != 16 {
		t.Errorf("Expected 16-byte MAC only, got %d bytes", len(ciphertext))
	}

	t.Logf("MAC for empty plaintext: %x", ciphertext)

	// Decrypt
	gcm2 := NewGCMBlockCipher(engines.NewSM4Engine())
	gcm2.Init(false, aeadParam)

	decrypted := make([]byte, len(plaintext))
	processed2, _ := gcm2.ProcessBytes(ciphertext, 0, len(ciphertext), decrypted, 0)
	finalLen2, err := gcm2.DoFinal(decrypted, processed2)

	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if finalLen2 != 0 {
		t.Errorf("Expected 0-byte plaintext, got %d bytes", finalLen2)
	}
}

// Test GCM with different MAC sizes
func TestGCMBlockCipher_DifferentMacSizes(t *testing.T) {
	key, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	nonce, _ := hex.DecodeString("000000000000000000000000")
	plaintext := []byte("Test")

	macSizes := []int{32, 64, 96, 104, 112, 120, 128} // bits

	for _, macSize := range macSizes {
		t.Run(hex.EncodeToString([]byte{byte(macSize)}), func(t *testing.T) {
			engine := engines.NewSM4Engine()
			gcm := NewGCMBlockCipher(engine)

			keyParam := params.NewKeyParameter(key)
			aeadParam := params.NewAEADParameters(keyParam, macSize, nonce, nil)
			gcm.Init(true, aeadParam)

			outputSize := gcm.GetOutputSize(len(plaintext))
			ciphertext := make([]byte, outputSize)

			processed, _ := gcm.ProcessBytes(plaintext, 0, len(plaintext), ciphertext, 0)
			finalLen, _ := gcm.DoFinal(ciphertext, processed)
			ciphertext = ciphertext[:processed+finalLen]

			expectedLen := len(plaintext) + macSize/8
			if len(ciphertext) != expectedLen {
				t.Errorf("Expected %d bytes (plaintext + %d-bit MAC), got %d bytes",
					expectedLen, macSize, len(ciphertext))
			}

			// Decrypt
			gcm2 := NewGCMBlockCipher(engines.NewSM4Engine())
			gcm2.Init(false, aeadParam)

			decrypted := make([]byte, len(plaintext))
			processed2, _ := gcm2.ProcessBytes(ciphertext, 0, len(ciphertext), decrypted, 0)
			finalLen2, err := gcm2.DoFinal(decrypted, processed2)

			if err != nil {
				t.Fatalf("Decryption with %d-bit MAC failed: %v", macSize, err)
			}

			decrypted = decrypted[:finalLen2]

			if !bytes.Equal(plaintext, decrypted) {
				t.Errorf("Decryption mismatch with %d-bit MAC", macSize)
			}
		})
	}
}

// Test GCM with tampering detection
func TestGCMBlockCipher_TamperingDetection(t *testing.T) {
	key, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	nonce, _ := hex.DecodeString("000000000000000000000000")
	plaintext := []byte("Important message")

	// Encrypt
	engine := engines.NewSM4Engine()
	gcm := NewGCMBlockCipher(engine)

	keyParam := params.NewKeyParameter(key)
	aeadParam := params.NewAEADParameters(keyParam, 128, nonce, nil)
	gcm.Init(true, aeadParam)

	outputSize := gcm.GetOutputSize(len(plaintext))
	ciphertext := make([]byte, outputSize)

	processed, _ := gcm.ProcessBytes(plaintext, 0, len(plaintext), ciphertext, 0)
	finalLen, _ := gcm.DoFinal(ciphertext, processed)
	ciphertext = ciphertext[:processed+finalLen]

	// Tamper with ciphertext
	tamperedCiphertext := make([]byte, len(ciphertext))
	copy(tamperedCiphertext, ciphertext)
	tamperedCiphertext[0] ^= 0x01 // Flip one bit

	// Try to decrypt (should fail)
	gcm2 := NewGCMBlockCipher(engines.NewSM4Engine())
	gcm2.Init(false, aeadParam)

	decrypted := make([]byte, len(plaintext))
	processed2, _ := gcm2.ProcessBytes(tamperedCiphertext, 0, len(tamperedCiphertext), decrypted, 0)
	_, err := gcm2.DoFinal(decrypted, processed2)

	if err == nil {
		t.Error("Expected MAC verification to fail with tampered ciphertext")
	}

	t.Logf("Tampering correctly detected: %v", err)
}

// Test GCM Reset functionality
func TestGCMBlockCipher_Reset(t *testing.T) {
	key, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	nonce, _ := hex.DecodeString("000000000000000000000000")
	plaintext := []byte("Test message")

	engine := engines.NewSM4Engine()
	gcm := NewGCMBlockCipher(engine)

	keyParam := params.NewKeyParameter(key)
	aeadParam := params.NewAEADParameters(keyParam, 128, nonce, nil)
	gcm.Init(true, aeadParam)

	// First encryption
	outputSize := gcm.GetOutputSize(len(plaintext))
	ciphertext1 := make([]byte, outputSize)
	processed1, _ := gcm.ProcessBytes(plaintext, 0, len(plaintext), ciphertext1, 0)
	finalLen1, _ := gcm.DoFinal(ciphertext1, processed1)
	ciphertext1 = ciphertext1[:processed1+finalLen1]

	// Reset and encrypt again
	gcm.Reset()
	ciphertext2 := make([]byte, outputSize)
	processed2, _ := gcm.ProcessBytes(plaintext, 0, len(plaintext), ciphertext2, 0)
	finalLen2, _ := gcm.DoFinal(ciphertext2, processed2)
	ciphertext2 = ciphertext2[:processed2+finalLen2]

	// Results should be identical
	if !bytes.Equal(ciphertext1, ciphertext2) {
		t.Errorf("Reset test failed: ciphertexts differ\nFirst:  %x\nSecond: %x",
			ciphertext1, ciphertext2)
	}
}

// Benchmark GCM encryption
func BenchmarkGCMBlockCipher_Encrypt(b *testing.B) {
	key, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	nonce, _ := hex.DecodeString("000000000000000000000000")
	plaintext := make([]byte, 1024)

	engine := engines.NewSM4Engine()
	gcm := NewGCMBlockCipher(engine)

	keyParam := params.NewKeyParameter(key)
	aeadParam := params.NewAEADParameters(keyParam, 128, nonce, nil)

	outputSize := gcm.GetOutputSize(len(plaintext))
	ciphertext := make([]byte, outputSize)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		gcm.Init(true, aeadParam)
		processed, _ := gcm.ProcessBytes(plaintext, 0, len(plaintext), ciphertext, 0)
		gcm.DoFinal(ciphertext, processed)
	}
}

// Benchmark GCM decryption
func BenchmarkGCMBlockCipher_Decrypt(b *testing.B) {
	key, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	nonce, _ := hex.DecodeString("000000000000000000000000")
	plaintext := make([]byte, 1024)

	// Create ciphertext
	engine := engines.NewSM4Engine()
	gcm := NewGCMBlockCipher(engine)

	keyParam := params.NewKeyParameter(key)
	aeadParam := params.NewAEADParameters(keyParam, 128, nonce, nil)
	gcm.Init(true, aeadParam)

	outputSize := gcm.GetOutputSize(len(plaintext))
	ciphertext := make([]byte, outputSize)
	processed, _ := gcm.ProcessBytes(plaintext, 0, len(plaintext), ciphertext, 0)
	finalLen, _ := gcm.DoFinal(ciphertext, processed)
	ciphertext = ciphertext[:processed+finalLen]

	decrypted := make([]byte, len(plaintext))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		gcm2 := NewGCMBlockCipher(engines.NewSM4Engine())
		gcm2.Init(false, aeadParam)
		processed2, _ := gcm2.ProcessBytes(ciphertext, 0, len(ciphertext), decrypted, 0)
		gcm2.DoFinal(decrypted, processed2)
	}
}
