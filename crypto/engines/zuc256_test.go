package engines

import (
	"bytes"
	"testing"

	"github.com/lihongjie0209/sm-go-bc/crypto/params"
)

// TestZuc256BasicFunctionality tests basic ZUC-256 engine functionality.
func TestZuc256BasicFunctionality(t *testing.T) {
	t.Run("AlgorithmName", func(t *testing.T) {
		engine := NewZuc256Engine()
		if engine.GetAlgorithmName() != "ZUC-256" {
			t.Errorf("Expected algorithm name 'ZUC-256', got '%s'", engine.GetAlgorithmName())
		}
	})

	t.Run("Require256BitKey", func(t *testing.T) {
		engine := NewZuc256Engine()
		key := make([]byte, 16) // Wrong size (should be 32)
		iv := make([]byte, 23)
		p := params.NewParametersWithIV(params.NewKeyParameter(key), iv)

		err := engine.Init(true, p)
		if err == nil {
			t.Error("Expected error for wrong key size")
		}
	})

	t.Run("Require184BitIV", func(t *testing.T) {
		engine := NewZuc256Engine()
		key := make([]byte, 32)
		iv := make([]byte, 16) // Wrong size (should be 23 or 25)
		p := params.NewParametersWithIV(params.NewKeyParameter(key), iv)

		err := engine.Init(true, p)
		if err == nil {
			t.Error("Expected error for wrong IV size")
		}
	})

	t.Run("RequireParametersWithIV", func(t *testing.T) {
		engine := NewZuc256Engine()
		key := make([]byte, 32)
		p := params.NewKeyParameter(key)

		err := engine.Init(true, p)
		if err == nil {
			t.Error("Expected error when IV is not provided")
		}
	})
}

// TestZuc256StreamCipherProperties tests stream cipher properties.
func TestZuc256StreamCipherProperties(t *testing.T) {
	t.Run("SameOutputForSameKeyIV", func(t *testing.T) {
		key := make([]byte, 32)
		iv := make([]byte, 23)
		for i := 0; i < 32; i++ {
			key[i] = byte(i)
		}
		for i := 0; i < 23; i++ {
			iv[i] = byte(i + 32)
		}

		engine1 := NewZuc256Engine()
		engine2 := NewZuc256Engine()
		p := params.NewParametersWithIV(params.NewKeyParameter(key), iv)

		err := engine1.Init(true, p)
		if err != nil {
			t.Fatalf("Failed to initialize engine1: %v", err)
		}
		err = engine2.Init(true, p)
		if err != nil {
			t.Fatalf("Failed to initialize engine2: %v", err)
		}

		input := []byte("Test message for ZUC-256")
		output1 := make([]byte, len(input))
		output2 := make([]byte, len(input))

		engine1.ProcessBytes(input, 0, len(input), output1, 0)
		engine2.ProcessBytes(input, 0, len(input), output2, 0)

		if !bytes.Equal(output1, output2) {
			t.Error("Same key/IV should produce same output")
		}
	})

	t.Run("DifferentOutputForDifferentKey", func(t *testing.T) {
		key1 := make([]byte, 32)
		key2 := make([]byte, 32)
		iv := make([]byte, 23)

		for i := 0; i < 32; i++ {
			key1[i] = byte(i)
			key2[i] = byte(i + 1) // Different key
		}
		for i := 0; i < 23; i++ {
			iv[i] = byte(i)
		}

		engine1 := NewZuc256Engine()
		engine2 := NewZuc256Engine()

		engine1.Init(true, params.NewParametersWithIV(params.NewKeyParameter(key1), iv))
		engine2.Init(true, params.NewParametersWithIV(params.NewKeyParameter(key2), iv))

		input := []byte("Test message")
		output1 := make([]byte, len(input))
		output2 := make([]byte, len(input))

		engine1.ProcessBytes(input, 0, len(input), output1, 0)
		engine2.ProcessBytes(input, 0, len(input), output2, 0)

		if bytes.Equal(output1, output2) {
			t.Error("Different keys should produce different output")
		}
	})

	t.Run("EncryptDecryptRoundtrip", func(t *testing.T) {
		key := make([]byte, 32)
		iv := make([]byte, 23)
		for i := 0; i < 32; i++ {
			key[i] = byte(i)
		}
		for i := 0; i < 23; i++ {
			iv[i] = byte(i + 32)
		}

		plaintext := []byte("Hello, ZUC-256 stream cipher for 5G!")

		// Encrypt
		engine1 := NewZuc256Engine()
		engine1.Init(true, params.NewParametersWithIV(params.NewKeyParameter(key), iv))
		ciphertext := make([]byte, len(plaintext))
		engine1.ProcessBytes(plaintext, 0, len(plaintext), ciphertext, 0)

		// Decrypt
		engine2 := NewZuc256Engine()
		engine2.Init(false, params.NewParametersWithIV(params.NewKeyParameter(key), iv))
		decrypted := make([]byte, len(ciphertext))
		engine2.ProcessBytes(ciphertext, 0, len(ciphertext), decrypted, 0)

		if !bytes.Equal(plaintext, decrypted) {
			t.Errorf("Roundtrip failed\nOriginal:  %s\nDecrypted: %s", plaintext, decrypted)
		}
	})
}

// TestZuc256Reset tests the reset functionality.
func TestZuc256Reset(t *testing.T) {
	engine := NewZuc256Engine()
	key := make([]byte, 32)
	iv := make([]byte, 23)
	for i := 0; i < 32; i++ {
		key[i] = byte(i)
	}
	for i := 0; i < 23; i++ {
		iv[i] = byte(i + 32)
	}

	err := engine.Init(true, params.NewParametersWithIV(params.NewKeyParameter(key), iv))
	if err != nil {
		t.Fatalf("Failed to initialize: %v", err)
	}

	input := []byte("Test message for reset")

	// First encryption
	output1 := make([]byte, len(input))
	engine.ProcessBytes(input, 0, len(input), output1, 0)

	// Reset and encrypt again
	engine.Reset()
	output2 := make([]byte, len(input))
	engine.ProcessBytes(input, 0, len(input), output2, 0)

	if !bytes.Equal(output1, output2) {
		t.Error("Reset should produce same output for same input")
	}
}

// TestZuc256LongMessage tests processing of longer messages.
func TestZuc256LongMessage(t *testing.T) {
	engine := NewZuc256Engine()
	key := make([]byte, 32)
	iv := make([]byte, 23)
	for i := 0; i < 32; i++ {
		key[i] = byte(i)
	}
	for i := 0; i < 23; i++ {
		iv[i] = byte(i + 32)
	}

	err := engine.Init(true, params.NewParametersWithIV(params.NewKeyParameter(key), iv))
	if err != nil {
		t.Fatalf("Failed to initialize: %v", err)
	}

	// Process 2KB of data
	input := make([]byte, 2048)
	for i := range input {
		input[i] = byte(i & 0xff)
	}

	output := make([]byte, 2048)
	n, err := engine.ProcessBytes(input, 0, len(input), output, 0)
	if err != nil {
		t.Fatalf("ProcessBytes failed: %v", err)
	}
	if n != len(input) {
		t.Errorf("Expected %d bytes processed, got %d", len(input), n)
	}

	// Verify roundtrip
	engine.Reset()
	decrypted := make([]byte, 2048)
	engine.ProcessBytes(output, 0, len(output), decrypted, 0)

	if !bytes.Equal(input, decrypted) {
		t.Error("Long message roundtrip failed")
	}
}

// TestZuc256With25ByteIV tests ZUC-256 with 200-bit (25-byte) IV.
func TestZuc256With25ByteIV(t *testing.T) {
	engine := NewZuc256Engine()
	key := make([]byte, 32)
	iv := make([]byte, 25) // 200-bit IV
	for i := 0; i < 32; i++ {
		key[i] = byte(i)
	}
	for i := 0; i < 25; i++ {
		iv[i] = byte(i + 32)
	}

	err := engine.Init(true, params.NewParametersWithIV(params.NewKeyParameter(key), iv))
	if err != nil {
		t.Fatalf("Failed to initialize with 25-byte IV: %v", err)
	}

	plaintext := []byte("Testing ZUC-256 with 200-bit IV")
	ciphertext := make([]byte, len(plaintext))
	engine.ProcessBytes(plaintext, 0, len(plaintext), ciphertext, 0)

	// Decrypt
	engine.Reset()
	decrypted := make([]byte, len(ciphertext))
	engine.ProcessBytes(ciphertext, 0, len(ciphertext), decrypted, 0)

	if !bytes.Equal(plaintext, decrypted) {
		t.Error("Roundtrip with 25-byte IV failed")
	}
}

// TestZuc256Determinism tests that ZUC-256 is deterministic.
func TestZuc256Determinism(t *testing.T) {
	key := make([]byte, 32)
	iv := make([]byte, 23)
	for i := 0; i < 32; i++ {
		key[i] = byte(i * 3)
	}
	for i := 0; i < 23; i++ {
		iv[i] = byte(i * 5)
	}
	input := []byte("Deterministic test message for ZUC-256")

	// First run
	engine1 := NewZuc256Engine()
	engine1.Init(true, params.NewParametersWithIV(params.NewKeyParameter(key), iv))
	output1 := make([]byte, len(input))
	engine1.ProcessBytes(input, 0, len(input), output1, 0)

	// Second run
	engine2 := NewZuc256Engine()
	engine2.Init(true, params.NewParametersWithIV(params.NewKeyParameter(key), iv))
	output2 := make([]byte, len(input))
	engine2.ProcessBytes(input, 0, len(input), output2, 0)

	if !bytes.Equal(output1, output2) {
		t.Error("ZUC-256 is not deterministic")
	}
}
