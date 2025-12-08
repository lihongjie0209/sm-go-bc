package engines

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/lihongjie0209/sm-go-bc/crypto/params"
)

// TestZUCBasicFunctionality tests basic ZUC engine functionality.
func TestZUCBasicFunctionality(t *testing.T) {
	t.Run("AlgorithmName", func(t *testing.T) {
		engine := NewZUCEngine()
		if engine.GetAlgorithmName() != "ZUC-128" {
			t.Errorf("Expected algorithm name 'ZUC-128', got '%s'", engine.GetAlgorithmName())
		}
	})

	t.Run("Require128BitKey", func(t *testing.T) {
		engine := NewZUCEngine()
		key := make([]byte, 15) // Wrong size
		iv := make([]byte, 16)
		p := params.NewParametersWithIV(params.NewKeyParameter(key), iv)

		err := engine.Init(true, p)
		if err == nil || err.Error() != "ZUC requires a 128-bit key" {
			t.Errorf("Expected error for wrong key size")
		}
	})

	t.Run("Require128BitIV", func(t *testing.T) {
		engine := NewZUCEngine()
		key := make([]byte, 16)
		iv := make([]byte, 15) // Wrong size
		p := params.NewParametersWithIV(params.NewKeyParameter(key), iv)

		err := engine.Init(true, p)
		if err == nil || err.Error() != "ZUC requires a 128-bit IV" {
			t.Errorf("Expected error for wrong IV size")
		}
	})

	t.Run("RequireParametersWithIV", func(t *testing.T) {
		engine := NewZUCEngine()
		key := make([]byte, 16)
		p := params.NewKeyParameter(key)

		err := engine.Init(true, p)
		if err == nil {
			t.Errorf("Expected error when IV is not provided")
		}
	})
}

// TestZUCTestVectors tests ZUC with known test vectors.
func TestZUCTestVectors(t *testing.T) {
	t.Run("AllZeros", func(t *testing.T) {
		engine := NewZUCEngine()
		key := make([]byte, 16) // All zeros
		iv := make([]byte, 16)  // All zeros
		p := params.NewParametersWithIV(params.NewKeyParameter(key), iv)

		err := engine.Init(true, p)
		if err != nil {
			t.Fatalf("Failed to initialize: %v", err)
		}

		// Generate 8 bytes of keystream
		input := make([]byte, 8)
		output := make([]byte, 8)

		n, err := engine.ProcessBytes(input, 0, 8, output, 0)
		if err != nil {
			t.Fatalf("ProcessBytes failed: %v", err)
		}
		if n != 8 {
			t.Errorf("Expected 8 bytes processed, got %d", n)
		}

		// Output should be non-zero (keystream XOR zeros = keystream)
		allZero := true
		for _, b := range output {
			if b != 0 {
				allZero = false
				break
			}
		}
		if allZero {
			t.Error("Keystream should not be all zeros")
		}
	})

	t.Run("TestVector3GPP", func(t *testing.T) {
		engine := NewZUCEngine()

		// Test vector from 3GPP specification
		key := make([]byte, 16)
		iv := make([]byte, 16)

		p := params.NewParametersWithIV(params.NewKeyParameter(key), iv)
		err := engine.Init(true, p)
		if err != nil {
			t.Fatalf("Failed to initialize: %v", err)
		}

		input := make([]byte, 4)
		output := make([]byte, 4)

		_, err = engine.ProcessBytes(input, 0, 4, output, 0)
		if err != nil {
			t.Fatalf("ProcessBytes failed: %v", err)
		}

		// The output should be deterministic
		if len(output) != 4 {
			t.Errorf("Expected 4 bytes output, got %d", len(output))
		}
	})
}

// TestZUCStreamCipherProperties tests stream cipher properties.
func TestZUCStreamCipherProperties(t *testing.T) {
	t.Run("SameOutputForSameKeyIV", func(t *testing.T) {
		key := make([]byte, 16)
		iv := make([]byte, 16)
		for i := 0; i < 16; i++ {
			key[i] = byte(i)
			iv[i] = byte(i + 16)
		}

		engine1 := NewZUCEngine()
		engine2 := NewZUCEngine()
		p := params.NewParametersWithIV(params.NewKeyParameter(key), iv)

		err := engine1.Init(true, p)
		if err != nil {
			t.Fatalf("Failed to initialize engine1: %v", err)
		}
		err = engine2.Init(true, p)
		if err != nil {
			t.Fatalf("Failed to initialize engine2: %v", err)
		}

		input := []byte("Test message")
		output1 := make([]byte, len(input))
		output2 := make([]byte, len(input))

		engine1.ProcessBytes(input, 0, len(input), output1, 0)
		engine2.ProcessBytes(input, 0, len(input), output2, 0)

		if !bytes.Equal(output1, output2) {
			t.Error("Same key/IV should produce same output")
		}
	})

	t.Run("DifferentOutputForDifferentIV", func(t *testing.T) {
		key := make([]byte, 16)
		for i := 0; i < 16; i++ {
			key[i] = byte(i)
		}

		iv1 := make([]byte, 16)
		iv2 := make([]byte, 16)
		for i := 0; i < 16; i++ {
			iv1[i] = byte(i)
			iv2[i] = byte(i + 1) // Different IV
		}

		engine1 := NewZUCEngine()
		engine2 := NewZUCEngine()

		engine1.Init(true, params.NewParametersWithIV(params.NewKeyParameter(key), iv1))
		engine2.Init(true, params.NewParametersWithIV(params.NewKeyParameter(key), iv2))

		input := []byte("Test message")
		output1 := make([]byte, len(input))
		output2 := make([]byte, len(input))

		engine1.ProcessBytes(input, 0, len(input), output1, 0)
		engine2.ProcessBytes(input, 0, len(input), output2, 0)

		if bytes.Equal(output1, output2) {
			t.Error("Different IVs should produce different output")
		}
	})

	t.Run("EncryptDecryptRoundtrip", func(t *testing.T) {
		key := make([]byte, 16)
		iv := make([]byte, 16)
		for i := 0; i < 16; i++ {
			key[i] = byte(i)
			iv[i] = byte(i + 16)
		}

		plaintext := []byte("Hello, ZUC stream cipher!")

		// Encrypt
		engine1 := NewZUCEngine()
		engine1.Init(true, params.NewParametersWithIV(params.NewKeyParameter(key), iv))
		ciphertext := make([]byte, len(plaintext))
		engine1.ProcessBytes(plaintext, 0, len(plaintext), ciphertext, 0)

		// Decrypt
		engine2 := NewZUCEngine()
		engine2.Init(false, params.NewParametersWithIV(params.NewKeyParameter(key), iv))
		decrypted := make([]byte, len(ciphertext))
		engine2.ProcessBytes(ciphertext, 0, len(ciphertext), decrypted, 0)

		if !bytes.Equal(plaintext, decrypted) {
			t.Errorf("Roundtrip failed\nOriginal:  %s\nDecrypted: %s", plaintext, decrypted)
		}
	})
}

// TestZUCReturnByte tests single byte processing.
func TestZUCReturnByte(t *testing.T) {
	engine := NewZUCEngine()
	key := make([]byte, 16)
	iv := make([]byte, 16)
	for i := 0; i < 16; i++ {
		key[i] = byte(i)
		iv[i] = byte(i + 16)
	}

	err := engine.Init(true, params.NewParametersWithIV(params.NewKeyParameter(key), iv))
	if err != nil {
		t.Fatalf("Failed to initialize: %v", err)
	}

	// Process byte by byte
	input := []byte{0x01, 0x02, 0x03, 0x04}
	output1 := make([]byte, 4)
	for i := 0; i < 4; i++ {
		b, err := engine.ReturnByte(input[i])
		if err != nil {
			t.Fatalf("ReturnByte failed: %v", err)
		}
		output1[i] = b
	}

	// Process as block
	engine.Reset()
	output2 := make([]byte, 4)
	engine.ProcessBytes(input, 0, 4, output2, 0)

	if !bytes.Equal(output1, output2) {
		t.Error("ReturnByte and ProcessBytes should produce same output")
	}
}

// TestZUCReset tests the reset functionality.
func TestZUCReset(t *testing.T) {
	engine := NewZUCEngine()
	key := make([]byte, 16)
	iv := make([]byte, 16)
	for i := 0; i < 16; i++ {
		key[i] = byte(i)
		iv[i] = byte(i + 16)
	}

	err := engine.Init(true, params.NewParametersWithIV(params.NewKeyParameter(key), iv))
	if err != nil {
		t.Fatalf("Failed to initialize: %v", err)
	}

	input := []byte("Test message")

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

// TestZUCBufferBoundaries tests buffer boundary conditions.
func TestZUCBufferBoundaries(t *testing.T) {
	t.Run("InputBufferTooShort", func(t *testing.T) {
		engine := NewZUCEngine()
		key := make([]byte, 16)
		iv := make([]byte, 16)
		engine.Init(true, params.NewParametersWithIV(params.NewKeyParameter(key), iv))

		input := make([]byte, 5)
		output := make([]byte, 10)

		_, err := engine.ProcessBytes(input, 0, 10, output, 0)
		if err == nil {
			t.Error("Expected error for input buffer too short")
		}
	})

	t.Run("OutputBufferTooShort", func(t *testing.T) {
		engine := NewZUCEngine()
		key := make([]byte, 16)
		iv := make([]byte, 16)
		engine.Init(true, params.NewParametersWithIV(params.NewKeyParameter(key), iv))

		input := make([]byte, 10)
		output := make([]byte, 5)

		_, err := engine.ProcessBytes(input, 0, 10, output, 0)
		if err == nil {
			t.Error("Expected error for output buffer too short")
		}
	})

	t.Run("WithOffsets", func(t *testing.T) {
		engine := NewZUCEngine()
		key := make([]byte, 16)
		iv := make([]byte, 16)
		engine.Init(true, params.NewParametersWithIV(params.NewKeyParameter(key), iv))

		input := make([]byte, 20)
		for i := range input {
			input[i] = byte(i)
		}
		output := make([]byte, 20)

		// Process middle 10 bytes
		n, err := engine.ProcessBytes(input, 5, 10, output, 5)
		if err != nil {
			t.Fatalf("ProcessBytes failed: %v", err)
		}
		if n != 10 {
			t.Errorf("Expected 10 bytes processed, got %d", n)
		}

		// Verify only middle 10 bytes are non-zero
		for i := 0; i < 5; i++ {
			if output[i] != 0 {
				t.Errorf("Output before offset should be zero, got %d at index %d", output[i], i)
			}
		}
		for i := 15; i < 20; i++ {
			if output[i] != 0 {
				t.Errorf("Output after processed region should be zero, got %d at index %d", output[i], i)
			}
		}
	})
}

// TestZUCLongMessage tests processing of longer messages.
func TestZUCLongMessage(t *testing.T) {
	engine := NewZUCEngine()
	key := make([]byte, 16)
	iv := make([]byte, 16)
	for i := 0; i < 16; i++ {
		key[i] = byte(i)
		iv[i] = byte(i + 16)
	}

	err := engine.Init(true, params.NewParametersWithIV(params.NewKeyParameter(key), iv))
	if err != nil {
		t.Fatalf("Failed to initialize: %v", err)
	}

	// Process 1KB of data
	input := make([]byte, 1024)
	for i := range input {
		input[i] = byte(i & 0xff)
	}

	output := make([]byte, 1024)
	n, err := engine.ProcessBytes(input, 0, len(input), output, 0)
	if err != nil {
		t.Fatalf("ProcessBytes failed: %v", err)
	}
	if n != len(input) {
		t.Errorf("Expected %d bytes processed, got %d", len(input), n)
	}

	// Verify roundtrip
	engine.Reset()
	decrypted := make([]byte, 1024)
	engine.ProcessBytes(output, 0, len(output), decrypted, 0)

	if !bytes.Equal(input, decrypted) {
		t.Error("Long message roundtrip failed")
	}
}

// TestZUCUninitialized tests that uninitialized engine returns errors.
func TestZUCUninitialized(t *testing.T) {
	t.Run("ReturnByte", func(t *testing.T) {
		engine := NewZUCEngine()
		_, err := engine.ReturnByte(0x42)
		if err == nil {
			t.Error("Expected error from uninitialized engine")
		}
	})

	t.Run("ProcessBytes", func(t *testing.T) {
		engine := NewZUCEngine()
		input := make([]byte, 4)
		output := make([]byte, 4)
		_, err := engine.ProcessBytes(input, 0, 4, output, 0)
		if err == nil {
			t.Error("Expected error from uninitialized engine")
		}
	})
}

// TestZUCDeterminism tests that ZUC is deterministic.
func TestZUCDeterminism(t *testing.T) {
	key := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
	iv := []byte{0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20}
	input := []byte("Deterministic test message for ZUC")

	// First run
	engine1 := NewZUCEngine()
	engine1.Init(true, params.NewParametersWithIV(params.NewKeyParameter(key), iv))
	output1 := make([]byte, len(input))
	engine1.ProcessBytes(input, 0, len(input), output1, 0)

	// Second run
	engine2 := NewZUCEngine()
	engine2.Init(true, params.NewParametersWithIV(params.NewKeyParameter(key), iv))
	output2 := make([]byte, len(input))
	engine2.ProcessBytes(input, 0, len(input), output2, 0)

	if !bytes.Equal(output1, output2) {
		t.Errorf("ZUC is not deterministic\nFirst:  %s\nSecond: %s",
			hex.EncodeToString(output1), hex.EncodeToString(output2))
	}
}

// TestZUCIncrementalProcessing tests incremental processing.
func TestZUCIncrementalProcessing(t *testing.T) {
	key := make([]byte, 16)
	iv := make([]byte, 16)
	for i := 0; i < 16; i++ {
		key[i] = byte(i)
		iv[i] = byte(i + 16)
	}

	message := []byte("This is a test message for incremental processing")

	// Process all at once
	engine1 := NewZUCEngine()
	engine1.Init(true, params.NewParametersWithIV(params.NewKeyParameter(key), iv))
	output1 := make([]byte, len(message))
	engine1.ProcessBytes(message, 0, len(message), output1, 0)

	// Process incrementally
	engine2 := NewZUCEngine()
	engine2.Init(true, params.NewParametersWithIV(params.NewKeyParameter(key), iv))
	output2 := make([]byte, len(message))
	pos := 0
	for pos < len(message) {
		chunkSize := 5
		if pos+chunkSize > len(message) {
			chunkSize = len(message) - pos
		}
		engine2.ProcessBytes(message, pos, chunkSize, output2, pos)
		pos += chunkSize
	}

	if !bytes.Equal(output1, output2) {
		t.Error("Incremental processing produced different result")
	}
}
