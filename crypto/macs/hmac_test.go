package macs

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/lihongjie0209/sm-go-bc/crypto/digests"
	"github.com/lihongjie0209/sm-go-bc/crypto/params"
)

// Helper function: convert hex string to bytes
func hexToBytes(t *testing.T, hexStr string) []byte {
	bytes, err := hex.DecodeString(hexStr)
	if err != nil {
		t.Fatalf("Failed to decode hex: %v", err)
	}
	return bytes
}

// Helper function: convert bytes to hex string
func bytesToHex(data []byte) string {
	return hex.EncodeToString(data)
}

// Helper function: compute HMAC
func computeHMac(key []byte, message []byte) ([]byte, error) {
	hmac := NewHMac(digests.NewSM3Digest())
	err := hmac.Init(params.NewKeyParameter(key))
	if err != nil {
		return nil, err
	}
	hmac.UpdateArray(message, 0, len(message))
	out := make([]byte, hmac.GetMacSize())
	_, err = hmac.DoFinal(out, 0)
	return out, err
}

// TestHMacBasicProperties tests basic HMAC properties.
func TestHMacBasicProperties(t *testing.T) {
	t.Run("AlgorithmName", func(t *testing.T) {
		hmac := NewHMac(digests.NewSM3Digest())
		if hmac.GetAlgorithmName() != "HMac/SM3" {
			t.Errorf("Expected algorithm name 'HMac/SM3', got '%s'", hmac.GetAlgorithmName())
		}
	})

	t.Run("MacSize", func(t *testing.T) {
		hmac := NewHMac(digests.NewSM3Digest())
		if hmac.GetMacSize() != 32 {
			t.Errorf("Expected MAC size 32, got %d", hmac.GetMacSize())
		}
	})
}

// TestHMacInitialization tests HMAC initialization.
func TestHMacInitialization(t *testing.T) {
	t.Run("InitWithKey", func(t *testing.T) {
		hmac := NewHMac(digests.NewSM3Digest())
		key := make([]byte, 32)
		err := hmac.Init(params.NewKeyParameter(key))
		if err != nil {
			t.Fatalf("Failed to initialize HMAC: %v", err)
		}
	})

	t.Run("InitWithoutKeyParameter", func(t *testing.T) {
		hmac := NewHMac(digests.NewSM3Digest())
		// Pass a non-KeyParameter
		err := hmac.Init(params.NewParametersWithIV(nil, nil))
		if err == nil {
			t.Error("Expected error when initializing without KeyParameter")
		}
	})
}

// TestHMacBasicComputation tests basic HMAC computation.
func TestHMacBasicComputation(t *testing.T) {
	t.Run("EmptyMessage", func(t *testing.T) {
		key := make([]byte, 32)
		message := []byte{}
		result, err := computeHMac(key, message)
		if err != nil {
			t.Fatalf("Failed to compute HMAC: %v", err)
		}
		if len(result) != 32 {
			t.Errorf("Expected MAC length 32, got %d", len(result))
		}
	})

	t.Run("ShortMessage", func(t *testing.T) {
		key := []byte("key")
		message := []byte("The quick brown fox jumps over the lazy dog")
		result, err := computeHMac(key, message)
		if err != nil {
			t.Fatalf("Failed to compute HMAC: %v", err)
		}
		if len(result) != 32 {
			t.Errorf("Expected MAC length 32, got %d", len(result))
		}
		// Test against known value from JS implementation
		expected := "bd4a34077888162b210645b8ebf74b9af357303789357a27c7fc457244ebd398"
		actual := bytesToHex(result)
		if actual != expected {
			t.Errorf("HMAC mismatch\nExpected: %s\nActual:   %s", expected, actual)
		}
	})

	t.Run("MessageShorterThanBlockSize", func(t *testing.T) {
		key := []byte("key")
		message := []byte("hello")
		result, err := computeHMac(key, message)
		if err != nil {
			t.Fatalf("Failed to compute HMAC: %v", err)
		}
		if len(result) != 32 {
			t.Errorf("Expected MAC length 32, got %d", len(result))
		}
	})

	t.Run("MessageLongerThanBlockSize", func(t *testing.T) {
		key := []byte("key")
		message := []byte("This is a longer message that exceeds the block size of 64 bytes for SM3...")
		result, err := computeHMac(key, message)
		if err != nil {
			t.Fatalf("Failed to compute HMAC: %v", err)
		}
		if len(result) != 32 {
			t.Errorf("Expected MAC length 32, got %d", len(result))
		}
	})
}

// TestHMacKeyLengthHandling tests HMAC with different key lengths.
func TestHMacKeyLengthHandling(t *testing.T) {
	t.Run("ShortKey", func(t *testing.T) {
		key := make([]byte, 16) // 16 bytes < 64 bytes
		message := []byte("test")
		result, err := computeHMac(key, message)
		if err != nil {
			t.Fatalf("Failed to compute HMAC: %v", err)
		}
		if len(result) != 32 {
			t.Errorf("Expected MAC length 32, got %d", len(result))
		}
	})

	t.Run("KeyEqualToBlockSize", func(t *testing.T) {
		key := make([]byte, 64) // Exactly block size
		message := []byte("test")
		result, err := computeHMac(key, message)
		if err != nil {
			t.Fatalf("Failed to compute HMAC: %v", err)
		}
		if len(result) != 32 {
			t.Errorf("Expected MAC length 32, got %d", len(result))
		}
	})

	t.Run("LongKey", func(t *testing.T) {
		key := make([]byte, 128) // 128 bytes > 64 bytes
		message := []byte("test")
		result, err := computeHMac(key, message)
		if err != nil {
			t.Fatalf("Failed to compute HMAC: %v", err)
		}
		if len(result) != 32 {
			t.Errorf("Expected MAC length 32, got %d", len(result))
		}
	})

	t.Run("DifferentKeyLengthsSamePrefix", func(t *testing.T) {
		shortKey := make([]byte, 16)
		longKey := make([]byte, 32)
		// Set same prefix
		for i := range shortKey {
			shortKey[i] = 1
		}
		for i := range longKey {
			longKey[i] = 1
		}

		message := []byte("test")
		result1, err := computeHMac(shortKey, message)
		if err != nil {
			t.Fatalf("Failed to compute HMAC: %v", err)
		}
		result2, err := computeHMac(longKey, message)
		if err != nil {
			t.Fatalf("Failed to compute HMAC: %v", err)
		}

		if bytes.Equal(result1, result2) {
			t.Error("Expected different results for different key lengths")
		}
	})
}

// TestHMacIncrementalUpdates tests HMAC with multiple update calls.
func TestHMacIncrementalUpdates(t *testing.T) {
	t.Run("MultipleUpdates", func(t *testing.T) {
		key := []byte("key")
		message := []byte("hello world")

		// Compute in one go
		result1, err := computeHMac(key, message)
		if err != nil {
			t.Fatalf("Failed to compute HMAC: %v", err)
		}

		// Compute incrementally
		hmac := NewHMac(digests.NewSM3Digest())
		err = hmac.Init(params.NewKeyParameter(key))
		if err != nil {
			t.Fatalf("Failed to initialize HMAC: %v", err)
		}
		hmac.UpdateArray(message, 0, 5)  // "hello"
		hmac.UpdateArray(message, 5, 1)  // " "
		hmac.UpdateArray(message, 6, 5)  // "world"
		result2 := make([]byte, hmac.GetMacSize())
		_, err = hmac.DoFinal(result2, 0)
		if err != nil {
			t.Fatalf("Failed to finalize HMAC: %v", err)
		}

		if !bytes.Equal(result1, result2) {
			t.Errorf("Incremental update produced different result\nExpected: %s\nActual:   %s",
				bytesToHex(result1), bytesToHex(result2))
		}
	})

	t.Run("SingleByteUpdates", func(t *testing.T) {
		key := []byte("key")
		message := []byte("test")

		// Compute in one go
		result1, err := computeHMac(key, message)
		if err != nil {
			t.Fatalf("Failed to compute HMAC: %v", err)
		}

		// Compute byte by byte
		hmac := NewHMac(digests.NewSM3Digest())
		err = hmac.Init(params.NewKeyParameter(key))
		if err != nil {
			t.Fatalf("Failed to initialize HMAC: %v", err)
		}
		for _, b := range message {
			hmac.Update(b)
		}
		result2 := make([]byte, hmac.GetMacSize())
		_, err = hmac.DoFinal(result2, 0)
		if err != nil {
			t.Fatalf("Failed to finalize HMAC: %v", err)
		}

		if !bytes.Equal(result1, result2) {
			t.Errorf("Single byte updates produced different result\nExpected: %s\nActual:   %s",
				bytesToHex(result1), bytesToHex(result2))
		}
	})
}

// TestHMacReset tests HMAC reset functionality.
func TestHMacReset(t *testing.T) {
	t.Run("ResetAndReuse", func(t *testing.T) {
		hmac := NewHMac(digests.NewSM3Digest())
		key := []byte("key")
		message := []byte("test")

		// First computation
		err := hmac.Init(params.NewKeyParameter(key))
		if err != nil {
			t.Fatalf("Failed to initialize HMAC: %v", err)
		}
		hmac.UpdateArray(message, 0, len(message))
		result1 := make([]byte, hmac.GetMacSize())
		_, err = hmac.DoFinal(result1, 0)
		if err != nil {
			t.Fatalf("Failed to finalize HMAC: %v", err)
		}

		// Reset and compute again
		hmac.Reset()
		hmac.UpdateArray(message, 0, len(message))
		result2 := make([]byte, hmac.GetMacSize())
		_, err = hmac.DoFinal(result2, 0)
		if err != nil {
			t.Fatalf("Failed to finalize HMAC: %v", err)
		}

		// Should produce same result
		if !bytes.Equal(result1, result2) {
			t.Errorf("Reset produced different result\nExpected: %s\nActual:   %s",
				bytesToHex(result1), bytesToHex(result2))
		}
	})

	t.Run("ResetAfterPartialUpdate", func(t *testing.T) {
		hmac := NewHMac(digests.NewSM3Digest())
		key := []byte("key")
		message := []byte("test")

		err := hmac.Init(params.NewKeyParameter(key))
		if err != nil {
			t.Fatalf("Failed to initialize HMAC: %v", err)
		}

		// Partial update
		hmac.UpdateArray([]byte("wrong"), 0, 5)

		// Reset
		hmac.Reset()

		// Compute with correct message
		hmac.UpdateArray(message, 0, len(message))
		result1 := make([]byte, hmac.GetMacSize())
		_, err = hmac.DoFinal(result1, 0)
		if err != nil {
			t.Fatalf("Failed to finalize HMAC: %v", err)
		}

		// Compare with fresh computation
		result2, err := computeHMac(key, message)
		if err != nil {
			t.Fatalf("Failed to compute HMAC: %v", err)
		}

		if !bytes.Equal(result1, result2) {
			t.Errorf("Reset after partial update produced different result\nExpected: %s\nActual:   %s",
				bytesToHex(result2), bytesToHex(result1))
		}
	})
}

// TestHMacDoFinalAutoReset tests that DoFinal auto-resets the HMAC.
func TestHMacDoFinalAutoReset(t *testing.T) {
	hmac := NewHMac(digests.NewSM3Digest())
	key := []byte("key")
	message := []byte("test")

	err := hmac.Init(params.NewKeyParameter(key))
	if err != nil {
		t.Fatalf("Failed to initialize HMAC: %v", err)
	}

	// First computation
	hmac.UpdateArray(message, 0, len(message))
	result1 := make([]byte, hmac.GetMacSize())
	_, err = hmac.DoFinal(result1, 0)
	if err != nil {
		t.Fatalf("Failed to finalize HMAC: %v", err)
	}

	// Second computation without explicit reset
	hmac.UpdateArray(message, 0, len(message))
	result2 := make([]byte, hmac.GetMacSize())
	_, err = hmac.DoFinal(result2, 0)
	if err != nil {
		t.Fatalf("Failed to finalize HMAC: %v", err)
	}

	// Should produce same result (auto-reset after DoFinal)
	if !bytes.Equal(result1, result2) {
		t.Errorf("DoFinal should auto-reset\nExpected: %s\nActual:   %s",
			bytesToHex(result1), bytesToHex(result2))
	}
}

// TestHMacOutputBuffer tests output buffer handling.
func TestHMacOutputBuffer(t *testing.T) {
	t.Run("OutputBufferTooSmall", func(t *testing.T) {
		hmac := NewHMac(digests.NewSM3Digest())
		key := []byte("key")
		message := []byte("test")

		err := hmac.Init(params.NewKeyParameter(key))
		if err != nil {
			t.Fatalf("Failed to initialize HMAC: %v", err)
		}
		hmac.UpdateArray(message, 0, len(message))

		// Too small buffer
		out := make([]byte, 16) // Need 32 bytes
		_, err = hmac.DoFinal(out, 0)
		if err == nil {
			t.Error("Expected error for too small output buffer")
		}
	})

	t.Run("OutputBufferWithOffset", func(t *testing.T) {
		hmac := NewHMac(digests.NewSM3Digest())
		key := []byte("key")
		message := []byte("test")

		err := hmac.Init(params.NewKeyParameter(key))
		if err != nil {
			t.Fatalf("Failed to initialize HMAC: %v", err)
		}
		hmac.UpdateArray(message, 0, len(message))

		// Buffer with offset
		out := make([]byte, 48) // Extra space
		n, err := hmac.DoFinal(out, 10)
		if err != nil {
			t.Fatalf("Failed to finalize HMAC: %v", err)
		}
		if n != 32 {
			t.Errorf("Expected 32 bytes written, got %d", n)
		}

		// Verify data was written at offset
		result := out[10:42]
		expected, _ := computeHMac(key, message)
		if !bytes.Equal(result, expected) {
			t.Errorf("Result at offset doesn't match\nExpected: %s\nActual:   %s",
				bytesToHex(expected), bytesToHex(result))
		}
	})
}

// TestHMacDeterminism tests that HMAC is deterministic.
func TestHMacDeterminism(t *testing.T) {
	key := []byte("test-key")
	message := []byte("test-message")

	result1, err := computeHMac(key, message)
	if err != nil {
		t.Fatalf("Failed to compute HMAC: %v", err)
	}

	result2, err := computeHMac(key, message)
	if err != nil {
		t.Fatalf("Failed to compute HMAC: %v", err)
	}

	if !bytes.Equal(result1, result2) {
		t.Errorf("HMAC is not deterministic\nFirst:  %s\nSecond: %s",
			bytesToHex(result1), bytesToHex(result2))
	}
}

// TestHMacDifferentKeys tests that different keys produce different MACs.
func TestHMacDifferentKeys(t *testing.T) {
	key1 := []byte("key1")
	key2 := []byte("key2")
	message := []byte("same message")

	result1, err := computeHMac(key1, message)
	if err != nil {
		t.Fatalf("Failed to compute HMAC: %v", err)
	}

	result2, err := computeHMac(key2, message)
	if err != nil {
		t.Fatalf("Failed to compute HMAC: %v", err)
	}

	if bytes.Equal(result1, result2) {
		t.Error("Different keys should produce different MACs")
	}
}

// TestHMacDifferentMessages tests that different messages produce different MACs.
func TestHMacDifferentMessages(t *testing.T) {
	key := []byte("key")
	message1 := []byte("message1")
	message2 := []byte("message2")

	result1, err := computeHMac(key, message1)
	if err != nil {
		t.Fatalf("Failed to compute HMAC: %v", err)
	}

	result2, err := computeHMac(key, message2)
	if err != nil {
		t.Fatalf("Failed to compute HMAC: %v", err)
	}

	if bytes.Equal(result1, result2) {
		t.Error("Different messages should produce different MACs")
	}
}

// TestHMacRFC2104TestVectors tests HMAC-SM3 with adapted RFC 2104 test vectors.
// Note: RFC 2104 test vectors are for HMAC-MD5, we adapt them for HMAC-SM3.
func TestHMacRFC2104Adaptation(t *testing.T) {
	tests := []struct {
		name    string
		key     string
		message string
	}{
		{
			name:    "Test1",
			key:     "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
			message: "Hi There",
		},
		{
			name:    "Test2",
			key:     "4a656665", // "Jefe"
			message: "what do ya want for nothing?",
		},
		{
			name:    "Test3",
			key:     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			message: string(bytes.Repeat([]byte{0xdd}, 50)),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := hexToBytes(t, tt.key)
			message := []byte(tt.message)
			result, err := computeHMac(key, message)
			if err != nil {
				t.Fatalf("Failed to compute HMAC: %v", err)
			}
			if len(result) != 32 {
				t.Errorf("Expected MAC length 32, got %d", len(result))
			}
			// We don't check specific values since these are adapted test vectors
			// The important part is that they execute without error
		})
	}
}
