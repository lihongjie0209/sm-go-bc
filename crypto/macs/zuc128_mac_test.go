package macs

import (
	"bytes"
	"testing"

	"github.com/lihongjie0209/sm-go-bc/crypto/params"
)

// TestZuc128MacBasicFunctionality tests basic ZUC-128 MAC functionality.
func TestZuc128MacBasicFunctionality(t *testing.T) {
	t.Run("AlgorithmName", func(t *testing.T) {
		mac := NewZuc128Mac()
		if mac.GetAlgorithmName() != "ZUC-128-MAC" {
			t.Errorf("Expected algorithm name 'ZUC-128-MAC', got '%s'", mac.GetAlgorithmName())
		}
	})

	t.Run("DefaultMacSize", func(t *testing.T) {
		mac := NewZuc128Mac()
		if mac.GetMacSize() != 4 { // 32 bits = 4 bytes
			t.Errorf("Expected MAC size 4 bytes, got %d", mac.GetMacSize())
		}
	})

	t.Run("CustomMacSize", func(t *testing.T) {
		mac := NewZuc128MacWithLength(64) // 64-bit MAC
		if mac.GetMacSize() != 8 {
			t.Errorf("Expected MAC size 8 bytes, got %d", mac.GetMacSize())
		}
	})

	t.Run("RequireInitialization", func(t *testing.T) {
		mac := NewZuc128Mac()
		out := make([]byte, 4)
		_, err := mac.DoFinal(out, 0)
		if err == nil {
			t.Error("Expected error for uninitialized MAC")
		}
	})
}

// TestZuc128MacComputation tests MAC computation.
func TestZuc128MacComputation(t *testing.T) {
	t.Run("EmptyMessage", func(t *testing.T) {
		mac := NewZuc128Mac()
		key := make([]byte, 16)
		iv := make([]byte, 16)
		p := params.NewParametersWithIV(params.NewKeyParameter(key), iv)

		err := mac.Init(p)
		if err != nil {
			t.Fatalf("Failed to initialize: %v", err)
		}

		// Empty message
		out := make([]byte, mac.GetMacSize())
		n, err := mac.DoFinal(out, 0)
		if err != nil {
			t.Fatalf("DoFinal failed: %v", err)
		}
		if n != 4 {
			t.Errorf("Expected 4 bytes, got %d", n)
		}
	})

	t.Run("ShortMessage", func(t *testing.T) {
		mac := NewZuc128Mac()
		key := make([]byte, 16)
		iv := make([]byte, 16)
		for i := 0; i < 16; i++ {
			key[i] = byte(i)
			iv[i] = byte(i + 16)
		}
		p := params.NewParametersWithIV(params.NewKeyParameter(key), iv)

		err := mac.Init(p)
		if err != nil {
			t.Fatalf("Failed to initialize: %v", err)
		}

		message := []byte("Test")
		mac.UpdateArray(message, 0, len(message))

		out := make([]byte, mac.GetMacSize())
		n, err := mac.DoFinal(out, 0)
		if err != nil {
			t.Fatalf("DoFinal failed: %v", err)
		}
		if n != 4 {
			t.Errorf("Expected 4 bytes, got %d", n)
		}
	})

	t.Run("LongMessage", func(t *testing.T) {
		mac := NewZuc128Mac()
		key := make([]byte, 16)
		iv := make([]byte, 16)
		for i := 0; i < 16; i++ {
			key[i] = byte(i)
			iv[i] = byte(i + 16)
		}
		p := params.NewParametersWithIV(params.NewKeyParameter(key), iv)

		err := mac.Init(p)
		if err != nil {
			t.Fatalf("Failed to initialize: %v", err)
		}

		message := make([]byte, 1024)
		for i := range message {
			message[i] = byte(i & 0xff)
		}
		mac.UpdateArray(message, 0, len(message))

		out := make([]byte, mac.GetMacSize())
		_, err = mac.DoFinal(out, 0)
		if err != nil {
			t.Fatalf("DoFinal failed: %v", err)
		}
	})
}

// TestZuc128MacDeterminism tests that MAC is deterministic.
func TestZuc128MacDeterminism(t *testing.T) {
	key := make([]byte, 16)
	iv := make([]byte, 16)
	for i := 0; i < 16; i++ {
		key[i] = byte(i)
		iv[i] = byte(i + 16)
	}
	message := []byte("Deterministic test message")

	// First computation
	mac1 := NewZuc128Mac()
	mac1.Init(params.NewParametersWithIV(params.NewKeyParameter(key), iv))
	mac1.UpdateArray(message, 0, len(message))
	out1 := make([]byte, mac1.GetMacSize())
	mac1.DoFinal(out1, 0)

	// Second computation
	mac2 := NewZuc128Mac()
	mac2.Init(params.NewParametersWithIV(params.NewKeyParameter(key), iv))
	mac2.UpdateArray(message, 0, len(message))
	out2 := make([]byte, mac2.GetMacSize())
	mac2.DoFinal(out2, 0)

	if !bytes.Equal(out1, out2) {
		t.Error("ZUC-128 MAC is not deterministic")
	}
}

// TestZuc128MacDifferentKeys tests that different keys produce different MACs.
func TestZuc128MacDifferentKeys(t *testing.T) {
	key1 := make([]byte, 16)
	key2 := make([]byte, 16)
	iv := make([]byte, 16)
	for i := 0; i < 16; i++ {
		key1[i] = byte(i)
		key2[i] = byte(i + 1) // Different key
		iv[i] = byte(i)
	}
	message := []byte("Test message")

	// First MAC
	mac1 := NewZuc128Mac()
	mac1.Init(params.NewParametersWithIV(params.NewKeyParameter(key1), iv))
	mac1.UpdateArray(message, 0, len(message))
	out1 := make([]byte, mac1.GetMacSize())
	mac1.DoFinal(out1, 0)

	// Second MAC
	mac2 := NewZuc128Mac()
	mac2.Init(params.NewParametersWithIV(params.NewKeyParameter(key2), iv))
	mac2.UpdateArray(message, 0, len(message))
	out2 := make([]byte, mac2.GetMacSize())
	mac2.DoFinal(out2, 0)

	if bytes.Equal(out1, out2) {
		t.Error("Different keys should produce different MACs")
	}
}

// TestZuc128MacDifferentMessages tests that different messages produce different MACs.
func TestZuc128MacDifferentMessages(t *testing.T) {
	key := make([]byte, 16)
	iv := make([]byte, 16)
	for i := 0; i < 16; i++ {
		key[i] = byte(i)
		iv[i] = byte(i + 16)
	}

	// First MAC
	mac1 := NewZuc128Mac()
	mac1.Init(params.NewParametersWithIV(params.NewKeyParameter(key), iv))
	mac1.UpdateArray([]byte("message1"), 0, 8)
	out1 := make([]byte, mac1.GetMacSize())
	mac1.DoFinal(out1, 0)

	// Second MAC
	mac2 := NewZuc128Mac()
	mac2.Init(params.NewParametersWithIV(params.NewKeyParameter(key), iv))
	mac2.UpdateArray([]byte("message2"), 0, 8)
	out2 := make([]byte, mac2.GetMacSize())
	mac2.DoFinal(out2, 0)

	if bytes.Equal(out1, out2) {
		t.Error("Different messages should produce different MACs")
	}
}

// TestZuc128MacIncrementalUpdate tests incremental updates.
func TestZuc128MacIncrementalUpdate(t *testing.T) {
	key := make([]byte, 16)
	iv := make([]byte, 16)
	for i := 0; i < 16; i++ {
		key[i] = byte(i)
		iv[i] = byte(i + 16)
	}
	message := []byte("Hello, World!")

	// Compute all at once
	mac1 := NewZuc128Mac()
	mac1.Init(params.NewParametersWithIV(params.NewKeyParameter(key), iv))
	mac1.UpdateArray(message, 0, len(message))
	out1 := make([]byte, mac1.GetMacSize())
	mac1.DoFinal(out1, 0)

	// Compute incrementally
	mac2 := NewZuc128Mac()
	mac2.Init(params.NewParametersWithIV(params.NewKeyParameter(key), iv))
	mac2.UpdateArray(message, 0, 5)  // "Hello"
	mac2.UpdateArray(message, 5, 2)  // ", "
	mac2.UpdateArray(message, 7, 6)  // "World!"
	out2 := make([]byte, mac2.GetMacSize())
	mac2.DoFinal(out2, 0)

	if !bytes.Equal(out1, out2) {
		t.Error("Incremental update produced different result")
	}
}

// TestZuc128MacByteByByte tests byte-by-byte updates.
func TestZuc128MacByteByByte(t *testing.T) {
	key := make([]byte, 16)
	iv := make([]byte, 16)
	for i := 0; i < 16; i++ {
		key[i] = byte(i)
		iv[i] = byte(i + 16)
	}
	message := []byte("Test")

	// Compute all at once
	mac1 := NewZuc128Mac()
	mac1.Init(params.NewParametersWithIV(params.NewKeyParameter(key), iv))
	mac1.UpdateArray(message, 0, len(message))
	out1 := make([]byte, mac1.GetMacSize())
	mac1.DoFinal(out1, 0)

	// Compute byte by byte
	mac2 := NewZuc128Mac()
	mac2.Init(params.NewParametersWithIV(params.NewKeyParameter(key), iv))
	for _, b := range message {
		mac2.Update(b)
	}
	out2 := make([]byte, mac2.GetMacSize())
	mac2.DoFinal(out2, 0)

	if !bytes.Equal(out1, out2) {
		t.Error("Byte-by-byte update produced different result")
	}
}

// TestZuc128MacReset tests the reset functionality.
func TestZuc128MacReset(t *testing.T) {
	mac := NewZuc128Mac()
	key := make([]byte, 16)
	iv := make([]byte, 16)
	for i := 0; i < 16; i++ {
		key[i] = byte(i)
		iv[i] = byte(i + 16)
	}
	message := []byte("Test message")

	err := mac.Init(params.NewParametersWithIV(params.NewKeyParameter(key), iv))
	if err != nil {
		t.Fatalf("Failed to initialize: %v", err)
	}

	// First computation
	mac.UpdateArray(message, 0, len(message))
	out1 := make([]byte, mac.GetMacSize())
	mac.DoFinal(out1, 0)

	// Second computation (DoFinal should auto-reset)
	mac.UpdateArray(message, 0, len(message))
	out2 := make([]byte, mac.GetMacSize())
	mac.DoFinal(out2, 0)

	if !bytes.Equal(out1, out2) {
		t.Error("Reset should produce same output for same input")
	}
}

// TestZuc128MacOutputBuffer tests output buffer handling.
func TestZuc128MacOutputBuffer(t *testing.T) {
	t.Run("BufferTooSmall", func(t *testing.T) {
		mac := NewZuc128Mac()
		key := make([]byte, 16)
		iv := make([]byte, 16)
		mac.Init(params.NewParametersWithIV(params.NewKeyParameter(key), iv))
		mac.UpdateArray([]byte("Test"), 0, 4)

		out := make([]byte, 2) // Too small
		_, err := mac.DoFinal(out, 0)
		if err == nil {
			t.Error("Expected error for buffer too small")
		}
	})

	t.Run("WithOffset", func(t *testing.T) {
		mac := NewZuc128Mac()
		key := make([]byte, 16)
		iv := make([]byte, 16)
		mac.Init(params.NewParametersWithIV(params.NewKeyParameter(key), iv))
		mac.UpdateArray([]byte("Test"), 0, 4)

		out := make([]byte, 10) // Extra space
		n, err := mac.DoFinal(out, 5)
		if err != nil {
			t.Fatalf("DoFinal failed: %v", err)
		}
		if n != 4 {
			t.Errorf("Expected 4 bytes written, got %d", n)
		}

		// Verify first 5 bytes are still zero
		for i := 0; i < 5; i++ {
			if out[i] != 0 {
				t.Errorf("Byte %d should be zero, got %d", i, out[i])
			}
		}
	})
}
