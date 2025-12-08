package macs

import (
	"bytes"
	"testing"

	"github.com/lihongjie0209/sm-go-bc/crypto/params"
)

// TestZuc256MacBasicFunctionality tests basic ZUC-256 MAC functionality.
func TestZuc256MacBasicFunctionality(t *testing.T) {
	t.Run("AlgorithmName", func(t *testing.T) {
		mac := NewZuc256Mac()
		if mac.GetAlgorithmName() != "ZUC-256-MAC" {
			t.Errorf("Expected algorithm name 'ZUC-256-MAC', got '%s'", mac.GetAlgorithmName())
		}
	})

	t.Run("DefaultMacSize", func(t *testing.T) {
		mac := NewZuc256Mac()
		if mac.GetMacSize() != 8 { // 64 bits = 8 bytes
			t.Errorf("Expected MAC size 8 bytes, got %d", mac.GetMacSize())
		}
	})

	t.Run("CustomMacSize32", func(t *testing.T) {
		mac := NewZuc256MacWithLength(32)
		if mac.GetMacSize() != 4 {
			t.Errorf("Expected MAC size 4 bytes, got %d", mac.GetMacSize())
		}
	})

	t.Run("CustomMacSize128", func(t *testing.T) {
		mac := NewZuc256MacWithLength(128)
		if mac.GetMacSize() != 16 {
			t.Errorf("Expected MAC size 16 bytes, got %d", mac.GetMacSize())
		}
	})

	t.Run("RequireInitialization", func(t *testing.T) {
		mac := NewZuc256Mac()
		out := make([]byte, 8)
		_, err := mac.DoFinal(out, 0)
		if err == nil {
			t.Error("Expected error for uninitialized MAC")
		}
	})
}

// TestZuc256MacComputation tests MAC computation.
func TestZuc256MacComputation(t *testing.T) {
	t.Run("EmptyMessage", func(t *testing.T) {
		mac := NewZuc256Mac()
		key := make([]byte, 32)
		iv := make([]byte, 23)
		p := params.NewParametersWithIV(params.NewKeyParameter(key), iv)

		err := mac.Init(p)
		if err != nil {
			t.Fatalf("Failed to initialize: %v", err)
		}

		out := make([]byte, mac.GetMacSize())
		n, err := mac.DoFinal(out, 0)
		if err != nil {
			t.Fatalf("DoFinal failed: %v", err)
		}
		if n != 8 {
			t.Errorf("Expected 8 bytes, got %d", n)
		}
	})

	t.Run("ShortMessage", func(t *testing.T) {
		mac := NewZuc256Mac()
		key := make([]byte, 32)
		iv := make([]byte, 23)
		for i := 0; i < 32; i++ {
			key[i] = byte(i)
		}
		for i := 0; i < 23; i++ {
			iv[i] = byte(i + 32)
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
		if n != 8 {
			t.Errorf("Expected 8 bytes, got %d", n)
		}
	})

	t.Run("LongMessage", func(t *testing.T) {
		mac := NewZuc256Mac()
		key := make([]byte, 32)
		iv := make([]byte, 23)
		for i := 0; i < 32; i++ {
			key[i] = byte(i)
		}
		for i := 0; i < 23; i++ {
			iv[i] = byte(i + 32)
		}
		p := params.NewParametersWithIV(params.NewKeyParameter(key), iv)

		err := mac.Init(p)
		if err != nil {
			t.Fatalf("Failed to initialize: %v", err)
		}

		message := make([]byte, 2048)
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

// TestZuc256MacDeterminism tests that MAC is deterministic.
func TestZuc256MacDeterminism(t *testing.T) {
	key := make([]byte, 32)
	iv := make([]byte, 23)
	for i := 0; i < 32; i++ {
		key[i] = byte(i)
	}
	for i := 0; i < 23; i++ {
		iv[i] = byte(i + 32)
	}
	message := []byte("Deterministic test message for ZUC-256")

	// First computation
	mac1 := NewZuc256Mac()
	mac1.Init(params.NewParametersWithIV(params.NewKeyParameter(key), iv))
	mac1.UpdateArray(message, 0, len(message))
	out1 := make([]byte, mac1.GetMacSize())
	mac1.DoFinal(out1, 0)

	// Second computation
	mac2 := NewZuc256Mac()
	mac2.Init(params.NewParametersWithIV(params.NewKeyParameter(key), iv))
	mac2.UpdateArray(message, 0, len(message))
	out2 := make([]byte, mac2.GetMacSize())
	mac2.DoFinal(out2, 0)

	if !bytes.Equal(out1, out2) {
		t.Error("ZUC-256 MAC is not deterministic")
	}
}

// TestZuc256MacDifferentKeys tests that different keys produce different MACs.
func TestZuc256MacDifferentKeys(t *testing.T) {
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
	message := []byte("Test message")

	// First MAC
	mac1 := NewZuc256Mac()
	mac1.Init(params.NewParametersWithIV(params.NewKeyParameter(key1), iv))
	mac1.UpdateArray(message, 0, len(message))
	out1 := make([]byte, mac1.GetMacSize())
	mac1.DoFinal(out1, 0)

	// Second MAC
	mac2 := NewZuc256Mac()
	mac2.Init(params.NewParametersWithIV(params.NewKeyParameter(key2), iv))
	mac2.UpdateArray(message, 0, len(message))
	out2 := make([]byte, mac2.GetMacSize())
	mac2.DoFinal(out2, 0)

	if bytes.Equal(out1, out2) {
		t.Error("Different keys should produce different MACs")
	}
}

// TestZuc256MacDifferentMessages tests that different messages produce different MACs.
func TestZuc256MacDifferentMessages(t *testing.T) {
	key := make([]byte, 32)
	iv := make([]byte, 23)
	for i := 0; i < 32; i++ {
		key[i] = byte(i)
	}
	for i := 0; i < 23; i++ {
		iv[i] = byte(i + 32)
	}

	// First MAC
	mac1 := NewZuc256Mac()
	mac1.Init(params.NewParametersWithIV(params.NewKeyParameter(key), iv))
	mac1.UpdateArray([]byte("message1"), 0, 8)
	out1 := make([]byte, mac1.GetMacSize())
	mac1.DoFinal(out1, 0)

	// Second MAC
	mac2 := NewZuc256Mac()
	mac2.Init(params.NewParametersWithIV(params.NewKeyParameter(key), iv))
	mac2.UpdateArray([]byte("message2"), 0, 8)
	out2 := make([]byte, mac2.GetMacSize())
	mac2.DoFinal(out2, 0)

	if bytes.Equal(out1, out2) {
		t.Error("Different messages should produce different MACs")
	}
}

// TestZuc256MacIncrementalUpdate tests incremental updates.
func TestZuc256MacIncrementalUpdate(t *testing.T) {
	key := make([]byte, 32)
	iv := make([]byte, 23)
	for i := 0; i < 32; i++ {
		key[i] = byte(i)
	}
	for i := 0; i < 23; i++ {
		iv[i] = byte(i + 32)
	}
	message := []byte("Hello, ZUC-256 MAC!")

	// Compute all at once
	mac1 := NewZuc256Mac()
	mac1.Init(params.NewParametersWithIV(params.NewKeyParameter(key), iv))
	mac1.UpdateArray(message, 0, len(message))
	out1 := make([]byte, mac1.GetMacSize())
	mac1.DoFinal(out1, 0)

	// Compute incrementally
	mac2 := NewZuc256Mac()
	mac2.Init(params.NewParametersWithIV(params.NewKeyParameter(key), iv))
	mac2.UpdateArray(message, 0, 7)   // "Hello, "
	mac2.UpdateArray(message, 7, 8)   // "ZUC-256 "
	mac2.UpdateArray(message, 15, 4)  // "MAC!"
	out2 := make([]byte, mac2.GetMacSize())
	mac2.DoFinal(out2, 0)

	if !bytes.Equal(out1, out2) {
		t.Error("Incremental update produced different result")
	}
}

// TestZuc256MacByteByByte tests byte-by-byte updates.
func TestZuc256MacByteByByte(t *testing.T) {
	key := make([]byte, 32)
	iv := make([]byte, 23)
	for i := 0; i < 32; i++ {
		key[i] = byte(i)
	}
	for i := 0; i < 23; i++ {
		iv[i] = byte(i + 32)
	}
	message := []byte("Test")

	// Compute all at once
	mac1 := NewZuc256Mac()
	mac1.Init(params.NewParametersWithIV(params.NewKeyParameter(key), iv))
	mac1.UpdateArray(message, 0, len(message))
	out1 := make([]byte, mac1.GetMacSize())
	mac1.DoFinal(out1, 0)

	// Compute byte by byte
	mac2 := NewZuc256Mac()
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

// TestZuc256MacReset tests the reset functionality.
func TestZuc256MacReset(t *testing.T) {
	mac := NewZuc256Mac()
	key := make([]byte, 32)
	iv := make([]byte, 23)
	for i := 0; i < 32; i++ {
		key[i] = byte(i)
	}
	for i := 0; i < 23; i++ {
		iv[i] = byte(i + 32)
	}
	message := []byte("Test message for ZUC-256")

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
