package paddings

import (
	"bytes"
	"testing"
)

func TestZeroBytePadding_GetPaddingName(t *testing.T) {
	padding := NewZeroBytePadding()
	if name := padding.GetPaddingName(); name != "ZeroBytePadding" {
		t.Errorf("Expected name 'ZeroBytePadding', got '%s'", name)
	}
}

func TestZeroBytePadding_AddPadding(t *testing.T) {
	padding := NewZeroBytePadding()

	tests := []struct {
		name     string
		blockSize int
		inOff    int
		expected []byte
	}{
		{
			name:     "Pad 1 byte",
			blockSize: 16,
			inOff:    15,
			expected: []byte{0x00},
		},
		{
			name:     "Pad 8 bytes",
			blockSize: 16,
			inOff:    8,
			expected: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
		{
			name:     "Pad full block",
			blockSize: 16,
			inOff:    0,
			expected: make([]byte, 16),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			block := make([]byte, tt.blockSize)
			added := padding.AddPadding(block, tt.inOff)

			if added != len(tt.expected) {
				t.Errorf("Expected %d bytes added, got %d", len(tt.expected), added)
			}

			if !bytes.Equal(block[tt.inOff:], tt.expected) {
				t.Errorf("Expected padding %v, got %v", tt.expected, block[tt.inOff:])
			}
		})
	}
}

func TestZeroBytePadding_PadCount(t *testing.T) {
	padding := NewZeroBytePadding()

	tests := []struct {
		name     string
		input    []byte
		expected int
	}{
		{
			name:     "1 zero byte",
			input:    []byte{0x01, 0x02, 0x03, 0x04, 0x00},
			expected: 1,
		},
		{
			name:     "4 zero bytes",
			input:    []byte{0x01, 0x02, 0x00, 0x00, 0x00, 0x00},
			expected: 4,
		},
		{
			name:     "No zero bytes",
			input:    []byte{0x01, 0x02, 0x03, 0x04},
			expected: 0,
		},
		{
			name:     "All zero bytes",
			input:    make([]byte, 16),
			expected: 16,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			count, err := padding.PadCount(tt.input)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			if count != tt.expected {
				t.Errorf("Expected pad count %d, got %d", tt.expected, count)
			}
		})
	}
}

func TestZeroBytePadding_RoundTrip(t *testing.T) {
	padding := NewZeroBytePadding()
	blockSize := 16

	// Test with non-zero data that doesn't end with zeros
	data := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	
	// Add padding
	block := make([]byte, blockSize)
	copy(block, data)
	added := padding.AddPadding(block, len(data))

	// Verify padding was added
	if added != blockSize-len(data) {
		t.Errorf("Expected %d bytes padding, got %d", blockSize-len(data), added)
	}

	// Remove padding
	padCount, _ := padding.PadCount(block)
	if padCount != added {
		t.Errorf("Expected pad count %d, got %d", added, padCount)
	}

	// Verify original data
	unpadded := block[:len(block)-padCount]
	if !bytes.Equal(unpadded, data) {
		t.Errorf("Data corruption after padding/unpadding: expected %v, got %v", data, unpadded)
	}
}

func TestZeroBytePadding_Ambiguity(t *testing.T) {
	// Note: Zero byte padding has an ambiguity issue
	// Data that legitimately ends with zeros cannot be distinguished from padding
	padding := NewZeroBytePadding()

	// Data that ends with zeros
	data := []byte{0x01, 0x02, 0x00, 0x00}
	block := make([]byte, 16)
	copy(block, data)
	padding.AddPadding(block, len(data))

	// PadCount will count the trailing zeros from data as padding
	padCount, _ := padding.PadCount(block)
	
	// This will be more than the actual padding added
	t.Logf("Warning: Zero byte padding is ambiguous. Data had 2 trailing zeros, total padding detected: %d", padCount)
}

func BenchmarkZeroBytePadding_AddPadding(b *testing.B) {
	padding := NewZeroBytePadding()
	block := make([]byte, 16)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		padding.AddPadding(block, 8)
	}
}

func BenchmarkZeroBytePadding_PadCount(b *testing.B) {
	padding := NewZeroBytePadding()
	block := []byte{0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x00, 0x00}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		padding.PadCount(block)
	}
}
