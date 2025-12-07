package paddings

import (
	"bytes"
	"testing"
)

func TestISO7816d4Padding_GetPaddingName(t *testing.T) {
	padding := NewISO7816d4Padding()
	if name := padding.GetPaddingName(); name != "ISO7816-4" {
		t.Errorf("Expected name 'ISO7816-4', got '%s'", name)
	}
}

func TestISO7816d4Padding_AddPadding(t *testing.T) {
	padding := NewISO7816d4Padding()

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
			expected: []byte{0x80},
		},
		{
			name:     "Pad 2 bytes",
			blockSize: 16,
			inOff:    14,
			expected: []byte{0x80, 0x00},
		},
		{
			name:     "Pad 8 bytes",
			blockSize: 16,
			inOff:    8,
			expected: []byte{0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
		{
			name:     "Pad full block",
			blockSize: 16,
			inOff:    0,
			expected: append([]byte{0x80}, make([]byte, 15)...),
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
				t.Errorf("Expected padding %x, got %x", tt.expected, block[tt.inOff:])
			}

			// Verify first byte is always 0x80
			if block[tt.inOff] != 0x80 {
				t.Errorf("Expected first padding byte 0x80, got 0x%02x", block[tt.inOff])
			}
		})
	}
}

func TestISO7816d4Padding_PadCount(t *testing.T) {
	padding := NewISO7816d4Padding()

	tests := []struct {
		name     string
		input    []byte
		expected int
	}{
		{
			name:     "1 byte padding",
			input:    []byte{0x01, 0x02, 0x03, 0x04, 0x80},
			expected: 1,
		},
		{
			name:     "2 bytes padding",
			input:    []byte{0x01, 0x02, 0x03, 0x80, 0x00},
			expected: 2,
		},
		{
			name:     "8 bytes padding",
			input:    []byte{0x01, 0x02, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			expected: 8,
		},
		{
			name:     "Full block padding",
			input:    append([]byte{0x80}, make([]byte, 15)...),
			expected: 16,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			count, _ := padding.PadCount(tt.input)
			if count != tt.expected {
				t.Errorf("Expected pad count %d, got %d", tt.expected, count)
			}
		})
	}
}

func TestISO7816d4Padding_PadCount_Invalid(t *testing.T) {
	padding := NewISO7816d4Padding()

	tests := []struct {
		name  string
		input []byte
	}{
		{
			name:  "Missing 0x80 marker",
			input: []byte{0x01, 0x02, 0x03, 0x00, 0x00},
		},
		{
			name:  "Wrong marker byte",
			input: []byte{0x01, 0x02, 0x03, 0x7F, 0x00},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := padding.PadCount(tt.input)
			if err == nil {
				t.Error("Expected error for invalid padding, but got nil")
			}
		})
	}
}

func TestISO7816d4Padding_RoundTrip(t *testing.T) {
	padding := NewISO7816d4Padding()
	blockSize := 16

	testData := [][]byte{
		{0x01, 0x02, 0x03, 0x04, 0x05},
		{0x01},
		{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F},
		{}, // Empty data
	}

	for _, data := range testData {
		t.Run("", func(t *testing.T) {
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
		})
	}
}

func TestISO7816d4Padding_AllPositions(t *testing.T) {
	padding := NewISO7816d4Padding()
	blockSize := 16

	// Test padding at every possible position
	for inOff := 0; inOff < blockSize; inOff++ {
		block := make([]byte, blockSize)
		
		// Fill with non-zero data
		for i := 0; i < inOff; i++ {
			block[i] = byte(i + 1)
		}

		// Add padding
		added := padding.AddPadding(block, inOff)
		expectedAdded := blockSize - inOff

		if added != expectedAdded {
			t.Errorf("At offset %d: expected %d bytes added, got %d", inOff, expectedAdded, added)
		}

		// Verify 0x80 marker
		if block[inOff] != 0x80 {
			t.Errorf("At offset %d: expected 0x80 marker, got 0x%02x", inOff, block[inOff])
		}

		// Verify zero bytes
		for i := inOff + 1; i < blockSize; i++ {
			if block[i] != 0x00 {
				t.Errorf("At offset %d: expected 0x00 at position %d, got 0x%02x", inOff, i, block[i])
			}
		}

		// Remove padding
		padCount, _ := padding.PadCount(block)
		if padCount != added {
			t.Errorf("At offset %d: expected pad count %d, got %d", inOff, added, padCount)
		}
	}
}

func BenchmarkISO7816d4Padding_AddPadding(b *testing.B) {
	padding := NewISO7816d4Padding()
	block := make([]byte, 16)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		padding.AddPadding(block, 8)
	}
}

func BenchmarkISO7816d4Padding_PadCount(b *testing.B) {
	padding := NewISO7816d4Padding()
	block := []byte{0x01, 0x02, 0x03, 0x80, 0x00, 0x00, 0x00, 0x00}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		padding.PadCount(block)
	}
}
