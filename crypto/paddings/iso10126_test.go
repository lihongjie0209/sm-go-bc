package paddings

import (
	"bytes"
	"testing"
)

func TestISO10126Padding_GetPaddingName(t *testing.T) {
	padding := NewISO10126Padding()
	if name := padding.GetPaddingName(); name != "ISO10126-2" {
		t.Errorf("Expected name 'ISO10126-2', got '%s'", name)
	}
}

func TestISO10126Padding_AddPadding(t *testing.T) {
	padding := NewISO10126Padding()

	tests := []struct {
		name           string
		blockSize      int
		inOff          int
		expectedLength int
		expectedLast   byte
	}{
		{
			name:           "Pad 1 byte",
			blockSize:      16,
			inOff:          15,
			expectedLength: 1,
			expectedLast:   0x01,
		},
		{
			name:           "Pad 2 bytes",
			blockSize:      16,
			inOff:          14,
			expectedLength: 2,
			expectedLast:   0x02,
		},
		{
			name:           "Pad 8 bytes",
			blockSize:      16,
			inOff:          8,
			expectedLength: 8,
			expectedLast:   0x08,
		},
		{
			name:           "Pad full block",
			blockSize:      16,
			inOff:          0,
			expectedLength: 16,
			expectedLast:   0x10,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			block := make([]byte, tt.blockSize)
			added := padding.AddPadding(block, tt.inOff)

			if added != tt.expectedLength {
				t.Errorf("Expected %d bytes added, got %d", tt.expectedLength, added)
			}

			// Verify last byte contains padding length
			lastByte := block[len(block)-1]
			if lastByte != tt.expectedLast {
				t.Errorf("Expected last byte 0x%02x, got 0x%02x", tt.expectedLast, lastByte)
			}

			// Verify padding length matches added bytes
			if int(lastByte) != added {
				t.Errorf("Last byte (%d) doesn't match added bytes (%d)", lastByte, added)
			}
		})
	}
}

func TestISO10126Padding_Randomness(t *testing.T) {
	padding := NewISO10126Padding()
	blockSize := 16
	inOff := 8

	// Create two padded blocks
	block1 := make([]byte, blockSize)
	block2 := make([]byte, blockSize)

	padding.AddPadding(block1, inOff)
	padding.AddPadding(block2, inOff)

	// Last bytes should be the same (padding length)
	if block1[blockSize-1] != block2[blockSize-1] {
		t.Error("Last bytes (padding length) should be the same")
	}

	// Random bytes should be different (with very high probability)
	// Compare the random part (excluding the last byte)
	if bytes.Equal(block1[inOff:blockSize-1], block2[inOff:blockSize-1]) {
		t.Error("Random padding bytes should be different between two calls")
	}
}

func TestISO10126Padding_PadCount(t *testing.T) {
	padding := NewISO10126Padding()

	tests := []struct {
		name     string
		input    []byte
		expected int
	}{
		{
			name:     "1 byte padding",
			input:    []byte{0x01, 0x02, 0x03, 0x04, 0x01},
			expected: 1,
		},
		{
			name:     "2 bytes padding",
			input:    []byte{0x01, 0x02, 0x03, 0xAB, 0x02},
			expected: 2,
		},
		{
			name:     "8 bytes padding",
			input:    []byte{0x01, 0x02, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0x08},
			expected: 8,
		},
		{
			name:     "16 bytes padding",
			input:    append(make([]byte, 15), 0x10),
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

func TestISO10126Padding_PadCount_Invalid(t *testing.T) {
	padding := NewISO10126Padding()

	tests := []struct {
		name  string
		input []byte
	}{
		{
			name:  "Padding length too large",
			input: []byte{0x01, 0x02, 0x03, 0x20}, // Claims 32 bytes in 4-byte block
		},
		{
			name:  "Padding length zero",
			input: []byte{0x01, 0x02, 0x03, 0x00},
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

func TestISO10126Padding_RoundTrip(t *testing.T) {
	padding := NewISO10126Padding()
	blockSize := 16

	testData := [][]byte{
		{0x01, 0x02, 0x03, 0x04, 0x05},
		{0x01},
		{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F},
		make([]byte, 0), // Empty data
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

func TestISO10126Padding_AllPositions(t *testing.T) {
	padding := NewISO10126Padding()
	blockSize := 16

	// Test padding at every possible position
	for inOff := 0; inOff < blockSize; inOff++ {
		block := make([]byte, blockSize)
		
		// Fill with known data
		for i := 0; i < inOff; i++ {
			block[i] = byte(i + 1)
		}

		// Add padding
		added := padding.AddPadding(block, inOff)
		expectedAdded := blockSize - inOff

		if added != expectedAdded {
			t.Errorf("At offset %d: expected %d bytes added, got %d", inOff, expectedAdded, added)
		}

		// Verify last byte contains correct padding length
		lastByte := block[blockSize-1]
		if int(lastByte) != added {
			t.Errorf("At offset %d: expected last byte %d, got %d", inOff, added, lastByte)
		}

		// Remove padding
		padCount, _ := padding.PadCount(block)
		if padCount != added {
			t.Errorf("At offset %d: expected pad count %d, got %d", inOff, added, padCount)
		}

		// Verify data integrity
		for i := 0; i < inOff; i++ {
			if block[i] != byte(i+1) {
				t.Errorf("At offset %d: data corrupted at position %d", inOff, i)
			}
		}
	}
}

func TestISO10126Padding_MultipleRounds(t *testing.T) {
	padding := NewISO10126Padding()
	blockSize := 16
	data := []byte{0x01, 0x02, 0x03, 0x04, 0x05}

	// Perform padding/unpadding multiple times
	for i := 0; i < 100; i++ {
		block := make([]byte, blockSize)
		copy(block, data)
		
		added := padding.AddPadding(block, len(data))
		padCount, _ := padding.PadCount(block)
		
		if padCount != added {
			t.Fatalf("Round %d: pad count mismatch", i)
		}

		unpadded := block[:len(block)-padCount]
		if !bytes.Equal(unpadded, data) {
			t.Fatalf("Round %d: data corruption", i)
		}
	}
}

func BenchmarkISO10126Padding_AddPadding(b *testing.B) {
	padding := NewISO10126Padding()
	block := make([]byte, 16)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		padding.AddPadding(block, 8)
	}
}

func BenchmarkISO10126Padding_PadCount(b *testing.B) {
	padding := NewISO10126Padding()
	block := []byte{0x01, 0x02, 0x03, 0x12, 0x34, 0x56, 0x78, 0x08}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		padding.PadCount(block)
	}
}
