package paddings

import (
	"testing"
)

func TestPKCS7GetPaddingName(t *testing.T) {
	padding := NewPKCS7Padding()
	if padding.GetPaddingName() != "PKCS7" {
		t.Errorf("Expected padding name 'PKCS7', got '%s'", padding.GetPaddingName())
	}
}

func TestPKCS7AddPadding(t *testing.T) {
	padding := NewPKCS7Padding()
	
	testCases := []struct {
		name       string
		blockSize  int
		dataLen    int
		expectedPad byte
	}{
		{"Full block", 16, 0, 16},
		{"1 byte", 16, 15, 1},
		{"Half block", 16, 8, 8},
		{"Almost full", 16, 15, 1},
		{"8-byte block full", 8, 0, 8},
		{"8-byte block partial", 8, 5, 3},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			block := make([]byte, tc.blockSize)
			// Fill data portion with non-zero
			for i := 0; i < tc.dataLen; i++ {
				block[i] = 0xFF
			}
			
			padLen := padding.AddPadding(block, tc.dataLen)
			
			if padLen != int(tc.expectedPad) {
				t.Errorf("Expected padding length %d, got %d", tc.expectedPad, padLen)
			}
			
			// Verify all padding bytes are correct
			for i := tc.dataLen; i < tc.blockSize; i++ {
				if block[i] != tc.expectedPad {
					t.Errorf("Padding byte at %d should be %d, got %d", i, tc.expectedPad, block[i])
				}
			}
		})
	}
}

func TestPKCS7PadCount(t *testing.T) {
	padding := NewPKCS7Padding()
	
	testCases := []struct {
		name        string
		block       []byte
		expectedPad int
		shouldError bool
	}{
		{
			"Valid padding 1",
			[]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01},
			1,
			false,
		},
		{
			"Valid padding 8",
			[]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08},
			8,
			false,
		},
		{
			"Valid padding 16",
			[]byte{0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10},
			16,
			false,
		},
		{
			"Invalid padding length 0",
			[]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00},
			0,
			true,
		},
		{
			"Invalid padding length 17",
			[]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x11},
			0,
			true,
		},
		{
			"Invalid padding bytes",
			[]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x02},
			0,
			true,
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			padCount, err := padding.PadCount(tc.block)
			
			if tc.shouldError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if padCount != tc.expectedPad {
					t.Errorf("Expected pad count %d, got %d", tc.expectedPad, padCount)
				}
			}
		})
	}
}

func TestPKCS7RoundTrip(t *testing.T) {
	padding := NewPKCS7Padding()
	blockSize := 16
	
	testCases := []int{0, 1, 7, 8, 15}
	
	for _, dataLen := range testCases {
		t.Run("", func(t *testing.T) {
			// Create a block with data
			block := make([]byte, blockSize)
			for i := 0; i < dataLen; i++ {
				block[i] = byte(i)
			}
			
			// Add padding
			padLen := padding.AddPadding(block, dataLen)
			
			// Verify padding
			count, err := padding.PadCount(block)
			if err != nil {
				t.Errorf("PadCount error: %v", err)
			}
			if count != padLen {
				t.Errorf("PadCount mismatch: expected %d, got %d", padLen, count)
			}
			
			// Verify data is intact
			for i := 0; i < dataLen; i++ {
				if block[i] != byte(i) {
					t.Errorf("Data corrupted at position %d", i)
				}
			}
		})
	}
}
