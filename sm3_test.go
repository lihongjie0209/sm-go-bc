package smgobc

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestSM3_Hash(t *testing.T) {
	sm3 := &SM3{}
	
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Empty string",
			input:    "",
			expected: "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b",
		},
		{
			name:     "abc",
			input:    "abc",
			expected: "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0",
		},
		{
			name:     "Sample message",
			input:    "message digest",
			expected: "c522a942e89bd80d97dd666e7a5531b36188c9817149e9b258dfe51ece98ed77",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash := sm3.Hash([]byte(tt.input))
			hashHex := hex.EncodeToString(hash)
			
			if hashHex != tt.expected {
				t.Errorf("Hash mismatch.\nExpected: %s\nGot: %s", tt.expected, hashHex)
			}
			
			// Verify hash length
			if len(hash) != 32 {
				t.Errorf("Expected hash length 32, got %d", len(hash))
			}
		})
	}
}

func TestSM3_Consistency(t *testing.T) {
	sm3 := &SM3{}
	
	data := []byte("The quick brown fox jumps over the lazy dog")
	
	hash1 := sm3.Hash(data)
	hash2 := sm3.Hash(data)
	
	if !bytes.Equal(hash1, hash2) {
		t.Error("Same input should produce same hash")
	}
}

func TestSM3_Different(t *testing.T) {
	sm3 := &SM3{}
	
	hash1 := sm3.Hash([]byte("data1"))
	hash2 := sm3.Hash([]byte("data2"))
	
	if bytes.Equal(hash1, hash2) {
		t.Error("Different inputs should produce different hashes")
	}
}
