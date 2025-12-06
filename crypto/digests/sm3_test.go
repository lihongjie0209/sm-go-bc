package digests

import (
	"encoding/hex"
	"testing"
)

// Basic Properties Tests
func TestSM3AlgorithmName(t *testing.T) {
	digest := NewSM3Digest()
	if digest.GetAlgorithmName() != "SM3" {
		t.Errorf("Expected algorithm name 'SM3', got '%s'", digest.GetAlgorithmName())
	}
}

func TestSM3DigestSize(t *testing.T) {
	digest := NewSM3Digest()
	if digest.GetDigestSize() != 32 {
		t.Errorf("Expected digest size 32, got %d", digest.GetDigestSize())
	}
}

func TestSM3ByteLength(t *testing.T) {
	digest := NewSM3Digest()
	if digest.GetByteLength() != 64 {
		t.Errorf("Expected byte length 64, got %d", digest.GetByteLength())
	}
}

// GB/T 32905-2016 Test Vectors
func TestSM3ABC(t *testing.T) {
	digest := NewSM3Digest()
	data := []byte("abc")
	digest.BlockUpdate(data, 0, len(data))
	output := make([]byte, 32)
	digest.DoFinal(output, 0)
	
	expected := "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
	actual := hex.EncodeToString(output)
	
	if actual != expected {
		t.Errorf("SM3 'abc' hash mismatch\nExpected: %s\nActual:   %s", expected, actual)
	}
}

func TestSM3LongString(t *testing.T) {
	data := []byte("abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd")
	digest := NewSM3Digest()
	digest.BlockUpdate(data, 0, len(data))
	output := make([]byte, 32)
	digest.DoFinal(output, 0)
	
	expected := "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732"
	actual := hex.EncodeToString(output)
	
	if actual != expected {
		t.Errorf("SM3 64-byte message hash mismatch\nExpected: %s\nActual:   %s", expected, actual)
	}
}

func TestSM3EmptyString(t *testing.T) {
	digest := NewSM3Digest()
	output := make([]byte, 32)
	digest.DoFinal(output, 0)
	
	expected := "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b"
	actual := hex.EncodeToString(output)
	
	if actual != expected {
		t.Errorf("SM3 empty string hash mismatch\nExpected: %s\nActual:   %s", expected, actual)
	}
}

func TestSM3SingleByte(t *testing.T) {
	digest := NewSM3Digest()
	digest.Update(0x61) // 'a'
	output := make([]byte, 32)
	digest.DoFinal(output, 0)
	
	expected := "623476ac18f65a2909e43c7fec61b49c7e764a91a18ccb82f1917a29c86c5e88"
	actual := hex.EncodeToString(output)
	
	if actual != expected {
		t.Errorf("SM3 single byte hash mismatch\nExpected: %s\nActual:   %s", expected, actual)
	}
}

// Update Methods Tests
func TestSM3SingleByteUpdates(t *testing.T) {
	digest := NewSM3Digest()
	digest.Update(0x61) // 'a'
	digest.Update(0x62) // 'b'
	digest.Update(0x63) // 'c'
	output := make([]byte, 32)
	digest.DoFinal(output, 0)
	
	expected := "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
	actual := hex.EncodeToString(output)
	
	if actual != expected {
		t.Errorf("SM3 single byte updates hash mismatch\nExpected: %s\nActual:   %s", expected, actual)
	}
}

func TestSM3ArrayUpdates(t *testing.T) {
	digest := NewSM3Digest()
	data := []byte("abc")
	digest.BlockUpdate(data, 0, len(data))
	output := make([]byte, 32)
	digest.DoFinal(output, 0)
	
	expected := "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
	actual := hex.EncodeToString(output)
	
	if actual != expected {
		t.Errorf("SM3 array updates hash mismatch\nExpected: %s\nActual:   %s", expected, actual)
	}
}

func TestSM3MixedUpdates(t *testing.T) {
	digest := NewSM3Digest()
	digest.Update(0x61) // 'a'
	digest.BlockUpdate([]byte("bc"), 0, 2)
	output := make([]byte, 32)
	digest.DoFinal(output, 0)
	
	expected := "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
	actual := hex.EncodeToString(output)
	
	if actual != expected {
		t.Errorf("SM3 mixed updates hash mismatch\nExpected: %s\nActual:   %s", expected, actual)
	}
}

// Reset Tests
func TestSM3Reset(t *testing.T) {
	digest := NewSM3Digest()
	data := []byte("abc")
	digest.BlockUpdate(data, 0, len(data))
	output1 := make([]byte, 32)
	digest.DoFinal(output1, 0)
	
	digest.Reset()
	digest.BlockUpdate(data, 0, len(data))
	output2 := make([]byte, 32)
	digest.DoFinal(output2, 0)
	
	expected := "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
	actual := hex.EncodeToString(output2)
	
	if actual != expected || hex.EncodeToString(output1) != hex.EncodeToString(output2) {
		t.Errorf("SM3 reset test failed")
	}
}

func TestSM3AutoResetAfterDoFinal(t *testing.T) {
	digest := NewSM3Digest()
	data := []byte("abc")
	
	digest.BlockUpdate(data, 0, len(data))
	output1 := make([]byte, 32)
	digest.DoFinal(output1, 0)
	
	digest.BlockUpdate(data, 0, len(data))
	output2 := make([]byte, 32)
	digest.DoFinal(output2, 0)
	
	if hex.EncodeToString(output1) != hex.EncodeToString(output2) {
		t.Error("SM3 auto-reset after DoFinal failed")
	}
}

// Memoable (Copy) Tests
func TestSM3Copy(t *testing.T) {
	digest1 := NewSM3Digest()
	digest1.BlockUpdate([]byte("a"), 0, 1)
	
	digest2 := NewSM3DigestFromCopy(digest1)
	
	digest1.BlockUpdate([]byte("bc"), 0, 2)
	output1 := make([]byte, 32)
	digest1.DoFinal(output1, 0)
	
	digest2.BlockUpdate([]byte("bc"), 0, 2)
	output2 := make([]byte, 32)
	digest2.DoFinal(output2, 0)
	
	for i := range output1 {
		if output1[i] != output2[i] {
			t.Errorf("SM3 copy test failed: outputs don't match at index %d", i)
			break
		}
	}
}

func TestSM3GetAlgorithmName(t *testing.T) {
	digest := NewSM3Digest()
	if digest.GetAlgorithmName() != "SM3" {
		t.Errorf("Expected algorithm name 'SM3', got '%s'", digest.GetAlgorithmName())
	}
}

func TestSM3GetDigestSize(t *testing.T) {
	digest := NewSM3Digest()
	if digest.GetDigestSize() != 32 {
		t.Errorf("Expected digest size 32, got %d", digest.GetDigestSize())
	}
}

// Large Messages Tests
func TestSM3LargerThanOneBlock(t *testing.T) {
	input := make([]byte, 128) // 2 blocks
	for i := range input {
		input[i] = byte(i & 0xff)
	}
	
	digest := NewSM3Digest()
	digest.BlockUpdate(input, 0, len(input))
	output := make([]byte, 32)
	digest.DoFinal(output, 0)
	
	if len(output) != 32 {
		t.Errorf("Expected 32-byte hash, got %d bytes", len(output))
	}
}

func TestSM3VeryLargeMessage(t *testing.T) {
	input := make([]byte, 1024) // 1KB
	for i := range input {
		input[i] = byte((i * 31) & 0xff)
	}
	
	digest := NewSM3Digest()
	digest.BlockUpdate(input, 0, len(input))
	output := make([]byte, 32)
	digest.DoFinal(output, 0)
	
	if len(output) != 32 {
		t.Errorf("Expected 32-byte hash, got %d bytes", len(output))
	}
}

// Edge Cases Tests
func TestSM3ExactBlockSize(t *testing.T) {
	input := make([]byte, 64) // Exactly one block
	for i := range input {
		input[i] = 0x42
	}
	
	digest := NewSM3Digest()
	digest.BlockUpdate(input, 0, len(input))
	output := make([]byte, 32)
	digest.DoFinal(output, 0)
	
	if len(output) != 32 {
		t.Errorf("Expected 32-byte hash, got %d bytes", len(output))
	}
}

func TestSM3BlockBoundaries(t *testing.T) {
	sizes := []int{63, 64, 65, 127, 128, 129}
	
	for _, size := range sizes {
		input := make([]byte, size)
		for i := range input {
			input[i] = 0x61 // 'a'
		}
		
		digest := NewSM3Digest()
		digest.BlockUpdate(input, 0, len(input))
		output := make([]byte, 32)
		digest.DoFinal(output, 0)
		
		if len(output) != 32 {
			t.Errorf("Size %d: Expected 32-byte hash, got %d bytes", size, len(output))
		}
	}
}

func TestSM3DifferentInputsDifferentHashes(t *testing.T) {
	input1 := []byte("abc")
	input2 := []byte("abd")
	
	digest1 := NewSM3Digest()
	digest1.BlockUpdate(input1, 0, len(input1))
	output1 := make([]byte, 32)
	digest1.DoFinal(output1, 0)
	
	digest2 := NewSM3Digest()
	digest2.BlockUpdate(input2, 0, len(input2))
	output2 := make([]byte, 32)
	digest2.DoFinal(output2, 0)
	
	if hex.EncodeToString(output1) == hex.EncodeToString(output2) {
		t.Error("Different inputs should produce different hashes")
	}
}

func TestSM3Deterministic(t *testing.T) {
	input := []byte("test message")
	
	digest1 := NewSM3Digest()
	digest1.BlockUpdate(input, 0, len(input))
	output1 := make([]byte, 32)
	digest1.DoFinal(output1, 0)
	
	digest2 := NewSM3Digest()
	digest2.BlockUpdate(input, 0, len(input))
	output2 := make([]byte, 32)
	digest2.DoFinal(output2, 0)
	
	if hex.EncodeToString(output1) != hex.EncodeToString(output2) {
		t.Error("Same input should always produce same hash")
	}
}

// Benchmark tests
func BenchmarkSM3Short(b *testing.B) {
	data := []byte("abc")
	output := make([]byte, 32)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		digest := NewSM3Digest()
		digest.BlockUpdate(data, 0, len(data))
		digest.DoFinal(output, 0)
	}
}

func BenchmarkSM3Long(b *testing.B) {
	data := make([]byte, 1024)
	for i := range data {
		data[i] = byte(i % 256)
	}
	output := make([]byte, 32)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		digest := NewSM3Digest()
		digest.BlockUpdate(data, 0, len(data))
		digest.DoFinal(output, 0)
	}
}
