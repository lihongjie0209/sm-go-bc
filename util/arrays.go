// Package util provides utility functions for SM cryptographic algorithms.
package util

// Arrays provides array manipulation utilities.
// Reference: org.bouncycastle.util.Arrays (bc-java)

// AreEqual returns true if the two byte slices have identical contents
func AreEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ConstantTimeAreEqual performs a constant-time comparison of two byte slices
func ConstantTimeAreEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	
	v := byte(0)
	for i := range a {
		v |= a[i] ^ b[i]
	}
	
	return v == 0
}

// Clone creates a copy of the byte slice
func Clone(data []byte) []byte {
	if data == nil {
		return nil
	}
	result := make([]byte, len(data))
	copy(result, data)
	return result
}

// Fill fills the slice with the specified value
func Fill(a []byte, val byte) {
	for i := range a {
		a[i] = val
	}
}

// Clear clears the byte slice (fills with zeros)
func Clear(data []byte) {
	Fill(data, 0)
}

// CopyOf creates a new slice with the specified length, copying data from the original
func CopyOf(data []byte, newLength int) []byte {
	result := make([]byte, newLength)
	copy(result, data)
	return result
}

// CopyOfRange creates a new slice containing the specified range from the original
func CopyOfRange(data []byte, from, to int) []byte {
	newLength := to - from
	result := make([]byte, newLength)
	copy(result, data[from:to])
	return result
}

// Append appends multiple byte slices together
func Append(a []byte, b ...[]byte) []byte {
	result := Clone(a)
	for _, bytes := range b {
		result = append(result, bytes...)
	}
	return result
}

// Concatenate concatenates multiple byte slices into a single slice
func Concatenate(arrays ...[]byte) []byte {
	totalLength := 0
	for _, array := range arrays {
		totalLength += len(array)
	}
	
	result := make([]byte, totalLength)
	pos := 0
	for _, array := range arrays {
		copy(result[pos:], array)
		pos += len(array)
	}
	
	return result
}

// Reverse reverses the byte slice in place
func Reverse(a []byte) {
	for i, j := 0, len(a)-1; i < j; i, j = i+1, j-1 {
		a[i], a[j] = a[j], a[i]
	}
}

// AreEqualUint32 returns true if the two uint32 slices have identical contents
func AreEqualUint32(a, b []uint32) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// CloneUint32 creates a copy of the uint32 slice
func CloneUint32(data []uint32) []uint32 {
	if data == nil {
		return nil
	}
	result := make([]uint32, len(data))
	copy(result, data)
	return result
}

// FillUint32 fills the slice with the specified value
func FillUint32(a []uint32, val uint32) {
	for i := range a {
		a[i] = val
	}
}
