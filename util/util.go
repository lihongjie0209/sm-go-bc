package util

import (
	"crypto/subtle"
)

// PadLeft pads a byte slice with zeros on the left to reach the target length
func PadLeft(data []byte, length int) []byte {
	if len(data) >= length {
		return data
	}
	padded := make([]byte, length)
	copy(padded[length-len(data):], data)
	return padded
}

// Concat concatenates multiple byte slices
func Concat(slices ...[]byte) []byte {
	var result []byte
	for _, slice := range slices {
		result = append(result, slice...)
	}
	return result
}

// ConstantTimeCompare compares two byte slices in constant time
func ConstantTimeCompare(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
