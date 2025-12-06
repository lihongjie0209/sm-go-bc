// Package util provides utility functions for SM cryptographic algorithms.
// This mirrors Bouncy Castle's org.bouncycastle.util.Pack
package util

import (
	"encoding/binary"
	"math/big"
)

// Pack provides byte packing and unpacking utilities.
// Reference: org.bouncycastle.util.Pack (bc-java)

// BigEndianToUint32 unpacks a uint32 from big-endian bytes
func BigEndianToUint32(bs []byte, off int) uint32 {
	return binary.BigEndian.Uint32(bs[off:])
}

// Uint32ToBigEndian packs a uint32 into big-endian bytes
func Uint32ToBigEndian(n uint32, bs []byte, off int) {
	binary.BigEndian.PutUint32(bs[off:], n)
}

// BigEndianToUint64 unpacks a uint64 from big-endian bytes
func BigEndianToUint64(bs []byte, off int) uint64 {
	return binary.BigEndian.Uint64(bs[off:])
}

// Uint64ToBigEndian packs a uint64 into big-endian bytes
func Uint64ToBigEndian(n uint64, bs []byte, off int) {
	binary.BigEndian.PutUint64(bs[off:], n)
}

// LittleEndianToUint32 unpacks a uint32 from little-endian bytes
func LittleEndianToUint32(bs []byte, off int) uint32 {
	return binary.LittleEndian.Uint32(bs[off:])
}

// Uint32ToLittleEndian packs a uint32 into little-endian bytes
func Uint32ToLittleEndian(n uint32, bs []byte, off int) {
	binary.LittleEndian.PutUint32(bs[off:], n)
}

// LittleEndianToUint64 unpacks a uint64 from little-endian bytes
func LittleEndianToUint64(bs []byte, off int) uint64 {
	return binary.LittleEndian.Uint64(bs[off:])
}

// Uint64ToLittleEndian packs a uint64 into little-endian bytes
func Uint64ToLittleEndian(n uint64, bs []byte, off int) {
	binary.LittleEndian.PutUint64(bs[off:], n)
}

// Uint32ArrayToBigEndian converts a uint32 array to big-endian bytes
func Uint32ArrayToBigEndian(ns []uint32, bs []byte, off int) {
	for i, n := range ns {
		Uint32ToBigEndian(n, bs, off+i*4)
	}
}

// BigEndianToUint32Array converts big-endian bytes to a uint32 array
func BigEndianToUint32Array(bs []byte, off int, ns []uint32) {
	for i := range ns {
		ns[i] = BigEndianToUint32(bs, off+i*4)
	}
}

// Uint32ArrayToLittleEndian converts a uint32 array to little-endian bytes
func Uint32ArrayToLittleEndian(ns []uint32, bs []byte, off int) {
	for i, n := range ns {
		Uint32ToLittleEndian(n, bs, off+i*4)
	}
}

// LittleEndianToUint32Array converts little-endian bytes to a uint32 array
func LittleEndianToUint32Array(bs []byte, off int, ns []uint32) {
	for i := range ns {
		ns[i] = LittleEndianToUint32(bs, off+i*4)
	}
}

// IntToBytes converts an integer to 4-byte big-endian representation.
func IntToBytes(n int) []byte {
	bs := make([]byte, 4)
	Uint32ToBigEndian(uint32(n), bs, 0)
	return bs
}

// BigIntToBytes converts a big.Int to bytes with specified length (big-endian).
// If the value is shorter, it will be left-padded with zeros.
func BigIntToBytes(n *big.Int, length int) []byte {
	bytes := n.Bytes() // Big-endian representation
	if len(bytes) >= length {
		return bytes[len(bytes)-length:]
	}
	// Pad with zeros on the left
	padded := make([]byte, length)
	copy(padded[length-len(bytes):], bytes)
	return padded
}
