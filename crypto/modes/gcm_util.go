// Package modes implements block cipher modes of operation.
package modes

import (
	"github.com/lihongjie0209/sm-go-bc/util"
)

// GCMUtil provides utility functions for GCM mode.
// Implements Galois field arithmetic for GCM authentication.
// Reference: org.bouncycastle.crypto.modes.gcm.GCMUtil
type GCMUtil struct{}

const (
	e1 = 0xe1000000
)

// XOR two 16-byte blocks.
func gcmXOR(block []byte, val []byte) {
	for i := 0; i < 16; i++ {
		block[i] ^= val[i]
	}
}

// GCMMultiply performs Galois field multiplication in GF(2^128).
// Multiplies two 128-bit blocks.
// This implements the algorithm from BouncyCastle's GCMUtil.java
func GCMMultiply(x []byte, y []byte) []byte {
	// Convert to 32-bit int arrays (4 ints = 128 bits)
	xInts := make([]uint32, 4)
	yInts := make([]uint32, 4)
	
	for i := 0; i < 4; i++ {
		offset := i * 4
		xInts[i] = util.BigEndianToUint32(x, offset)
		yInts[i] = util.BigEndianToUint32(y, offset)
	}
	
	y0, y1, y2, y3 := yInts[0], yInts[1], yInts[2], yInts[3]
	var z0, z1, z2, z3 uint32
	
	// Process each bit of x
	for i := 0; i < 4; i++ {
		bits := xInts[i]
		for j := 0; j < 32; j++ {
			// m1 is -1 (all 1s) if MSB is set, 0 otherwise
			m1 := uint32(int32(bits) >> 31)
			bits <<= 1
			
			z0 ^= (y0 & m1)
			z1 ^= (y1 & m1)
			z2 ^= (y2 & m1)
			z3 ^= (y3 & m1)
			
			// Shift y right with reduction polynomial
			m2 := uint32((int32(y3<<31) >> 8))
			y3 = (y3 >> 1) | (y2 << 31)
			y2 = (y2 >> 1) | (y1 << 31)
			y1 = (y1 >> 1) | (y0 << 31)
			y0 = (y0 >> 1) ^ (m2 & e1)
		}
	}
	
	// Convert result back to bytes
	result := make([]byte, 16)
	zInts := []uint32{z0, z1, z2, z3}
	for i := 0; i < 4; i++ {
		util.Uint32ToBigEndian(zInts[i], result, i*4)
	}
	
	return result
}

// GCMIncrement increments the rightmost 32 bits of a counter block.
func GCMIncrement(counter []byte) {
	c := uint32(1)
	for i := 15; i >= 12; i-- {
		c += uint32(counter[i])
		counter[i] = byte(c)
		c >>= 8
	}
}
