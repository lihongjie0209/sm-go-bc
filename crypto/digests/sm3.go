// Package digests implements cryptographic hash functions.
package digests

import (
	"github.com/lihongjie0209/sm-go-bc/crypto"
	"github.com/lihongjie0209/sm-go-bc/util"
)

// SM3Digest implements the SM3 cryptographic hash function.
// Reference: GM/T 0004-2012
// Based on: sm-py-bc/src/sm_bc/crypto/digests/sm3_digest.py
//           sm-js-bc/src/crypto/digests/SM3Digest.ts
type SM3Digest struct {
	v         [8]uint32   // Internal state
	inwords   [16]uint32  // Input buffer (16 words)
	xOff      int         // Current position in inwords
	w         [68]uint32  // Message expansion buffer
	xBuf      [4]byte     // Byte buffer
	xBufOff   int         // Position in byte buffer
	byteCount int64       // Total bytes processed
}

const (
	sm3DigestLength = 32
	sm3BlockSize    = 16 // 16 words = 64 bytes
)

// SM3 IV (Initial Values)
var sm3IV = [8]uint32{
	0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
	0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E,
}

// SM3 T constants (precomputed rotations)
var sm3T [64]uint32

func init() {
	// Initialize T constants
	// For j = 0 to 15: T = ROTL(0x79CC4519, j)
	t := uint32(0x79CC4519)
	for i := 0; i < 16; i++ {
		sm3T[i] = (t << uint(i)) | (t >> uint(32-i))
	}
	// For j = 16 to 63: T = ROTL(0x7A879D8A, j mod 32)
	t = 0x7A879D8A
	for i := 16; i < 64; i++ {
		n := i % 32
		sm3T[i] = (t << uint(n)) | (t >> uint(32-n))
	}
}

// NewSM3Digest creates a new SM3 digest instance.
func NewSM3Digest() *SM3Digest {
	d := &SM3Digest{}
	d.Reset()
	return d
}

// NewSM3DigestFromCopy creates a copy of an existing SM3 digest.
func NewSM3DigestFromCopy(other *SM3Digest) *SM3Digest {
	d := &SM3Digest{}
	d.copyFrom(other)
	return d
}

// GetAlgorithmName returns the algorithm name.
func (d *SM3Digest) GetAlgorithmName() string {
	return "SM3"
}

// GetDigestSize returns the size of the digest in bytes.
func (d *SM3Digest) GetDigestSize() int {
	return sm3DigestLength
}

// GetByteLength returns the byte length of the internal buffer (block size in bytes).
func (d *SM3Digest) GetByteLength() int {
	return sm3BlockSize * 4 // 16 words * 4 bytes = 64 bytes
}

// Update adds a single byte to the digest.
func (d *SM3Digest) Update(in byte) {
	d.xBuf[d.xBufOff] = in
	d.xBufOff++
	if d.xBufOff == 4 {
		d.processWord(d.xBuf[:], 0)
		d.xBufOff = 0
	}
	d.byteCount++
}

// BlockUpdate adds multiple bytes to the digest.
func (d *SM3Digest) BlockUpdate(in []byte, inOff int, length int) {
	limit := inOff + length
	
	// Fill the byte buffer first
	for d.xBufOff != 0 && inOff < limit {
		d.Update(in[inOff])
		inOff++
	}
	
	// Process full 4-byte words directly
	for inOff <= limit-4 {
		d.processWord(in, inOff)
		inOff += 4
		d.byteCount += 4
	}
	
	// Buffer remaining bytes
	for inOff < limit {
		d.Update(in[inOff])
		inOff++
	}
}

// DoFinal completes the hash computation and returns the digest.
func (d *SM3Digest) DoFinal(out []byte, outOff int) int {
	d.finish()
	
	// Write output
	for i := 0; i < 8; i++ {
		util.Uint32ToBigEndian(d.v[i], out, outOff+i*4)
	}
	
	d.Reset()
	return sm3DigestLength
}

// Reset resets the digest to its initial state.
func (d *SM3Digest) Reset() {
	d.byteCount = 0
	d.xBufOff = 0
	for i := range d.xBuf {
		d.xBuf[i] = 0
	}
	
	// Reset state to IV
	copy(d.v[:], sm3IV[:])
	d.xOff = 0
	for i := range d.inwords {
		d.inwords[i] = 0
	}
}

// Copy creates a copy of the digest (implements Memoable).
func (d *SM3Digest) Copy() crypto.Memoable {
	return NewSM3DigestFromCopy(d)
}

// ResetMemoable resets from another Memoable instance.
func (d *SM3Digest) ResetMemoable(other crypto.Memoable) {
	if otherDigest, ok := other.(*SM3Digest); ok {
		d.copyFrom(otherDigest)
	}
}

// copyFrom copies state from another digest.
func (d *SM3Digest) copyFrom(other *SM3Digest) {
	copy(d.v[:], other.v[:])
	copy(d.inwords[:], other.inwords[:])
	d.xOff = other.xOff
	copy(d.xBuf[:], other.xBuf[:])
	d.xBufOff = other.xBufOff
	d.byteCount = other.byteCount
	// w is scratch space, no need to copy
}

// finish performs padding and final processing.
func (d *SM3Digest) finish() {
	bitLength := d.byteCount << 3
	
	// Add padding: 1 bit followed by zeros
	d.Update(0x80)
	
	// Pad with zeros until we can add the length
	for d.xBufOff != 0 {
		d.Update(0)
	}
	
	d.processLength(bitLength)
	d.processBlock()
}

// processWord processes a 4-byte word from the input.
func (d *SM3Digest) processWord(input []byte, offset int) {
	d.inwords[d.xOff] = util.BigEndianToUint32(input, offset)
	d.xOff++
	if d.xOff >= 16 {
		d.processBlock()
	}
}

// processLength appends the message length to the buffer.
func (d *SM3Digest) processLength(bitLength int64) {
	if d.xOff > 14 {
		d.inwords[d.xOff] = 0
		d.xOff++
		d.processBlock()
	}
	
	for d.xOff < 14 {
		d.inwords[d.xOff] = 0
		d.xOff++
	}
	
	// Length is 64-bit, written as two 32-bit words (Big Endian)
	d.inwords[d.xOff] = uint32(bitLength >> 32)
	d.xOff++
	d.inwords[d.xOff] = uint32(bitLength & 0xFFFFFFFF)
	d.xOff++
}

// processBlock performs the SM3 compression function.
func (d *SM3Digest) processBlock() {
	// 1. Message Expansion
	// First 16 words are from input
	for j := 0; j < 16; j++ {
		d.w[j] = d.inwords[j]
	}
	
	// Expand to 68 words
	for j := 16; j < 68; j++ {
		wj3 := d.w[j-3]
		r15 := (wj3 << 15) | (wj3 >> 17)
		wj13 := d.w[j-13]
		r7 := (wj13 << 7) | (wj13 >> 25)
		
		tmp := d.w[j-16] ^ d.w[j-9] ^ r15
		p1 := tmp ^ ((tmp << 15) | (tmp >> 17)) ^ ((tmp << 23) | (tmp >> 9))
		
		d.w[j] = p1 ^ r7 ^ d.w[j-6]
	}
	
	// 2. Compression
	A, B, C, D, E, F, G, H := d.v[0], d.v[1], d.v[2], d.v[3], d.v[4], d.v[5], d.v[6], d.v[7]
	
	for j := 0; j < 64; j++ {
		// ROTL(A, 12)
		a12 := (A << 12) | (A >> 20)
		
		// SS1
		s1 := a12 + E + sm3T[j]
		ss1 := (s1 << 7) | (s1 >> 25)
		
		// SS2
		ss2 := ss1 ^ a12
		
		Wj := d.w[j]
		W1j := Wj ^ d.w[j+4]
		
		// TT1, TT2
		var ff, gg uint32
		if j < 16 {
			// FF0, GG0
			ff = A ^ B ^ C
			gg = E ^ F ^ G
		} else {
			// FF1, GG1
			ff = (A & B) | (A & C) | (B & C)
			gg = (E & F) | (^E & G)
		}
		
		tt1 := ff + D + ss2 + W1j
		tt2 := gg + H + ss1 + Wj
		
		D = C
		C = (B << 9) | (B >> 23)
		B = A
		A = tt1
		H = G
		G = (F << 19) | (F >> 13)
		F = E
		// P0(tt2)
		E = tt2 ^ ((tt2 << 9) | (tt2 >> 23)) ^ ((tt2 << 17) | (tt2 >> 15))
	}
	
	// 3. Update state
	d.v[0] ^= A
	d.v[1] ^= B
	d.v[2] ^= C
	d.v[3] ^= D
	d.v[4] ^= E
	d.v[5] ^= F
	d.v[6] ^= G
	d.v[7] ^= H
	
	d.xOff = 0
}

// Ensure SM3Digest implements the Digest interface
var _ crypto.Digest = (*SM3Digest)(nil)
var _ crypto.Memoable = (*SM3Digest)(nil)
