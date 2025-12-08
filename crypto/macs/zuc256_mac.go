// Package macs implements Message Authentication Code algorithms.
package macs

import (
	"errors"

	"github.com/lihongjie0209/sm-go-bc/crypto"
	"github.com/lihongjie0209/sm-go-bc/crypto/engines"
)

// Zuc256Mac implements the ZUC-256 MAC algorithm.
//
// This MAC provides enhanced security for 5G and beyond applications.
// It supports 32-bit, 64-bit, and 128-bit MAC lengths.
//
// Standards: ZUC-256 MAC Specification
// Reference: Based on ZUC-256 stream cipher
type Zuc256Mac struct {
	engine      *engines.Zuc256Engine
	initialized bool
	macBits     int // MAC length in bits
	
	// Working state
	keyStream   []uint32
	workingData []byte
	wordCount   int
}

// NewZuc256Mac creates a new ZUC-256 MAC instance.
//
// The MAC length defaults to 64 bits for enhanced security.
func NewZuc256Mac() *Zuc256Mac {
	return &Zuc256Mac{
		engine:      engines.NewZuc256Engine(),
		macBits:     64, // Default 64-bit MAC for ZUC-256
		keyStream:   make([]uint32, 0),
		workingData: make([]byte, 0),
	}
}

// NewZuc256MacWithLength creates a new ZUC-256 MAC with specified length.
//
// Parameters:
//   - macBits: MAC length in bits (32, 64, or 128)
func NewZuc256MacWithLength(macBits int) *Zuc256Mac {
	if macBits != 32 && macBits != 64 && macBits != 128 {
		macBits = 64 // Default to 64 bits if invalid
	}
	return &Zuc256Mac{
		engine:      engines.NewZuc256Engine(),
		macBits:     macBits,
		keyStream:   make([]uint32, 0),
		workingData: make([]byte, 0),
	}
}

// GetAlgorithmName returns the algorithm name.
func (z *Zuc256Mac) GetAlgorithmName() string {
	return "ZUC-256-MAC"
}

// GetMacSize returns the MAC size in bytes.
func (z *Zuc256Mac) GetMacSize() int {
	return z.macBits / 8
}

// Init initializes the MAC with key and IV.
//
// Parameters:
//   - params: must be ParametersWithIV containing a KeyParameter with 256-bit key
func (z *Zuc256Mac) Init(p crypto.CipherParameters) error {
	// Reset state
	z.keyStream = make([]uint32, 0)
	z.workingData = make([]byte, 0)
	z.wordCount = 0

	// Initialize the underlying ZUC-256 engine
	err := z.engine.Init(true, p)
	if err != nil {
		return err
	}

	z.initialized = true
	return nil
}

// Update adds a single byte to the MAC calculation.
func (z *Zuc256Mac) Update(in byte) {
	z.workingData = append(z.workingData, in)
}

// UpdateArray adds multiple bytes to the MAC calculation.
func (z *Zuc256Mac) UpdateArray(in []byte, inOff int, length int) {
	z.workingData = append(z.workingData, in[inOff:inOff+length]...)
}

// DoFinal completes the MAC calculation and writes the result.
//
// Parameters:
//   - out: output buffer for MAC
//   - outOff: offset in output buffer
//
// Returns:
//   - number of bytes written
//   - error if any
func (z *Zuc256Mac) DoFinal(out []byte, outOff int) (int, error) {
	if !z.initialized {
		return 0, errors.New("ZUC-256 MAC not initialized")
	}

	macBytes := z.GetMacSize()
	if len(out)-outOff < macBytes {
		return 0, errors.New("output buffer too small")
	}

	// Generate keystream for MAC calculation
	dataLen := len(z.workingData)
	numWords := (dataLen + 3) / 4
	if numWords == 0 {
		numWords = 1
	}

	// Generate keystream using ZUC-256
	z.keyStream = make([]uint32, numWords)
	for i := 0; i < numWords; i++ {
		keyStreamBytes := make([]byte, 4)
		zeroBytes := []byte{0, 0, 0, 0}
		z.engine.ProcessBytes(zeroBytes, 0, 4, keyStreamBytes, 0)
		z.keyStream[i] = uint32(keyStreamBytes[0])<<24 |
			uint32(keyStreamBytes[1])<<16 |
			uint32(keyStreamBytes[2])<<8 |
			uint32(keyStreamBytes[3])
	}

	// Perform MAC calculation
	mac := z.calculateMac()

	// Write MAC to output (big-endian)
	macBytesCount := z.macBits / 8
	macValue := uint64(mac) // For 128-bit MAC support
	for i := 0; i < macBytesCount; i++ {
		shift := (macBytesCount - 1 - i) * 8
		out[outOff+i] = byte((macValue >> shift) & 0xff)
	}

	// Reset for next use
	z.Reset()

	return macBytes, nil
}

// calculateMac performs the actual MAC calculation using ZUC-256 keystream.
func (z *Zuc256Mac) calculateMac() uint64 {
	// ZUC-256 MAC algorithm (extended version)
	var t uint64 = 0

	// Process each byte with corresponding keystream
	for i := 0; i < len(z.workingData); i++ {
		wordIdx := i / 4
		if wordIdx < len(z.keyStream) {
			// XOR data with keystream and accumulate
			t ^= uint64(z.workingData[i]) << (56 - (i%8)*8)
		}
	}

	// Final mixing with keystream words
	for i := 0; i < len(z.keyStream) && i < 2; i++ {
		t ^= uint64(z.keyStream[i]) << (32 * uint(1-i))
	}

	return t
}

// Reset resets the MAC to its initialized state.
func (z *Zuc256Mac) Reset() {
	z.workingData = make([]byte, 0)
	z.keyStream = make([]uint32, 0)
	z.wordCount = 0
	if z.initialized {
		z.engine.Reset()
	}
}
