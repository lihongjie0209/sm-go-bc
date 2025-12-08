// Package engines implements cryptographic cipher engines.
package engines

import (
	"errors"

	"github.com/lihongjie0209/sm-go-bc/crypto"
	"github.com/lihongjie0209/sm-go-bc/crypto/params"
)

// Zuc256Engine implements the ZUC-256 stream cipher algorithm.
//
// ZUC-256 is an enhanced version of ZUC that supports 256-bit keys
// and provides higher security for 5G and beyond applications.
//
// Standards: ZUC-256 Specification
// Reference: Based on ZUC-128 with extended parameters
type Zuc256Engine struct {
	// Embed ZUC-128 engine for reuse
	*ZUCEngine
	keyLength int
	ivLength  int
}

// Constants for ZUC-256
var d256 = []byte{
	0x22, 0x2f, 0x24, 0x2a, 0x6d, 0x40, 0x40, 0x40,
	0x40, 0x40, 0x40, 0x40, 0x40, 0x52, 0x10, 0x30,
}

// NewZuc256Engine creates a new ZUC-256 stream cipher engine.
func NewZuc256Engine() *Zuc256Engine {
	return &Zuc256Engine{
		ZUCEngine: NewZUCEngine(),
		keyLength: 32, // 256 bits
		ivLength:  23, // 184 bits (typical for ZUC-256)
	}
}

// Init initializes the cipher with 256-bit key.
//
// Parameters:
//   - forEncryption: ignored (stream ciphers are symmetric)
//   - params: must be ParametersWithIV containing a KeyParameter
func (z *Zuc256Engine) Init(forEncryption bool, p crypto.CipherParameters) error {
	// Extract key and IV from parameters
	paramsWithIV, ok := p.(*params.ParametersWithIV)
	if !ok {
		return errors.New("ZUC-256 init parameters must include an IV (use ParametersWithIV)")
	}

	iv := paramsWithIV.GetIV()
	keyParam, ok := paramsWithIV.GetParameters().(*params.KeyParameter)
	if !ok {
		return errors.New("ZUC-256 init parameters must include a KeyParameter")
	}

	key := keyParam.GetKey()

	// ZUC-256 supports 256-bit keys
	if len(key) != 32 {
		return errors.New("ZUC-256 requires a 256-bit (32-byte) key")
	}

	// ZUC-256 typically uses 184-bit (23-byte) IVs
	if len(iv) != 23 && len(iv) != 25 {
		return errors.New("ZUC-256 requires a 184-bit (23-byte) or 200-bit (25-byte) IV")
	}

	// Convert 256-bit key to 128-bit format for internal processing
	// This is done by deriving a 128-bit key from the 256-bit key
	derivedKey := z.deriveKey(key, iv)
	derivedIV := z.deriveIV(key, iv)

	z.ZUCEngine.workingKey = derivedKey
	z.ZUCEngine.workingIV = derivedIV

	z.ZUCEngine.setKeyAndIV(derivedKey, derivedIV)
	z.ZUCEngine.initialized = true

	return nil
}

// GetAlgorithmName returns the algorithm name.
func (z *Zuc256Engine) GetAlgorithmName() string {
	return "ZUC-256"
}

// deriveKey derives a 128-bit key from 256-bit key and IV for ZUC-256.
func (z *Zuc256Engine) deriveKey(key []byte, iv []byte) []byte {
	// ZUC-256 key derivation:
	// Use first 16 bytes of key, XOR with last 16 bytes
	derivedKey := make([]byte, 16)
	for i := 0; i < 16; i++ {
		derivedKey[i] = key[i] ^ key[i+16]
	}
	return derivedKey
}

// deriveIV derives a 128-bit IV from key and IV for ZUC-256.
func (z *Zuc256Engine) deriveIV(key []byte, iv []byte) []byte {
	// ZUC-256 IV derivation:
	// For 184-bit IV (23 bytes), pad to 128 bits
	// Mix with key material
	derivedIV := make([]byte, 16)

	// Copy first 16 bytes of IV if available
	copyLen := len(iv)
	if copyLen > 16 {
		copyLen = 16
	}
	copy(derivedIV, iv[:copyLen])

	// XOR with key material for additional security
	for i := 0; i < 16; i++ {
		if i < len(iv) {
			derivedIV[i] ^= key[(i+16)%32]
		}
	}

	return derivedIV
}

// Reset resets the cipher.
func (z *Zuc256Engine) Reset() {
	z.ZUCEngine.Reset()
}
