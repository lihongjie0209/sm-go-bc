// Package modes implements block cipher modes of operation.
package modes

import (
	"github.com/lihongjie0209/sm-go-bc/crypto"
)

// ECBBlockCipher implements Electronic Codebook (ECB) mode.
//
// ⚠️ WARNING: ECB mode is NOT SECURE and should NOT be used in production!
//
// ECB mode encrypts each block independently, which means:
// - Identical plaintext blocks always produce identical ciphertext blocks
// - This reveals patterns in the data (information leakage)
// - No diffusion across blocks
// - Vulnerable to various attacks
//
// This implementation is provided ONLY for:
// - Compatibility with legacy systems
// - Testing and educational purposes
//
// For secure encryption, use CBC, CTR, GCM, or other modern modes.
//
// Reference: NIST SP 800-38A, org.bouncycastle.crypto.modes.ECBBlockCipher
type ECBBlockCipher struct {
	cipher    crypto.BlockCipher
	blockSize int
}

// NewECBBlockCipher creates a new ECB mode cipher.
//
// ⚠️ WARNING: Do not use ECB mode for production encryption!
func NewECBBlockCipher(cipher crypto.BlockCipher) *ECBBlockCipher {
	return &ECBBlockCipher{
		cipher:    cipher,
		blockSize: cipher.GetBlockSize(),
	}
}

// GetUnderlyingCipher returns the underlying block cipher.
func (e *ECBBlockCipher) GetUnderlyingCipher() crypto.BlockCipher {
	return e.cipher
}

// Init initializes the cipher for encryption or decryption.
//
// Parameters:
//   - forEncryption: true for encryption, false for decryption
//   - params: cipher parameters (typically KeyParameter)
func (e *ECBBlockCipher) Init(forEncryption bool, params crypto.CipherParameters) {
	e.cipher.Init(forEncryption, params)
}

// GetAlgorithmName returns the algorithm name and mode.
func (e *ECBBlockCipher) GetAlgorithmName() string {
	return e.cipher.GetAlgorithmName() + "/ECB"
}

// GetBlockSize returns the block size in bytes.
func (e *ECBBlockCipher) GetBlockSize() int {
	return e.blockSize
}

// ProcessBlock processes one block of data.
//
// ECB mode simply passes through to the underlying cipher with no chaining.
// Each block is encrypted/decrypted independently.
func (e *ECBBlockCipher) ProcessBlock(in []byte, inOff int, out []byte, outOff int) int {
	if inOff+e.blockSize > len(in) {
		panic("input buffer too short")
	}

	if outOff+e.blockSize > len(out) {
		panic("output buffer too short")
	}

	return e.cipher.ProcessBlock(in, inOff, out, outOff)
}

// Reset resets the cipher to its initial state.
func (e *ECBBlockCipher) Reset() {
	e.cipher.Reset()
}

// Ensure ECBBlockCipher implements BlockCipher interface
var _ crypto.BlockCipher = (*ECBBlockCipher)(nil)
