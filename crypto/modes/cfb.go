// Package modes implements block cipher modes of operation.
package modes

import (
	"github.com/lihongjie0209/sm-go-bc/crypto"
	"github.com/lihongjie0209/sm-go-bc/crypto/params"
)

// CFBBlockCipher implements Cipher Feedback (CFB) mode.
// Reference: NIST SP 800-38A, org.bouncycastle.crypto.modes.CFBBlockCipher
// Based on: sm-js-bc/src/crypto/modes/CFBBlockCipher.ts
type CFBBlockCipher struct {
	cipher          crypto.BlockCipher
	cipherBlockSize int
	blockSize       int

	IV       []byte
	cfbV     []byte
	cfbOutV  []byte
	inBuf    []byte

	encrypting bool
	byteCount  int
}

// NewCFBBlockCipher creates a new CFB mode cipher.
// bitBlockSize is the block size in bits (must be a multiple of 8).
// Common values are 8 (CFB8), 64 (CFB64), or 128 (CFB128).
func NewCFBBlockCipher(cipher crypto.BlockCipher, bitBlockSize int) *CFBBlockCipher {
	cipherBlockSize := cipher.GetBlockSize()

	if bitBlockSize > cipherBlockSize*8 || bitBlockSize < 8 || bitBlockSize%8 != 0 {
		panic("CFB bitBlockSize must be a multiple of 8 and <= cipher block size")
	}

	blockSize := bitBlockSize / 8

	return &CFBBlockCipher{
		cipher:          cipher,
		cipherBlockSize: cipherBlockSize,
		blockSize:       blockSize,
		IV:              make([]byte, cipherBlockSize),
		cfbV:            make([]byte, cipherBlockSize),
		cfbOutV:         make([]byte, cipherBlockSize),
		inBuf:           make([]byte, blockSize),
	}
}

// GetUnderlyingCipher returns the underlying block cipher.
func (c *CFBBlockCipher) GetUnderlyingCipher() crypto.BlockCipher {
	return c.cipher
}

// Init initializes the cipher and, possibly, the initialization vector (IV).
// If an IV isn't passed as part of the parameter, the IV will be all zeros.
// An IV which is too short is handled in FIPS compliant fashion.
func (c *CFBBlockCipher) Init(forEncryption bool, parameters crypto.CipherParameters) {
	c.encrypting = forEncryption

	var actualParams crypto.CipherParameters

	// Check if parameters include an IV
	if ivParams, ok := parameters.(*params.ParametersWithIV); ok {
		iv := ivParams.GetIV()

		if len(iv) < len(c.IV) {
			// Prepend the supplied IV with zeros (per FIPS PUB 81)
			for i := 0; i < len(c.IV)-len(iv); i++ {
				c.IV[i] = 0
			}
			copy(c.IV[len(c.IV)-len(iv):], iv)
		} else {
			copy(c.IV, iv)
		}

		actualParams = ivParams.GetParameters()
	} else {
		// No IV provided, use all zeros
		for i := range c.IV {
			c.IV[i] = 0
		}
		actualParams = parameters
	}

	c.Reset()

	// If actualParams is nil, it's an IV change only (key is to be reused)
	// Note: CFB always uses encryption mode in the underlying cipher
	if actualParams != nil {
		c.cipher.Init(true, actualParams)
	}
}

// GetAlgorithmName returns the algorithm name and mode.
func (c *CFBBlockCipher) GetAlgorithmName() string {
	return c.cipher.GetAlgorithmName() + "/CFB" + string(rune(c.blockSize*8))
}

// GetBlockSize returns the block size we are operating at (in bytes).
func (c *CFBBlockCipher) GetBlockSize() int {
	return c.blockSize
}

// ProcessBlock processes one block of input from the array in and writes it to out.
func (c *CFBBlockCipher) ProcessBlock(in []byte, inOff int, out []byte, outOff int) int {
	return c.ProcessBytes(in, inOff, c.blockSize, out, outOff)
}

// ProcessBytes processes multiple bytes in CFB mode.
func (c *CFBBlockCipher) ProcessBytes(in []byte, inOff int, length int, out []byte, outOff int) int {
	if inOff+length > len(in) {
		panic("input buffer too short")
	}

	if outOff+length > len(out) {
		panic("output buffer too short")
	}

	for i := 0; i < length; i++ {
		if c.encrypting {
			out[outOff+i] = c.encryptByte(in[inOff+i])
		} else {
			out[outOff+i] = c.decryptByte(in[inOff+i])
		}
	}

	return length
}

// encryptByte encrypts a single byte.
func (c *CFBBlockCipher) encryptByte(inputByte byte) byte {
	if c.byteCount == 0 {
		c.cipher.ProcessBlock(c.cfbV, 0, c.cfbOutV, 0)
	}

	rv := c.cfbOutV[c.byteCount] ^ inputByte
	c.inBuf[c.byteCount] = rv
	c.byteCount++

	if c.byteCount == c.blockSize {
		c.byteCount = 0

		// Shift cfbV left by blockSize bytes
		copy(c.cfbV, c.cfbV[c.blockSize:])
		// Copy inBuf to the end of cfbV
		copy(c.cfbV[len(c.cfbV)-c.blockSize:], c.inBuf)
	}

	return rv
}

// decryptByte decrypts a single byte.
func (c *CFBBlockCipher) decryptByte(inputByte byte) byte {
	if c.byteCount == 0 {
		c.cipher.ProcessBlock(c.cfbV, 0, c.cfbOutV, 0)
	}

	c.inBuf[c.byteCount] = inputByte
	rv := c.cfbOutV[c.byteCount] ^ inputByte
	c.byteCount++

	if c.byteCount == c.blockSize {
		c.byteCount = 0

		// Shift cfbV left by blockSize bytes
		copy(c.cfbV, c.cfbV[c.blockSize:])
		// Copy inBuf to the end of cfbV
		copy(c.cfbV[len(c.cfbV)-c.blockSize:], c.inBuf)
	}

	return rv
}

// GetCurrentIV returns the current state of the initialization vector.
func (c *CFBBlockCipher) GetCurrentIV() []byte {
	result := make([]byte, len(c.cfbV))
	copy(result, c.cfbV)
	return result
}

// Reset resets the chaining vector back to the IV and resets the underlying cipher.
func (c *CFBBlockCipher) Reset() {
	copy(c.cfbV, c.IV)
	for i := range c.inBuf {
		c.inBuf[i] = 0
	}
	c.byteCount = 0

	c.cipher.Reset()
}

// Ensure CFBBlockCipher implements BlockCipher interface
var _ crypto.BlockCipher = (*CFBBlockCipher)(nil)
