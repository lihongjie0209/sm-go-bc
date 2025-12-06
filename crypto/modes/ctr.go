// Package modes implements block cipher modes of operation.
package modes

import (
	"github.com/lihongjie0209/sm-go-bc/crypto"
	"github.com/lihongjie0209/sm-go-bc/crypto/params"
)

// CTRBlockCipher implements Counter (CTR) mode, also known as SIC (Segmented Integer Counter).
// Reference: NIST SP 800-38A, org.bouncycastle.crypto.modes.SICBlockCipher
// Based on: sm-py-bc/src/sm_bc/crypto/modes/sic_block_cipher.py
//
// CTR mode turns a block cipher into a stream cipher by encrypting a counter
// and XORing the result with the plaintext. The counter is incremented for each block.
// Note: CTR mode uses encryption for both encryption and decryption operations.
type CTRBlockCipher struct {
	cipher     crypto.BlockCipher
	blockSize  int
	IV         []byte
	counter    []byte
	counterOut []byte
	byteCount  int
}

// NewCTRBlockCipher creates a new CTR mode cipher.
func NewCTRBlockCipher(cipher crypto.BlockCipher) *CTRBlockCipher {
	blockSize := cipher.GetBlockSize()
	return &CTRBlockCipher{
		cipher:     cipher,
		blockSize:  blockSize,
		IV:         make([]byte, blockSize),
		counter:    make([]byte, blockSize),
		counterOut: make([]byte, blockSize),
		byteCount:  0,
	}
}

// GetUnderlyingCipher returns the underlying block cipher.
func (c *CTRBlockCipher) GetUnderlyingCipher() crypto.BlockCipher {
	return c.cipher
}

// Init initializes the cipher.
// Note: forEncryption is ignored by CTR mode (always encrypts the counter).
func (c *CTRBlockCipher) Init(forEncryption bool, parameters crypto.CipherParameters) {
	ivParams, ok := parameters.(*params.ParametersWithIV)
	if !ok {
		panic("CTR/SIC mode requires ParametersWithIV")
	}
	
	iv := ivParams.GetIV()
	
	if c.blockSize < len(iv) {
		panic("CTR/SIC mode requires IV no greater than block size")
	}
	
	maxCounterSize := 8
	if c.blockSize/2 < maxCounterSize {
		maxCounterSize = c.blockSize / 2
	}
	
	if c.blockSize-len(iv) > maxCounterSize {
		panic("CTR/SIC mode requires IV of sufficient length")
	}
	
	copy(c.IV, iv)
	
	// Initialize the cipher (always with encryption)
	underlyingParams := ivParams.GetParameters()
	if underlyingParams != nil {
		c.cipher.Init(true, underlyingParams)
	}
	
	c.Reset()
}

// GetAlgorithmName returns the algorithm name and mode.
func (c *CTRBlockCipher) GetAlgorithmName() string {
	return c.cipher.GetAlgorithmName() + "/CTR"
}

// GetBlockSize returns the block size.
func (c *CTRBlockCipher) GetBlockSize() int {
	return c.blockSize
}

// ProcessBlock processes one block of input.
func (c *CTRBlockCipher) ProcessBlock(in []byte, inOff int, out []byte, outOff int) int {
	if c.byteCount != 0 {
		return c.processBytes(in, inOff, c.blockSize, out, outOff)
	}
	
	if inOff+c.blockSize > len(in) {
		panic("input buffer too short")
	}
	
	if outOff+c.blockSize > len(out) {
		panic("output buffer too short")
	}
	
	// Check counter before using it
	c.checkLastIncrement()
	
	// Encrypt the counter
	c.cipher.ProcessBlock(c.counter, 0, c.counterOut, 0)
	
	// XOR with input
	for i := 0; i < c.blockSize; i++ {
		out[outOff+i] = in[inOff+i] ^ c.counterOut[i]
	}
	
	c.incrementCounter()
	
	return c.blockSize
}

// ProcessBytes processes bytes in stream mode.
func (c *CTRBlockCipher) processBytes(in []byte, inOff int, length int, out []byte, outOff int) int {
	if inOff+length > len(in) {
		panic("input buffer too short")
	}
	
	if outOff+length > len(out) {
		panic("output buffer too short")
	}
	
	for i := 0; i < length; i++ {
		if c.byteCount == 0 {
			c.checkLastIncrement()
			c.cipher.ProcessBlock(c.counter, 0, c.counterOut, 0)
			out[outOff+i] = in[inOff+i] ^ c.counterOut[c.byteCount]
			c.byteCount++
		} else {
			out[outOff+i] = in[inOff+i] ^ c.counterOut[c.byteCount]
			c.byteCount++
			if c.byteCount == len(c.counter) {
				c.byteCount = 0
				c.incrementCounter()
			}
		}
	}
	
	return length
}

// Reset resets the cipher.
func (c *CTRBlockCipher) Reset() {
	for i := range c.counter {
		c.counter[i] = 0
	}
	copy(c.counter, c.IV)
	c.cipher.Reset()
	c.byteCount = 0
}

// checkLastIncrement checks that counter hasn't wrapped around.
func (c *CTRBlockCipher) checkLastIncrement() {
	// If the IV is the same as the blocksize we assume the user knows what they are doing
	if len(c.IV) < c.blockSize {
		if c.counter[len(c.IV)-1] != c.IV[len(c.IV)-1] {
			panic("Counter in CTR/SIC mode out of range")
		}
	}
}

// incrementCounter increments the counter by 1.
func (c *CTRBlockCipher) incrementCounter() {
	for i := len(c.counter) - 1; i >= 0; i-- {
		c.counter[i]++
		if c.counter[i] != 0 {
			break
		}
	}
}

// Ensure CTRBlockCipher implements BlockCipher interface
var _ crypto.BlockCipher = (*CTRBlockCipher)(nil)
