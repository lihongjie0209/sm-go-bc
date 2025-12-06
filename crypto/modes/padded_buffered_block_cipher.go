// Package modes implements block cipher modes of operation.
package modes

import (
	"fmt"
	"github.com/lihongjie0209/sm-go-bc/crypto"
)

// PaddedBufferedBlockCipher wraps a block cipher with buffering and padding support.
// Reference: org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher
type PaddedBufferedBlockCipher struct {
	cipher     crypto.BlockCipher
	padding    crypto.BlockCipherPadding
	buf        []byte
	bufOff     int
	forEncryption bool
}

// NewPaddedBufferedBlockCipher creates a new padded buffered block cipher.
func NewPaddedBufferedBlockCipher(cipher crypto.BlockCipher, padding crypto.BlockCipherPadding) *PaddedBufferedBlockCipher {
	blockSize := cipher.GetBlockSize()
	return &PaddedBufferedBlockCipher{
		cipher:  cipher,
		padding: padding,
		buf:     make([]byte, blockSize),
		bufOff:  0,
	}
}

// Init initializes the cipher.
func (c *PaddedBufferedBlockCipher) Init(forEncryption bool, params crypto.CipherParameters) {
	c.forEncryption = forEncryption
	c.Reset()
	c.cipher.Init(forEncryption, params)
}

// GetBlockSize returns the block size for this cipher.
func (c *PaddedBufferedBlockCipher) GetBlockSize() int {
	return c.cipher.GetBlockSize()
}

// GetUpdateOutputSize returns the size of the output buffer required for an update.
func (c *PaddedBufferedBlockCipher) GetUpdateOutputSize(length int) int {
	total := length + c.bufOff
	leftOver := total % len(c.buf)
	return total - leftOver
}

// GetOutputSize returns the size of the output buffer required.
func (c *PaddedBufferedBlockCipher) GetOutputSize(length int) int {
	total := length + c.bufOff
	
	if c.forEncryption {
		// For encryption, we need to account for padding
		leftOver := total % len(c.buf)
		if leftOver == 0 {
			return total + len(c.buf)
		}
		return total - leftOver + len(c.buf)
	}
	
	// For decryption, output will be at most total bytes
	return total
}

// ProcessByte processes a single byte.
func (c *PaddedBufferedBlockCipher) ProcessByte(in byte, out []byte, outOff int) (int, error) {
	c.buf[c.bufOff] = in
	c.bufOff++
	
	if c.bufOff == len(c.buf) {
		outLen := c.cipher.ProcessBlock(c.buf, 0, out, outOff)
		c.bufOff = 0
		return outLen, nil
	}
	
	return 0, nil
}

// ProcessBytes processes multiple bytes.
func (c *PaddedBufferedBlockCipher) ProcessBytes(in []byte, inOff int, length int, out []byte, outOff int) (int, error) {
	if length < 0 {
		return 0, fmt.Errorf("invalid length: %d", length)
	}
	
	blockSize := c.GetBlockSize()
	outputLen := c.GetUpdateOutputSize(length)
	
	if outputLen > 0 && outOff+outputLen > len(out) {
		return 0, fmt.Errorf("output buffer too short")
	}
	
	totalLen := 0
	gapLen := len(c.buf) - c.bufOff
	
	if length > gapLen {
		// Fill the buffer
		copy(c.buf[c.bufOff:], in[inOff:inOff+gapLen])
		
		totalLen += c.cipher.ProcessBlock(c.buf, 0, out, outOff)
		c.bufOff = 0
		length -= gapLen
		inOff += gapLen
		
		// Process full blocks
		for length > blockSize {
			totalLen += c.cipher.ProcessBlock(in, inOff, out, outOff+totalLen)
			length -= blockSize
			inOff += blockSize
		}
	}
	
	// Copy remaining bytes to buffer
	copy(c.buf[c.bufOff:], in[inOff:inOff+length])
	c.bufOff += length
	
	return totalLen, nil
}

// DoFinal completes the encryption/decryption.
func (c *PaddedBufferedBlockCipher) DoFinal(out []byte, outOff int) (int, error) {
	blockSize := c.cipher.GetBlockSize()
	totalLen := 0
	
	if c.forEncryption {
		// Add padding
		if c.bufOff == blockSize {
			// Buffer is full, process it first
			if outOff+2*blockSize > len(out) {
				return 0, fmt.Errorf("output buffer too short")
			}
			
			totalLen = c.cipher.ProcessBlock(c.buf, 0, out, outOff)
			c.bufOff = 0
		}
		
		// Add padding to buffer
		c.padding.AddPadding(c.buf, c.bufOff)
		
		// Process the final padded block
		totalLen += c.cipher.ProcessBlock(c.buf, 0, out, outOff+totalLen)
		c.Reset()
		
		return totalLen, nil
	}
	
	// Decryption
	if c.bufOff == blockSize {
		totalLen = c.cipher.ProcessBlock(c.buf, 0, c.buf, 0)
		c.bufOff = 0
	} else {
		c.Reset()
		return 0, fmt.Errorf("last block incomplete in decryption")
	}
	
	// Remove padding
	padCount, err := c.padding.PadCount(c.buf)
	if err != nil {
		c.Reset()
		return 0, fmt.Errorf("pad block corrupted: %v", err)
	}
	
	totalLen -= padCount
	copy(out[outOff:], c.buf[:totalLen])
	c.Reset()
	
	return totalLen, nil
}

// Reset resets the cipher.
func (c *PaddedBufferedBlockCipher) Reset() {
	for i := range c.buf {
		c.buf[i] = 0
	}
	c.bufOff = 0
	c.cipher.Reset()
}

// GetAlgorithmName returns the algorithm name.
func (c *PaddedBufferedBlockCipher) GetAlgorithmName() string {
	return c.cipher.GetAlgorithmName() + "/Padded"
}
