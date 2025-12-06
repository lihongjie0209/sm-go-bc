// Package modes implements block cipher modes of operation.
package modes

import (
	"github.com/lihongjie0209/sm-go-bc/crypto"
	"github.com/lihongjie0209/sm-go-bc/crypto/params"
)

// CBCBlockCipher implements Cipher Block Chaining (CBC) mode.
// Reference: NIST SP 800-38A, org.bouncycastle.crypto.modes.CBCBlockCipher
// Based on: sm-py-bc/src/sm_bc/crypto/modes/cbc_block_cipher.py
type CBCBlockCipher struct {
	cipher     crypto.BlockCipher
	blockSize  int
	IV         []byte
	cbcV       []byte
	cbcNextV   []byte
	encrypting bool
}

// NewCBCBlockCipher creates a new CBC mode cipher.
func NewCBCBlockCipher(cipher crypto.BlockCipher) *CBCBlockCipher {
	blockSize := cipher.GetBlockSize()
	return &CBCBlockCipher{
		cipher:    cipher,
		blockSize: blockSize,
		IV:        make([]byte, blockSize),
		cbcV:      make([]byte, blockSize),
		cbcNextV:  make([]byte, blockSize),
	}
}

// GetUnderlyingCipher returns the underlying block cipher.
func (c *CBCBlockCipher) GetUnderlyingCipher() crypto.BlockCipher {
	return c.cipher
}

// Init initializes the cipher and possibly the IV.
func (c *CBCBlockCipher) Init(forEncryption bool, parameters crypto.CipherParameters) {
	oldEncrypting := c.encrypting
	c.encrypting = forEncryption
	
	var actualParams crypto.CipherParameters
	
	// Check if parameters include an IV
	if ivParams, ok := parameters.(*params.ParametersWithIV); ok {
		iv := ivParams.GetIV()
		
		if len(iv) != c.blockSize {
			panic("initialization vector must be the same length as block size")
		}
		
		copy(c.IV, iv)
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
	if actualParams != nil {
		c.cipher.Init(forEncryption, actualParams)
	} else if oldEncrypting != forEncryption {
		panic("cannot change encrypting state without providing key")
	}
}

// GetAlgorithmName returns the algorithm name and mode.
func (c *CBCBlockCipher) GetAlgorithmName() string {
	return c.cipher.GetAlgorithmName() + "/CBC"
}

// GetBlockSize returns the block size of the underlying cipher.
func (c *CBCBlockCipher) GetBlockSize() int {
	return c.blockSize
}

// ProcessBlock processes one block of input.
func (c *CBCBlockCipher) ProcessBlock(in []byte, inOff int, out []byte, outOff int) int {
	if c.encrypting {
		return c.encryptBlock(in, inOff, out, outOff)
	}
	return c.decryptBlock(in, inOff, out, outOff)
}

// Reset resets the chaining vector back to the IV and resets the underlying cipher.
func (c *CBCBlockCipher) Reset() {
	copy(c.cbcV, c.IV)
	for i := range c.cbcNextV {
		c.cbcNextV[i] = 0
	}
	c.cipher.Reset()
}

// encryptBlock performs CBC encryption on one block.
func (c *CBCBlockCipher) encryptBlock(in []byte, inOff int, out []byte, outOff int) int {
	if inOff+c.blockSize > len(in) {
		panic("input buffer too short")
	}
	
	// XOR the cbcV and the input, then encrypt the cbcV
	for i := 0; i < c.blockSize; i++ {
		c.cbcV[i] ^= in[inOff+i]
	}
	
	length := c.cipher.ProcessBlock(c.cbcV, 0, out, outOff)
	
	// Copy ciphertext to cbcV
	copy(c.cbcV, out[outOff:outOff+c.blockSize])
	
	return length
}

// decryptBlock performs CBC decryption on one block.
func (c *CBCBlockCipher) decryptBlock(in []byte, inOff int, out []byte, outOff int) int {
	if inOff+c.blockSize > len(in) {
		panic("input buffer too short")
	}
	
	// Save the ciphertext block for next round
	copy(c.cbcNextV, in[inOff:inOff+c.blockSize])
	
	length := c.cipher.ProcessBlock(in, inOff, out, outOff)
	
	// XOR the cbcV and the output
	for i := 0; i < c.blockSize; i++ {
		out[outOff+i] ^= c.cbcV[i]
	}
	
	// Swap the back up buffer into next position
	c.cbcV, c.cbcNextV = c.cbcNextV, c.cbcV
	
	return length
}

// Ensure CBCBlockCipher implements BlockCipher interface
var _ crypto.BlockCipher = (*CBCBlockCipher)(nil)
