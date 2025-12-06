// Package modes implements block cipher modes of operation.
package modes

import (
	"fmt"
	"github.com/lihongjie0209/sm-go-bc/crypto"
	"github.com/lihongjie0209/sm-go-bc/crypto/params"
)

// OFBBlockCipher implements Output Feedback (OFB) mode.
// Reference: NIST SP 800-38A, org.bouncycastle.crypto.modes.OFBBlockCipher
// Based on: sm-py-bc/src/sm_bc/crypto/modes/ofb_block_cipher.py
//
// In OFB mode, the block cipher encrypts the previous output to produce
// the next keystream block. The keystream is then XORed with the plaintext.
//
// Key characteristics:
// - Encryption and decryption are identical operations (XOR with keystream)
// - Converts block cipher into stream cipher
// - Does not propagate errors
// - Feedback is from encrypted output, not ciphertext
type OFBBlockCipher struct {
	cipher       crypto.BlockCipher
	blockSize    int
	cipherSize   int
	IV           []byte
	ofbV         []byte // Output feedback register
	ofbOutV      []byte // Encrypted output
	byteCount    int
}

// NewOFBBlockCipher creates a new OFB mode cipher.
// blockSize is the feedback block size in bytes (must be <= cipher block size).
func NewOFBBlockCipher(cipher crypto.BlockCipher, bitBlockSize int) *OFBBlockCipher {
	cipherBlockSize := cipher.GetBlockSize()
	
	if bitBlockSize > cipherBlockSize*8 || bitBlockSize < 8 || bitBlockSize%8 != 0 {
		panic(fmt.Sprintf("OFB%d not supported", bitBlockSize))
	}
	
	blockSize := bitBlockSize / 8
	
	return &OFBBlockCipher{
		cipher:     cipher,
		blockSize:  blockSize,
		cipherSize: cipherBlockSize,
		IV:         make([]byte, cipherBlockSize),
		ofbV:       make([]byte, cipherBlockSize),
		ofbOutV:    make([]byte, cipherBlockSize),
		byteCount:  0,
	}
}

// GetUnderlyingCipher returns the underlying block cipher.
func (o *OFBBlockCipher) GetUnderlyingCipher() crypto.BlockCipher {
	return o.cipher
}

// Init initializes the cipher and possibly the IV.
// Note: forEncryption is ignored for OFB mode since encryption and decryption are identical.
func (o *OFBBlockCipher) Init(forEncryption bool, parameters crypto.CipherParameters) {
	ivParams, ok := parameters.(*params.ParametersWithIV)
	if ok {
		iv := ivParams.GetIV()
		
		if len(iv) < len(o.IV) {
			// Prepend the supplied IV with zeros (per FIPS PUB 81)
			for i := range o.IV {
				o.IV[i] = 0
			}
			copy(o.IV[len(o.IV)-len(iv):], iv)
		} else {
			copy(o.IV, iv[:len(o.IV)])
		}
		
		o.Reset()
		
		// If underlying params is nil, it's an IV change only
		underlyingParams := ivParams.GetParameters()
		if underlyingParams != nil {
			// OFB always encrypts the feedback register, regardless of mode
			o.cipher.Init(true, underlyingParams)
		}
	} else {
		o.Reset()
		
		// If it's not nil, key is to be reused
		if parameters != nil {
			// OFB always encrypts the feedback register
			o.cipher.Init(true, parameters)
		}
	}
}

// GetAlgorithmName returns the algorithm name and mode.
func (o *OFBBlockCipher) GetAlgorithmName() string {
	return fmt.Sprintf("%s/OFB%d", o.cipher.GetAlgorithmName(), o.blockSize*8)
}

// GetBlockSize returns the block size in bytes.
func (o *OFBBlockCipher) GetBlockSize() int {
	return o.blockSize
}

// ProcessBlock processes a block of input.
func (o *OFBBlockCipher) ProcessBlock(in []byte, inOff int, out []byte, outOff int) int {
	o.processBytes(in, inOff, o.blockSize, out, outOff)
	return o.blockSize
}

// processBytes processes a stream of bytes.
func (o *OFBBlockCipher) processBytes(in []byte, inOff int, length int, out []byte, outOff int) int {
	if inOff+length > len(in) {
		panic("input buffer too short")
	}
	
	if outOff+length > len(out) {
		panic("output buffer too short")
	}
	
	for i := 0; i < length; i++ {
		out[outOff+i] = o.calculateByte(in[inOff+i])
	}
	
	return length
}

// Reset resets the feedback register back to the IV and resets the underlying cipher.
func (o *OFBBlockCipher) Reset() {
	copy(o.ofbV, o.IV)
	o.byteCount = 0
	o.cipher.Reset()
}

// GetCurrentIV gets the current IV/output feedback register state.
func (o *OFBBlockCipher) GetCurrentIV() []byte {
	result := make([]byte, len(o.ofbV))
	copy(result, o.ofbV)
	return result
}

// calculateByte calculates a single output byte.
func (o *OFBBlockCipher) calculateByte(inByte byte) byte {
	// Generate new keystream block if needed
	if o.byteCount == 0 {
		o.cipher.ProcessBlock(o.ofbV, 0, o.ofbOutV, 0)
	}
	
	// XOR input with keystream
	outByte := o.ofbOutV[o.byteCount] ^ inByte
	o.byteCount++
	
	// Update feedback register when block is complete
	if o.byteCount == o.blockSize {
		o.byteCount = 0
		
		// Shift ofbV left by blockSize bytes
		copy(o.ofbV, o.ofbV[o.blockSize:])
		
		// Append the encrypted output to feedback register
		copy(o.ofbV[len(o.ofbV)-o.blockSize:], o.ofbOutV[:o.blockSize])
	}
	
	return outByte
}

// Ensure OFBBlockCipher implements BlockCipher interface
var _ crypto.BlockCipher = (*OFBBlockCipher)(nil)
