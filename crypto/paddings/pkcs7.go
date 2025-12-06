// Package paddings implements block cipher padding schemes.
package paddings

import (
	"errors"
	"github.com/lihongjie0209/sm-go-bc/crypto"
)

// PKCS7Padding implements PKCS#7 padding scheme.
// Reference: RFC 5652, org.bouncycastle.crypto.paddings.PKCS7Padding
// Based on: sm-py-bc/src/sm_bc/crypto/paddings/pkcs7_padding.py
type PKCS7Padding struct{}

// NewPKCS7Padding creates a new PKCS7 padding instance.
func NewPKCS7Padding() *PKCS7Padding {
	return &PKCS7Padding{}
}

// Init initializes the padding (not used for PKCS7).
func (p *PKCS7Padding) Init(random []byte) {
	// PKCS7 doesn't need initialization
}

// GetPaddingName returns the name of the padding.
func (p *PKCS7Padding) GetPaddingName() string {
	return "PKCS7"
}

// AddPadding adds PKCS7 padding to the last block.
// Returns the number of padding bytes added.
func (p *PKCS7Padding) AddPadding(in []byte, inOff int) int {
	blockLen := len(in) - inOff
	paddingLen := blockLen
	
	// PKCS7: pad with bytes all of the same value as the number of padding bytes
	for i := inOff; i < len(in); i++ {
		in[i] = byte(paddingLen)
	}
	
	return paddingLen
}

// PadCount returns the number of pad bytes in the block.
func (p *PKCS7Padding) PadCount(in []byte) (int, error) {
	blockLen := len(in)
	if blockLen == 0 {
		return 0, errors.New("empty block")
	}
	
	paddingLen := int(in[blockLen-1])
	
	// Validate padding length
	if paddingLen < 1 || paddingLen > blockLen {
		return 0, errors.New("invalid padding length")
	}
	
	// Verify all padding bytes are correct
	for i := blockLen - paddingLen; i < blockLen; i++ {
		if in[i] != byte(paddingLen) {
			return 0, errors.New("invalid padding bytes")
		}
	}
	
	return paddingLen, nil
}

// Ensure PKCS7Padding implements BlockCipherPadding
var _ crypto.BlockCipherPadding = (*PKCS7Padding)(nil)
