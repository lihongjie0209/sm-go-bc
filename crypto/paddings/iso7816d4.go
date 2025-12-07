package paddings

import (
	"fmt"

	"github.com/lihongjie0209/sm-go-bc/crypto"
)

// ISO7816d4Padding implements ISO 7816-4 padding scheme
// Padding format: 0x80 followed by zero or more 0x00 bytes
// Reference: org.bouncycastle.crypto.paddings.ISO7816d4Padding
type ISO7816d4Padding struct{}

// NewISO7816d4Padding creates a new ISO7816d4Padding instance
func NewISO7816d4Padding() *ISO7816d4Padding {
	return &ISO7816d4Padding{}
}

// Init initializes the padding (no-op for ISO7816-4 padding)
func (p *ISO7816d4Padding) Init(random []byte) {
	// No initialization required
}

// GetPaddingName returns the name of the padding
func (p *ISO7816d4Padding) GetPaddingName() string {
	return "ISO7816-4"
}

// AddPadding adds ISO 7816-4 padding to the input
// Format: 0x80 followed by 0x00 bytes
// Returns the number of padding bytes added
func (p *ISO7816d4Padding) AddPadding(input []byte, inOff int) int {
	added := len(input) - inOff

	// First padding byte is always 0x80
	input[inOff] = 0x80
	inOff++

	// Fill remaining bytes with 0x00
	for i := inOff; i < len(input); i++ {
		input[i] = 0x00
	}

	return added
}

// PadCount returns the number of padding bytes in the input
// Looks for the 0x80 byte working backwards from the end
func (p *ISO7816d4Padding) PadCount(input []byte) (int, error) {
	count := len(input) - 1

	// Find the 0x80 byte
	for count > 0 && input[count] == 0x00 {
		count--
	}

	// Verify it's the 0x80 marker
	if input[count] != 0x80 {
		return 0, fmt.Errorf("pad block corrupted: expected 0x80, got 0x%02x", input[count])
	}

	return len(input) - count, nil
}

// Ensure ISO7816d4Padding implements BlockCipherPadding
var _ crypto.BlockCipherPadding = (*ISO7816d4Padding)(nil)
