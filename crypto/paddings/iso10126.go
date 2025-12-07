package paddings

import (
	"crypto/rand"
	"fmt"

	"github.com/lihongjie0209/sm-go-bc/crypto"
)

// ISO10126Padding implements ISO 10126 padding scheme
// Padding format: random bytes followed by the padding length
// Reference: org.bouncycastle.crypto.paddings.ISO10126d2Padding
type ISO10126Padding struct{}

// NewISO10126Padding creates a new ISO10126Padding instance
func NewISO10126Padding() *ISO10126Padding {
	return &ISO10126Padding{}
}

// Init initializes the padding (no-op for ISO10126 padding)
func (p *ISO10126Padding) Init(random []byte) {
	// No initialization required
}

// GetPaddingName returns the name of the padding
func (p *ISO10126Padding) GetPaddingName() string {
	return "ISO10126-2"
}

// AddPadding adds ISO 10126 padding to the input
// Format: random bytes followed by padding length byte
// Returns the number of padding bytes added
func (p *ISO10126Padding) AddPadding(input []byte, inOff int) int {
	added := len(input) - inOff

	// Fill with random bytes
	if added > 1 {
		randomBytes := make([]byte, added-1)
		rand.Read(randomBytes)
		copy(input[inOff:], randomBytes)
	}

	// Last byte is the padding length
	input[len(input)-1] = byte(added)

	return added
}

// PadCount returns the number of padding bytes in the input
// Reads the last byte which contains the padding length
func (p *ISO10126Padding) PadCount(input []byte) (int, error) {
	count := int(input[len(input)-1])

	// Validate padding count
	if count < 1 || count > len(input) {
		return 0, fmt.Errorf("pad block corrupted: invalid padding length %d", count)
	}

	return count, nil
}

// Ensure ISO10126Padding implements BlockCipherPadding
var _ crypto.BlockCipherPadding = (*ISO10126Padding)(nil)
