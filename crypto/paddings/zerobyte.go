package paddings

import "github.com/lihongjie0209/sm-go-bc/crypto"

// ZeroBytePadding implements zero byte padding scheme
// Reference: org.bouncycastle.crypto.paddings.ZeroBytePadding
type ZeroBytePadding struct{}

// NewZeroBytePadding creates a new ZeroBytePadding instance
func NewZeroBytePadding() *ZeroBytePadding {
	return &ZeroBytePadding{}
}

// Init initializes the padding (no-op for zero byte padding)
func (p *ZeroBytePadding) Init(random []byte) {
	// No initialization required
}

// GetPaddingName returns the name of the padding
func (p *ZeroBytePadding) GetPaddingName() string {
	return "ZeroBytePadding"
}

// AddPadding adds zero byte padding to the input
// Returns the number of padding bytes added
func (p *ZeroBytePadding) AddPadding(input []byte, inOff int) int {
	added := len(input) - inOff

	for i := inOff; i < len(input); i++ {
		input[i] = 0
	}

	return added
}

// PadCount returns the number of padding bytes in the input
// Note: This can be ambiguous as data might legitimately end with zeros
func (p *ZeroBytePadding) PadCount(input []byte) (int, error) {
	count := len(input)

	for count > 0 && input[count-1] == 0 {
		count--
	}

	return len(input) - count, nil
}

// Ensure ZeroBytePadding implements BlockCipherPadding
var _ crypto.BlockCipherPadding = (*ZeroBytePadding)(nil)
