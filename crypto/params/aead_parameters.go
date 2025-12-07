// Package params provides cryptographic parameter types.
package params

// AEADParameters holds parameters for AEAD (Authenticated Encryption with Associated Data) modes.
// Used with modes like GCM that provide both encryption and authentication.
// Reference: org.bouncycastle.crypto.params.AEADParameters
type AEADParameters struct {
	key            *KeyParameter
	nonce          []byte
	macSize        int  // MAC size in bits
	associatedText []byte
}

// NewAEADParameters creates new AEAD parameters.
//
// Parameters:
//   - key: The cipher key
//   - macSize: The MAC/tag size in bits (must be multiple of 8)
//   - nonce: The nonce/IV
//   - associatedText: Optional additional authenticated data (AAD), can be nil
func NewAEADParameters(key *KeyParameter, macSize int, nonce []byte, associatedText []byte) *AEADParameters {
	return &AEADParameters{
		key:            key,
		macSize:        macSize,
		nonce:          nonce,
		associatedText: associatedText,
	}
}

// GetKey returns the cipher key.
func (p *AEADParameters) GetKey() *KeyParameter {
	return p.key
}

// GetMacSize returns the MAC size in bits.
func (p *AEADParameters) GetMacSize() int {
	return p.macSize
}

// GetNonce returns the nonce/IV.
func (p *AEADParameters) GetNonce() []byte {
	return p.nonce
}

// GetAssociatedText returns the associated text (additional authenticated data).
// Returns nil if no AAD was provided.
func (p *AEADParameters) GetAssociatedText() []byte {
	return p.associatedText
}

// IsCipherParameters is a marker method to identify this as cipher parameters.
func (p *AEADParameters) IsCipherParameters() bool {
	return true
}
