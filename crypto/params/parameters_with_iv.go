// Package params provides cryptographic parameter types.
package params

import "github.com/lihongjie0209/sm-go-bc/crypto"

// ParametersWithIV wraps cipher parameters and an initialization vector.
// Reference: org.bouncycastle.crypto.params.ParametersWithIV
type ParametersWithIV struct {
	iv         []byte
	parameters crypto.CipherParameters
}

// NewParametersWithIV creates parameters with an IV.
func NewParametersWithIV(parameters crypto.CipherParameters, iv []byte) *ParametersWithIV {
	// Make a defensive copy of IV
	ivCopy := make([]byte, len(iv))
	copy(ivCopy, iv)
	
	return &ParametersWithIV{
		iv:         ivCopy,
		parameters: parameters,
	}
}

// GetIV returns the initialization vector.
func (p *ParametersWithIV) GetIV() []byte {
	return p.iv
}

// GetParameters returns the underlying cipher parameters.
func (p *ParametersWithIV) GetParameters() crypto.CipherParameters {
	return p.parameters
}

// IsCipherParameters implements the CipherParameters marker interface.
func (p *ParametersWithIV) IsCipherParameters() bool {
	return true
}

// Ensure ParametersWithIV implements CipherParameters
var _ crypto.CipherParameters = (*ParametersWithIV)(nil)
