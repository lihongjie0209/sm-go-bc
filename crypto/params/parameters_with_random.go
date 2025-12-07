// Package params provides cipher parameter types.
package params

import (
	"crypto/rand"
	"io"

	"github.com/lihongjie0209/sm-go-bc/crypto"
)

// ParametersWithRandom wraps cipher parameters with a custom random source.
// Based on: org.bouncycastle.crypto.params.ParametersWithRandom
type ParametersWithRandom struct {
	parameters crypto.CipherParameters
	random     io.Reader
}

// NewParametersWithRandom creates parameters with a custom random source.
// If random is nil, crypto/rand.Reader is used.
func NewParametersWithRandom(parameters crypto.CipherParameters, random io.Reader) *ParametersWithRandom {
	if random == nil {
		random = rand.Reader
	}
	return &ParametersWithRandom{
		parameters: parameters,
		random:     random,
	}
}

// GetParameters returns the wrapped cipher parameters.
func (p *ParametersWithRandom) GetParameters() crypto.CipherParameters {
	return p.parameters
}

// GetRandom returns the random source.
func (p *ParametersWithRandom) GetRandom() io.Reader {
	return p.random
}

// IsCipherParameters is a marker method to indicate this type implements CipherParameters.
func (p *ParametersWithRandom) IsCipherParameters() {}
