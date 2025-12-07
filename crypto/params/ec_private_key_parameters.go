// Package params provides cipher parameter types.
package params

import (
	"math/big"
)

// ECPrivateKeyParameters represents EC private key parameters.
// Based on: org.bouncycastle.crypto.params.ECPrivateKeyParameters
type ECPrivateKeyParameters struct {
	*ECKeyParameters
	d *big.Int
}

// NewECPrivateKeyParameters creates new EC private key parameters.
func NewECPrivateKeyParameters(d *big.Int, parameters *ECDomainParameters) *ECPrivateKeyParameters {
	return &ECPrivateKeyParameters{
		ECKeyParameters: NewECKeyParameters(true, parameters),
		d:               d,
	}
}

// GetD returns the private key value.
func (p *ECPrivateKeyParameters) GetD() *big.Int {
	return p.d
}
