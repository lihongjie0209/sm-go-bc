package params

import (
	"math/big"
)

// AsymmetricKeyParameter is the base interface for asymmetric keys
type AsymmetricKeyParameter interface {
	IsPrivate() bool
}

// ECKeyParameters is the base class for EC key parameters
type ECKeyParameters struct {
	parameters *ECDomainParameters
	isPrivate  bool
}

// GetParameters returns the domain parameters
func (k *ECKeyParameters) GetParameters() *ECDomainParameters {
	return k.parameters
}

// IsPrivate returns true if this is a private key
func (k *ECKeyParameters) IsPrivate() bool {
	return k.isPrivate
}

// ECPublicKeyParameters represents an EC public key
type ECPublicKeyParameters struct {
	ECKeyParameters
	Q ECPoint
}

// NewECPublicKeyParameters creates new public key parameters
func NewECPublicKeyParameters(Q ECPoint, parameters *ECDomainParameters) *ECPublicKeyParameters {
	return &ECPublicKeyParameters{
		ECKeyParameters: ECKeyParameters{
			parameters: parameters,
			isPrivate:  false,
		},
		Q: Q,
	}
}

// GetQ returns the public key point
func (k *ECPublicKeyParameters) GetQ() ECPoint {
	return k.Q
}

// ECPrivateKeyParameters represents an EC private key
type ECPrivateKeyParameters struct {
	ECKeyParameters
	d *big.Int
}

// NewECPrivateKeyParameters creates new private key parameters
func NewECPrivateKeyParameters(d *big.Int, parameters *ECDomainParameters) *ECPrivateKeyParameters {
	return &ECPrivateKeyParameters{
		ECKeyParameters: ECKeyParameters{
			parameters: parameters,
			isPrivate:  true,
		},
		d: d,
	}
}

// GetD returns the private key value
func (k *ECPrivateKeyParameters) GetD() *big.Int {
	return k.d
}
