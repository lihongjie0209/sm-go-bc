package params

import (
	"math/big"
)

// ECCurve interface placeholder
type ECCurve interface {
	GetFieldSize() int
	Equals(interface{}) bool
}

// ECPoint interface placeholder  
type ECPoint interface {
	Equals(interface{}) bool
	Multiply(*big.Int) ECPoint
	Twice() ECPoint
}

// ECDomainParameters represents elliptic curve domain parameters
type ECDomainParameters struct {
	curve ECCurve
	G     ECPoint
	n     *big.Int
	h     *big.Int
	seed  []byte
}

// NewECDomainParameters creates new domain parameters
func NewECDomainParameters(curve ECCurve, G ECPoint, n *big.Int, h *big.Int, seed ...[]byte) *ECDomainParameters {
	params := &ECDomainParameters{
		curve: curve,
		G:     G,
		n:     n,
		h:     h,
	}
	
	if h == nil {
		params.h = big.NewInt(1)
	}
	
	if len(seed) > 0 && seed[0] != nil {
		params.seed = seed[0]
	}
	
	return params
}

// GetCurve returns the elliptic curve
func (p *ECDomainParameters) GetCurve() ECCurve {
	return p.curve
}

// GetG returns the generator point
func (p *ECDomainParameters) GetG() ECPoint {
	return p.G
}

// GetN returns the order of the generator
func (p *ECDomainParameters) GetN() *big.Int {
	return p.n
}

// GetH returns the cofactor
func (p *ECDomainParameters) GetH() *big.Int {
	return p.h
}

// GetSeed returns the seed (if any)
func (p *ECDomainParameters) GetSeed() []byte {
	return p.seed
}

// Equals checks if two domain parameters are equal
func (p *ECDomainParameters) Equals(other interface{}) bool {
	if other == nil {
		return false
	}
	
	otherParams, ok := other.(*ECDomainParameters)
	if !ok {
		return false
	}
	
	return p.curve.Equals(otherParams.curve) &&
		p.G.Equals(otherParams.G) &&
		p.n.Cmp(otherParams.n) == 0 &&
		p.h.Cmp(otherParams.h) == 0
}

// HashCode returns a hash code for the parameters
func (p *ECDomainParameters) HashCode() int {
	hash := int64(p.curve.GetFieldSize())
	if p.n.IsInt64() {
		hash ^= p.n.Int64()
	}
	if p.h.IsInt64() {
		hash ^= p.h.Int64()
	}
	return int(hash)
}
