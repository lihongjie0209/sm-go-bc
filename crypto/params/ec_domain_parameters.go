// Package params provides cipher parameter types.
package params

import (
	"math/big"

	"github.com/lihongjie0209/sm-go-bc/math/ec"
)

// ECDomainParameters represents elliptic curve domain parameters.
// Based on: org.bouncycastle.crypto.params.ECDomainParameters
type ECDomainParameters struct {
	curve *ec.Curve
	g     *ec.Point
	n     *big.Int
	h     *big.Int
	seed  []byte
}

// NewECDomainParameters creates new EC domain parameters.
func NewECDomainParameters(
	curve *ec.Curve,
	g *ec.Point,
	n *big.Int,
	h *big.Int,
	seed []byte,
) *ECDomainParameters {
	if h == nil {
		h = big.NewInt(1)
	}
	return &ECDomainParameters{
		curve: curve,
		g:     g,
		n:     n,
		h:     h,
		seed:  seed,
	}
}

// GetCurve returns the elliptic curve.
func (p *ECDomainParameters) GetCurve() *ec.Curve {
	return p.curve
}

// GetG returns the base point.
func (p *ECDomainParameters) GetG() *ec.Point {
	return p.g
}

// GetN returns the order of the base point.
func (p *ECDomainParameters) GetN() *big.Int {
	return p.n
}

// GetH returns the cofactor.
func (p *ECDomainParameters) GetH() *big.Int {
	return p.h
}

// GetSeed returns the seed used to generate the curve (may be nil).
func (p *ECDomainParameters) GetSeed() []byte {
	return p.seed
}

// Equals checks if two domain parameters are equal.
func (p *ECDomainParameters) Equals(other *ECDomainParameters) bool {
	if other == nil {
		return false
	}
	return p.curve.Equals(other.curve) &&
		p.g.Equals(other.g) &&
		p.n.Cmp(other.n) == 0 &&
		p.h.Cmp(other.h) == 0
}
