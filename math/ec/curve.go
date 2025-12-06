// Package ec implements elliptic curve cryptography.
package ec

import (
	"math/big"
)

// Curve represents an elliptic curve over Fp.
// Curve equation: y^2 = x^3 + ax + b (mod p)
type Curve struct {
	p        *big.Int     // Field modulus
	a        FieldElement // Curve coefficient a
	b        FieldElement // Curve coefficient b
	order    *big.Int     // Order of base point
	cofactor int          // Cofactor
	g        *Point       // Base point (generator)
}

// NewCurve creates a new elliptic curve.
func NewCurve(p, a, b, order *big.Int, cofactor int) *Curve {
	aField := NewFp(p, a)
	bField := NewFp(p, b)
	
	return &Curve{
		p:        new(big.Int).Set(p),
		a:        aField,
		b:        bField,
		order:    new(big.Int).Set(order),
		cofactor: cofactor,
	}
}

// GetP returns the field modulus.
func (c *Curve) GetP() *big.Int {
	return new(big.Int).Set(c.p)
}

// GetA returns coefficient a.
func (c *Curve) GetA() FieldElement {
	return c.a
}

// GetB returns coefficient b.
func (c *Curve) GetB() FieldElement {
	return c.b
}

// GetOrder returns the order of the base point.
func (c *Curve) GetOrder() *big.Int {
	return new(big.Int).Set(c.order)
}

// GetCofactor returns the cofactor.
func (c *Curve) GetCofactor() int {
	return c.cofactor
}

// GetG returns the base point.
func (c *Curve) GetG() *Point {
	return c.g
}

// SetG sets the base point.
func (c *Curve) SetG(g *Point) {
	c.g = g
}

// GetFieldSize returns the bit length of the field.
func (c *Curve) GetFieldSize() int {
	return c.p.BitLen()
}

// CreatePoint creates a point on the curve from big.Int coordinates.
func (c *Curve) CreatePoint(x, y *big.Int) *Point {
	xField := NewFp(c.p, x)
	yField := NewFp(c.p, y)
	return NewPoint(c, xField, yField)
}

// GetInfinity returns the point at infinity for this curve.
func (c *Curve) GetInfinity() *Point {
	return &Point{
		curve:      c,
		isInfinity: true,
	}
}

// ValidatePoint checks if a point is valid on the curve.
func (c *Curve) ValidatePoint(p *Point) bool {
	if p.isInfinity {
		return true
	}
	return p.IsValid()
}

// FromBigInteger creates a field element from big.Int.
func (c *Curve) FromBigInteger(x *big.Int) FieldElement {
	return NewFp(c.p, x)
}

// DecodePoint decodes a point from bytes.
func (c *Curve) DecodePoint(encoded []byte) *Point {
	return DecodePoint(c, encoded)
}

// Equals checks if two curves are equal.
func (c *Curve) Equals(other *Curve) bool {
	if other == nil {
		return false
	}
	return c.p.Cmp(other.p) == 0 &&
		c.a.Equals(other.a) &&
		c.b.Equals(other.b)
}
