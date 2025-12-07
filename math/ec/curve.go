// Package ec implements elliptic curve cryptography.
package ec

import (
	"math/big"
)

// Curve represents an elliptic curve over Fp.
// Curve equation: y^2 = x^3 + ax + b (mod p)
type Curve struct {
	P *big.Int     // Field modulus
	A FieldElement // Curve coefficient a
	B FieldElement // Curve coefficient b
	N *big.Int     // Order of base point (renamed from order for consistency)
	H int          // Cofactor (renamed from cofactor for consistency)
	G *Point       // Base point (generator)
	p        *big.Int     // Field modulus (private, for backward compatibility)
	a        FieldElement // Curve coefficient a (private)
	b        FieldElement // Curve coefficient b (private)
	order    *big.Int     // Order of base point (private)
	cofactor int          // Cofactor (private)
	g        *Point       // Base point (private)
}

// NewCurve creates a new elliptic curve.
func NewCurve(p, a, b, order *big.Int, cofactor int) *Curve {
	aField := NewFp(p, a)
	bField := NewFp(p, b)
	pCopy := new(big.Int).Set(p)
	orderCopy := new(big.Int).Set(order)
	
	return &Curve{
		P:        pCopy,
		A:        aField,
		B:        bField,
		N:        orderCopy,
		H:        cofactor,
		p:        pCopy,
		a:        aField,
		b:        bField,
		order:    orderCopy,
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
	c.G = g
	c.g = g
}

// GetFieldSize returns the bit length of the field.
func (c *Curve) GetFieldSize() int {
	return c.P.BitLen()
}

// FieldSize returns the bit length of the field (alias for GetFieldSize).
func (c *Curve) FieldSize() int {
	return c.GetFieldSize()
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

// ScalarBaseMult multiplies the base point G by a scalar k.
func (c *Curve) ScalarBaseMult(k []byte) *Point {
	if c.G == nil {
		panic("base point G is not set")
	}
	kInt := new(big.Int).SetBytes(k)
	return c.G.Multiply(kInt)
}

// ScalarMult multiplies a point P by a scalar k.
func (c *Curve) ScalarMult(p *Point, k []byte) *Point {
	kInt := new(big.Int).SetBytes(k)
	return p.Multiply(kInt)
}

// Add adds two points on the curve.
func (c *Curve) Add(p1, p2 *Point) *Point {
	return p1.Add(p2)
}
