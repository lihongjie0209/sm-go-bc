// Package ec implements elliptic curve cryptography.
package ec

import (
	"bytes"
	"math/big"
)

// Point represents a point on an elliptic curve.
type Point struct {
	curve      *Curve
	x          FieldElement
	y          FieldElement
	isInfinity bool
}

// NewPoint creates a new point on the curve.
func NewPoint(curve *Curve, x, y FieldElement) *Point {
	if x == nil || y == nil {
		return &Point{
			curve:      curve,
			isInfinity: true,
		}
	}
	return &Point{
		curve:      curve,
		x:          x,
		y:          y,
		isInfinity: false,
	}
}

// GetInfinity returns the point at infinity.
func (p *Point) GetInfinity() *Point {
	return &Point{
		curve:      p.curve,
		isInfinity: true,
	}
}

// IsInfinity returns true if the point is the point at infinity.
func (p *Point) IsInfinity() bool {
	return p.isInfinity
}

// GetX returns the x-coordinate.
func (p *Point) GetX() FieldElement {
	return p.x
}

// GetY returns the y-coordinate.
func (p *Point) GetY() FieldElement {
	return p.y
}

// GetXCoord returns the x-coordinate (alias for GetX).
func (p *Point) GetXCoord() FieldElement {
	return p.x
}

// GetYCoord returns the y-coordinate (alias for GetY).
func (p *Point) GetYCoord() FieldElement {
	return p.y
}

// GetCurve returns the curve.
func (p *Point) GetCurve() *Curve {
	return p.curve
}

// IsValid checks if the point lies on the curve.
// For curve y^2 = x^3 + ax + b
func (p *Point) IsValid() bool {
	if p.isInfinity {
		return true
	}
	
	// y^2 = x^3 + ax + b
	lhs := p.y.Square()
	x2 := p.x.Square()
	x3 := x2.Multiply(p.x)
	ax := p.curve.a.Multiply(p.x)
	rhs := x3.Add(ax).Add(p.curve.b)
	
	return lhs.Equals(rhs)
}

// Add adds two points on the curve (affine coordinates).
func (p *Point) Add(q *Point) *Point {
	if p.isInfinity {
		return q
	}
	if q.isInfinity {
		return p
	}
	
	// Check if points are the same
	if p.Equals(q) {
		return p.Twice()
	}
	
	// Check if p.x == q.x (vertical line, result is infinity)
	if p.x.Equals(q.x) {
		return p.GetInfinity()
	}
	
	// λ = (y2 - y1) / (x2 - x1)
	numerator := q.y.Subtract(p.y)
	denominator := q.x.Subtract(p.x)
	lambda := numerator.Divide(denominator)
	
	// x3 = λ^2 - x1 - x2
	x3 := lambda.Square().Subtract(p.x).Subtract(q.x)
	
	// y3 = λ(x1 - x3) - y1
	y3 := lambda.Multiply(p.x.Subtract(x3)).Subtract(p.y)
	
	return NewPoint(p.curve, x3, y3)
}

// Twice doubles the point (affine coordinates).
func (p *Point) Twice() *Point {
	if p.isInfinity {
		return p
	}
	
	// Check if y == 0 (result is infinity)
	if p.y.ToBigInt().Cmp(big.NewInt(0)) == 0 {
		return p.GetInfinity()
	}
	
	// λ = (3x^2 + a) / (2y)
	x2 := p.x.Square()
	three := NewFp(p.curve.a.(*Fp).q, big.NewInt(3))
	numerator := three.Multiply(x2).Add(p.curve.a)
	
	two := NewFp(p.curve.a.(*Fp).q, big.NewInt(2))
	denominator := two.Multiply(p.y)
	
	lambda := numerator.Divide(denominator)
	
	// x3 = λ^2 - 2x
	x3 := lambda.Square().Subtract(two.Multiply(p.x))
	
	// y3 = λ(x - x3) - y
	y3 := lambda.Multiply(p.x.Subtract(x3)).Subtract(p.y)
	
	return NewPoint(p.curve, x3, y3)
}

// Negate negates the point.
func (p *Point) Negate() *Point {
	if p.isInfinity {
		return p
	}
	return NewPoint(p.curve, p.x, p.y.Negate())
}

// Subtract subtracts q from p.
func (p *Point) Subtract(q *Point) *Point {
	return p.Add(q.Negate())
}

// Multiply multiplies the point by a scalar (double-and-add).
func (p *Point) Multiply(k *big.Int) *Point {
	if p.isInfinity {
		return p
	}
	
	if k.Sign() == 0 {
		return p.GetInfinity()
	}
	
	if k.Sign() < 0 {
		neg := new(big.Int).Neg(k)
		return p.Negate().Multiply(neg)
	}
	
	// Double-and-add algorithm
	result := p.GetInfinity()
	addend := p
	
	kBits := k.Bytes()
	for i := len(kBits) - 1; i >= 0; i-- {
		for j := 0; j < 8; j++ {
			if (kBits[i] & (1 << j)) != 0 {
				result = result.Add(addend)
			}
			addend = addend.Twice()
		}
	}
	
	return result
}

// Equals checks if two points are equal.
func (p *Point) Equals(q *Point) bool {
	if p.isInfinity && q.isInfinity {
		return true
	}
	if p.isInfinity || q.isInfinity {
		return false
	}
	return p.x.Equals(q.x) && p.y.Equals(q.y)
}

// GetEncoded encodes the point to bytes.
func (p *Point) GetEncoded(compressed bool) []byte {
	if p.isInfinity {
		return []byte{0x00}
	}
	
	xBytes := p.x.ToBigInt().Bytes()
	byteLen := (p.curve.GetFieldSize() + 7) / 8
	
	// Pad x to field size
	if len(xBytes) < byteLen {
		padded := make([]byte, byteLen)
		copy(padded[byteLen-len(xBytes):], xBytes)
		xBytes = padded
	}
	
	if compressed {
		// 0x02 or 0x03 based on y LSB
		header := byte(0x02)
		if p.y.TestBitZero() {
			header = 0x03
		}
		result := make([]byte, 1+byteLen)
		result[0] = header
		copy(result[1:], xBytes)
		return result
	}
	
	// Uncompressed: 0x04 || x || y
	yBytes := p.y.ToBigInt().Bytes()
	if len(yBytes) < byteLen {
		padded := make([]byte, byteLen)
		copy(padded[byteLen-len(yBytes):], yBytes)
		yBytes = padded
	}
	
	result := make([]byte, 1+2*byteLen)
	result[0] = 0x04
	copy(result[1:], xBytes)
	copy(result[1+byteLen:], yBytes)
	return result
}

// DecodePoint decodes a point from bytes.
func DecodePoint(curve *Curve, encoded []byte) *Point {
	if len(encoded) == 0 {
		return nil
	}
	
	typ := encoded[0]
	
	if typ == 0x00 {
		return &Point{curve: curve, isInfinity: true}
	}
	
	byteLen := (curve.GetFieldSize() + 7) / 8
	
	if typ == 0x02 || typ == 0x03 {
		// Compressed point
		if len(encoded) != 1+byteLen {
			return nil
		}
		
		yTilde := typ & 1
		xBytes := encoded[1:]
		x := new(big.Int).SetBytes(xBytes)
		xField := NewFp(curve.p, x)
		
		// Compute y^2 = x^3 + ax + b
		x2 := xField.Square()
		x3 := x2.Multiply(xField)
		ax := curve.a.Multiply(xField)
		alpha := x3.Add(ax).Add(curve.b)
		
		// Find square root
		beta := alpha.Sqrt()
		if beta == nil {
			return nil
		}
		
		// Select correct root based on yTilde
		bit0 := byte(0)
		if beta.TestBitZero() {
			bit0 = 1
		}
		
		if bit0 != yTilde {
			beta = beta.Negate()
		}
		
		return NewPoint(curve, xField, beta)
	}
	
	if typ == 0x04 {
		// Uncompressed point
		if len(encoded) != 1+2*byteLen {
			return nil
		}
		
		xBytes := encoded[1 : 1+byteLen]
		yBytes := encoded[1+byteLen:]
		
		x := new(big.Int).SetBytes(xBytes)
		y := new(big.Int).SetBytes(yBytes)
		
		xField := NewFp(curve.p, x)
		yField := NewFp(curve.p, y)
		
		return NewPoint(curve, xField, yField)
	}
	
	return nil
}

// String returns a string representation of the point.
func (p *Point) String() string {
	if p.isInfinity {
		return "Point(INFINITY)"
	}
	var buf bytes.Buffer
	buf.WriteString("Point(")
	buf.WriteString(p.x.String())
	buf.WriteString(", ")
	buf.WriteString(p.y.String())
	buf.WriteString(")")
	return buf.String()
}
