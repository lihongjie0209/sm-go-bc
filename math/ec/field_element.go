// Package ec implements elliptic curve cryptography.
package ec

import (
	"math/big"
)

// FieldElement represents an element in a finite field.
type FieldElement interface {
	ToBigInt() *big.Int
	GetFieldSize() int
	Add(b FieldElement) FieldElement
	AddOne() FieldElement
	Subtract(b FieldElement) FieldElement
	Multiply(b FieldElement) FieldElement
	Divide(b FieldElement) FieldElement
	Negate() FieldElement
	Square() FieldElement
	Invert() FieldElement
	Sqrt() FieldElement
	TestBitZero() bool
	Equals(b FieldElement) bool
	String() string
}

// Fp represents an element in prime field Fp (integers mod p).
type Fp struct {
	q *big.Int // Field modulus
	x *big.Int // Value
}

// NewFp creates a new Fp field element.
func NewFp(q, x *big.Int) *Fp {
	result := new(big.Int).Mod(x, q)
	return &Fp{
		q: new(big.Int).Set(q),
		x: result,
	}
}

// ToBigInt returns the value as big.Int.
func (f *Fp) ToBigInt() *big.Int {
	return new(big.Int).Set(f.x)
}

// GetFieldSize returns the bit length of the field.
func (f *Fp) GetFieldSize() int {
	return f.q.BitLen()
}

// Add adds two field elements.
func (f *Fp) Add(b FieldElement) FieldElement {
	bFp := b.(*Fp)
	result := new(big.Int).Add(f.x, bFp.x)
	result.Mod(result, f.q)
	return &Fp{q: f.q, x: result}
}

// AddOne adds 1 to the field element.
func (f *Fp) AddOne() FieldElement {
	result := new(big.Int).Add(f.x, big.NewInt(1))
	result.Mod(result, f.q)
	return &Fp{q: f.q, x: result}
}

// Subtract subtracts two field elements.
func (f *Fp) Subtract(b FieldElement) FieldElement {
	bFp := b.(*Fp)
	result := new(big.Int).Sub(f.x, bFp.x)
	result.Mod(result, f.q)
	return &Fp{q: f.q, x: result}
}

// Multiply multiplies two field elements.
func (f *Fp) Multiply(b FieldElement) FieldElement {
	bFp := b.(*Fp)
	result := new(big.Int).Mul(f.x, bFp.x)
	result.Mod(result, f.q)
	return &Fp{q: f.q, x: result}
}

// Divide divides two field elements.
func (f *Fp) Divide(b FieldElement) FieldElement {
	bFp := b.(*Fp)
	// Compute modular inverse of b
	inv := new(big.Int).ModInverse(bFp.x, f.q)
	result := new(big.Int).Mul(f.x, inv)
	result.Mod(result, f.q)
	return &Fp{q: f.q, x: result}
}

// Negate negates the field element.
func (f *Fp) Negate() FieldElement {
	result := new(big.Int).Neg(f.x)
	result.Mod(result, f.q)
	return &Fp{q: f.q, x: result}
}

// Square squares the field element.
func (f *Fp) Square() FieldElement {
	result := new(big.Int).Mul(f.x, f.x)
	result.Mod(result, f.q)
	return &Fp{q: f.q, x: result}
}

// Invert inverts the field element.
func (f *Fp) Invert() FieldElement {
	result := new(big.Int).ModInverse(f.x, f.q)
	return &Fp{q: f.q, x: result}
}

// Sqrt computes the square root if it exists.
func (f *Fp) Sqrt() FieldElement {
	// Check if q % 4 == 3 (easy case)
	qMod4 := new(big.Int).And(f.q, big.NewInt(3))
	if qMod4.Cmp(big.NewInt(3)) == 0 {
		// z = x^((q+1)/4)
		exp := new(big.Int).Add(f.q, big.NewInt(1))
		exp.Rsh(exp, 2)
		z := new(big.Int).Exp(f.x, exp, f.q)
		
		// Verify: z^2 == x
		check := new(big.Int).Mul(z, z)
		check.Mod(check, f.q)
		if check.Cmp(f.x) == 0 {
			return &Fp{q: f.q, x: z}
		}
		return nil
	}
	
	// Tonelli-Shanks algorithm for general case
	// Check if x is quadratic residue: x^((q-1)/2) == 1
	exp := new(big.Int).Sub(f.q, big.NewInt(1))
	exp.Rsh(exp, 1)
	legendre := new(big.Int).Exp(f.x, exp, f.q)
	if legendre.Cmp(big.NewInt(1)) != 0 {
		return nil // No square root exists
	}
	
	// Find s and t such that q-1 = 2^s * t
	s := 0
	t := new(big.Int).Sub(f.q, big.NewInt(1))
	for new(big.Int).And(t, big.NewInt(1)).Cmp(big.NewInt(0)) == 0 {
		t.Rsh(t, 1)
		s++
	}
	
	// Find a quadratic non-residue z
	z := big.NewInt(1)
	qMinus1 := new(big.Int).Sub(f.q, big.NewInt(1))
	exp = new(big.Int).Rsh(qMinus1, 1)
	for {
		z.Add(z, big.NewInt(1))
		legendre = new(big.Int).Exp(z, exp, f.q)
		if legendre.Cmp(qMinus1) == 0 {
			break
		}
	}
	
	c := new(big.Int).Exp(z, t, f.q)
	tPlusOne := new(big.Int).Add(t, big.NewInt(1))
	tPlusOne.Rsh(tPlusOne, 1)
	r := new(big.Int).Exp(f.x, tPlusOne, f.q)
	tVal := new(big.Int).Exp(f.x, t, f.q)
	m := s
	
	for {
		if tVal.Cmp(big.NewInt(1)) == 0 {
			return &Fp{q: f.q, x: r}
		}
		
		// Find least i such that t^(2^i) == 1
		i := 1
		temp := new(big.Int).Mul(tVal, tVal)
		temp.Mod(temp, f.q)
		for temp.Cmp(big.NewInt(1)) != 0 && i < m {
			temp.Mul(temp, temp)
			temp.Mod(temp, f.q)
			i++
		}
		
		// b = c^(2^(m-i-1))
		b := new(big.Int).Set(c)
		for j := 0; j < m-i-1; j++ {
			b.Mul(b, b)
			b.Mod(b, f.q)
		}
		
		r.Mul(r, b)
		r.Mod(r, f.q)
		c.Mul(b, b)
		c.Mod(c, f.q)
		tVal.Mul(tVal, c)
		tVal.Mod(tVal, f.q)
		m = i
	}
}

// TestBitZero returns true if the least significant bit is 1.
func (f *Fp) TestBitZero() bool {
	return f.x.Bit(0) == 1
}

// Equals checks if two field elements are equal.
func (f *Fp) Equals(b FieldElement) bool {
	if b == nil {
		return false
	}
	bFp, ok := b.(*Fp)
	if !ok {
		return false
	}
	return f.x.Cmp(bFp.x) == 0 && f.q.Cmp(bFp.q) == 0
}

// String returns string representation.
func (f *Fp) String() string {
	return f.x.Text(16)
}
