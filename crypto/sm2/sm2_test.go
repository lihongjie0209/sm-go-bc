package sm2

import (
	"math/big"
	"testing"
)

func TestSM2CurveParameters(t *testing.T) {
	curve := GetCurve()
	
	if curve == nil {
		t.Fatal("Failed to get SM2 curve")
	}
	
	// Check field size (256 bits)
	if curve.GetFieldSize() != 256 {
		t.Errorf("Expected field size 256, got %d", curve.GetFieldSize())
	}
}

func TestSM2BasePoint(t *testing.T) {
	g := GetG()
	
	if g == nil {
		t.Fatal("Failed to get base point")
	}
	
	if g.IsInfinity() {
		t.Error("Base point should not be infinity")
	}
	
	// Base point should be on curve
	if !g.IsValid() {
		t.Error("Base point is not valid on curve")
	}
}

func TestSM2BasePointOrder(t *testing.T) {
	g := GetG()
	n := GetN()
	
	// [n]G should equal infinity
	nG := g.Multiply(n)
	
	if !nG.IsInfinity() {
		t.Error("n*G should be infinity")
	}
}

func TestSM2PointAddition(t *testing.T) {
	g := GetG()
	
	// G + G should equal 2G
	g2_add := g.Add(g)
	g2_twice := g.Twice()
	
	if !g2_add.Equals(g2_twice) {
		t.Error("G + G should equal 2G")
	}
}

func TestSM2PointMultiplication(t *testing.T) {
	g := GetG()
	
	// 0*G = infinity
	zero := big.NewInt(0)
	result := g.Multiply(zero)
	if !result.IsInfinity() {
		t.Error("0*G should be infinity")
	}
	
	// 1*G = G
	one := big.NewInt(1)
	result = g.Multiply(one)
	if !result.Equals(g) {
		t.Error("1*G should equal G")
	}
	
	// 2*G
	two := big.NewInt(2)
	g2_mult := g.Multiply(two)
	g2_twice := g.Twice()
	if !g2_mult.Equals(g2_twice) {
		t.Error("2*G should equal G.Twice()")
	}
}

func TestSM2ValidateKeys(t *testing.T) {
	// Valid private key
	d := big.NewInt(12345)
	if !ValidatePrivateKey(d) {
		t.Error("Valid private key rejected")
	}
	
	// Invalid: d = 0
	d = big.NewInt(0)
	if ValidatePrivateKey(d) {
		t.Error("Private key 0 should be invalid")
	}
	
	// Invalid: d = n
	d = GetN()
	if ValidatePrivateKey(d) {
		t.Error("Private key n should be invalid")
	}
	
	// Invalid: d > n
	d = new(big.Int).Add(GetN(), big.NewInt(1))
	if ValidatePrivateKey(d) {
		t.Error("Private key > n should be invalid")
	}
}

func TestSM2PublicKeyValidation(t *testing.T) {
	g := GetG()
	
	// Valid public key: Q = d*G
	d := big.NewInt(12345)
	Q := g.Multiply(d)
	
	if !ValidatePublicKey(Q) {
		t.Error("Valid public key rejected")
	}
	
	// Invalid: point at infinity
	inf := g.Multiply(GetN())
	if ValidatePublicKey(inf) {
		t.Error("Point at infinity should be invalid public key")
	}
}

func TestSM2PointEncoding(t *testing.T) {
	g := GetG()
	
	// Test uncompressed encoding
	encoded := g.GetEncoded(false)
	if encoded[0] != 0x04 {
		t.Error("Uncompressed encoding should start with 0x04")
	}
	
	// Should be 1 + 32 + 32 = 65 bytes
	if len(encoded) != 65 {
		t.Errorf("Expected 65 bytes, got %d", len(encoded))
	}
	
	// Test compressed encoding
	encodedComp := g.GetEncoded(true)
	if encodedComp[0] != 0x02 && encodedComp[0] != 0x03 {
		t.Error("Compressed encoding should start with 0x02 or 0x03")
	}
	
	// Should be 1 + 32 = 33 bytes
	if len(encodedComp) != 33 {
		t.Errorf("Expected 33 bytes, got %d", len(encodedComp))
	}
}

func TestSM2PointDecoding(t *testing.T) {
	g := GetG()
	curve := GetCurve()
	
	// Encode and decode uncompressed
	encoded := g.GetEncoded(false)
	decoded := curve.DecodePoint(encoded)
	
	if !decoded.Equals(g) {
		t.Error("Decoded point doesn't match original (uncompressed)")
	}
	
	// Encode and decode compressed
	encodedComp := g.GetEncoded(true)
	decodedComp := curve.DecodePoint(encodedComp)
	
	if !decodedComp.Equals(g) {
		t.Error("Decoded point doesn't match original (compressed)")
	}
}

func TestSM2DomainParameters(t *testing.T) {
	params := GetDomainParameters()
	
	if params == nil {
		t.Fatal("Failed to get domain parameters")
	}
	
	if params.Curve == nil {
		t.Error("Curve is nil")
	}
	
	if params.G == nil {
		t.Error("Base point is nil")
	}
	
	if params.N == nil {
		t.Error("Order is nil")
	}
	
	if params.H != 1 {
		t.Errorf("Expected cofactor 1, got %d", params.H)
	}
}
