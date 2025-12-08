package asn1

import (
	"bytes"
	"math/big"
	"testing"
)

// TestASN1Integer tests ASN.1 INTEGER encoding/decoding.
func TestASN1Integer(t *testing.T) {
	t.Run("PositiveInteger", func(t *testing.T) {
		value := big.NewInt(12345)
		asn1Int := NewASN1Integer(value)
		
		if asn1Int.GetTag() != TagInteger {
			t.Errorf("Expected tag %d, got %d", TagInteger, asn1Int.GetTag())
		}
		
		encoded, err := asn1Int.GetEncoded()
		if err != nil {
			t.Fatalf("GetEncoded failed: %v", err)
		}
		
		decoded, err := NewASN1IntegerFromBytes(encoded)
		if err != nil {
			t.Fatalf("NewASN1IntegerFromBytes failed: %v", err)
		}
		
		if decoded.GetValue().Cmp(value) != 0 {
			t.Errorf("Expected value %v, got %v", value, decoded.GetValue())
		}
	})
	
	t.Run("NegativeInteger", func(t *testing.T) {
		value := big.NewInt(-12345)
		asn1Int := NewASN1Integer(value)
		
		encoded, err := asn1Int.GetEncoded()
		if err != nil {
			t.Fatalf("GetEncoded failed: %v", err)
		}
		
		decoded, err := NewASN1IntegerFromBytes(encoded)
		if err != nil {
			t.Fatalf("NewASN1IntegerFromBytes failed: %v", err)
		}
		
		if decoded.GetValue().Cmp(value) != 0 {
			t.Errorf("Expected value %v, got %v", value, decoded.GetValue())
		}
	})
	
	t.Run("LargeInteger", func(t *testing.T) {
		value := new(big.Int)
		value.SetString("123456789012345678901234567890", 10)
		asn1Int := NewASN1Integer(value)
		
		encoded, err := asn1Int.GetEncoded()
		if err != nil {
			t.Fatalf("GetEncoded failed: %v", err)
		}
		
		decoded, err := NewASN1IntegerFromBytes(encoded)
		if err != nil {
			t.Fatalf("NewASN1IntegerFromBytes failed: %v", err)
		}
		
		if decoded.GetValue().Cmp(value) != 0 {
			t.Errorf("Expected value %v, got %v", value, decoded.GetValue())
		}
	})
}

// TestASN1OctetString tests ASN.1 OCTET STRING encoding/decoding.
func TestASN1OctetString(t *testing.T) {
	t.Run("EmptyString", func(t *testing.T) {
		octets := []byte{}
		asn1Str := NewASN1OctetString(octets)
		
		if asn1Str.GetTag() != TagOctetString {
			t.Errorf("Expected tag %d, got %d", TagOctetString, asn1Str.GetTag())
		}
		
		result := asn1Str.GetOctets()
		if len(result) != 0 {
			t.Errorf("Expected empty octets, got %d bytes", len(result))
		}
	})
	
	t.Run("NonEmptyString", func(t *testing.T) {
		octets := []byte("Hello, ASN.1!")
		asn1Str := NewASN1OctetString(octets)
		
		encoded, err := asn1Str.GetEncoded()
		if err != nil {
			t.Fatalf("GetEncoded failed: %v", err)
		}
		
		decoded, err := NewASN1OctetStringFromBytes(encoded)
		if err != nil {
			t.Fatalf("NewASN1OctetStringFromBytes failed: %v", err)
		}
		
		result := decoded.GetOctets()
		if !bytes.Equal(result, octets) {
			t.Errorf("Expected %v, got %v", octets, result)
		}
	})
	
	t.Run("BinaryData", func(t *testing.T) {
		octets := []byte{0x00, 0x01, 0x02, 0xff, 0xfe, 0xfd}
		asn1Str := NewASN1OctetString(octets)
		
		encoded, err := asn1Str.GetEncoded()
		if err != nil {
			t.Fatalf("GetEncoded failed: %v", err)
		}
		
		decoded, err := NewASN1OctetStringFromBytes(encoded)
		if err != nil {
			t.Fatalf("NewASN1OctetStringFromBytes failed: %v", err)
		}
		
		result := decoded.GetOctets()
		if !bytes.Equal(result, octets) {
			t.Errorf("Expected %v, got %v", octets, result)
		}
	})
}

// TestASN1ObjectIdentifier tests ASN.1 OBJECT IDENTIFIER encoding/decoding.
func TestASN1ObjectIdentifier(t *testing.T) {
	t.Run("SM2_OID", func(t *testing.T) {
		oidString := "1.2.156.10197.1.301"
		oid, err := NewASN1ObjectIdentifier(oidString)
		if err != nil {
			t.Fatalf("NewASN1ObjectIdentifier failed: %v", err)
		}
		
		if oid.GetTag() != TagObjectIdentifier {
			t.Errorf("Expected tag %d, got %d", TagObjectIdentifier, oid.GetTag())
		}
		
		if oid.GetID() != oidString {
			t.Errorf("Expected OID %s, got %s", oidString, oid.GetID())
		}
		
		encoded, err := oid.GetEncoded()
		if err != nil {
			t.Fatalf("GetEncoded failed: %v", err)
		}
		
		decoded, err := NewASN1ObjectIdentifierFromBytes(encoded)
		if err != nil {
			t.Fatalf("NewASN1ObjectIdentifierFromBytes failed: %v", err)
		}
		
		if decoded.GetID() != oidString {
			t.Errorf("Expected OID %s, got %s", oidString, decoded.GetID())
		}
	})
	
	t.Run("SM3_OID", func(t *testing.T) {
		oidString := "1.2.156.10197.1.401"
		oid, err := NewASN1ObjectIdentifier(oidString)
		if err != nil {
			t.Fatalf("NewASN1ObjectIdentifier failed: %v", err)
		}
		
		if oid.GetID() != oidString {
			t.Errorf("Expected OID %s, got %s", oidString, oid.GetID())
		}
	})
	
	t.Run("OIDEquality", func(t *testing.T) {
		oid1, _ := NewASN1ObjectIdentifier("1.2.3.4.5")
		oid2, _ := NewASN1ObjectIdentifier("1.2.3.4.5")
		oid3, _ := NewASN1ObjectIdentifier("1.2.3.4.6")
		
		if !oid1.Equal(oid2) {
			t.Error("Expected OIDs to be equal")
		}
		
		if oid1.Equal(oid3) {
			t.Error("Expected OIDs to be different")
		}
	})
}

// TestASN1BitString tests ASN.1 BIT STRING encoding/decoding.
func TestASN1BitString(t *testing.T) {
	t.Run("NoPadding", func(t *testing.T) {
		data := []byte{0xff, 0x00, 0xff}
		bitString := NewASN1BitString(data, 0)
		
		if bitString.GetTag() != TagBitString {
			t.Errorf("Expected tag %d, got %d", TagBitString, bitString.GetTag())
		}
		
		if bitString.GetPadBits() != 0 {
			t.Errorf("Expected 0 pad bits, got %d", bitString.GetPadBits())
		}
		
		result := bitString.GetBytes()
		if !bytes.Equal(result, data) {
			t.Errorf("Expected %v, got %v", data, result)
		}
	})
	
	t.Run("WithPadding", func(t *testing.T) {
		data := []byte{0xff, 0x80}  // Last 7 bits unused
		bitString := NewASN1BitString(data, 7)
		
		if bitString.GetPadBits() != 7 {
			t.Errorf("Expected 7 pad bits, got %d", bitString.GetPadBits())
		}
		
		result := bitString.GetBytes()
		if !bytes.Equal(result, data) {
			t.Errorf("Expected %v, got %v", data, result)
		}
	})
}

// TestASN1Tags tests tag utility functions.
func TestASN1Tags(t *testing.T) {
	t.Run("IsConstructed", func(t *testing.T) {
		if !IsConstructed(TagSequence | TagConstructed) {
			t.Error("Expected tag to be constructed")
		}
		
		if IsConstructed(TagInteger) {
			t.Error("Expected tag not to be constructed")
		}
	})
	
	t.Run("GetClass", func(t *testing.T) {
		if GetClass(TagInteger) != ClassUniversal {
			t.Error("Expected universal class")
		}
		
		if GetClass(TagContextSpecific|0x01) != ClassContextSpecific {
			t.Error("Expected context-specific class")
		}
	})
	
	t.Run("GetTagNumber", func(t *testing.T) {
		if GetTagNumber(TagInteger) != TagInteger {
			t.Errorf("Expected tag number %d, got %d", TagInteger, GetTagNumber(TagInteger))
		}
	})
}
