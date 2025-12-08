package asn1

import (
	"encoding/asn1"
	"fmt"
	"math/big"
)

// ASN1Integer represents an ASN.1 INTEGER.
//
// This struct matches org.bouncycastle.asn1.ASN1Integer.
type ASN1Integer struct {
	ASN1Object
	value *big.Int
}

// NewASN1Integer creates a new ASN1Integer from a big.Int.
func NewASN1Integer(value *big.Int) *ASN1Integer {
	return &ASN1Integer{
		ASN1Object: ASN1Object{
			tag:   TagInteger,
			bytes: nil, // Will be lazily encoded
		},
		value: new(big.Int).Set(value),
	}
}

// NewASN1IntegerFromInt64 creates a new ASN1Integer from an int64.
func NewASN1IntegerFromInt64(value int64) *ASN1Integer {
	return NewASN1Integer(big.NewInt(value))
}

// NewASN1IntegerFromBytes creates a new ASN1Integer from encoded bytes.
func NewASN1IntegerFromBytes(bytes []byte) (*ASN1Integer, error) {
	// Parse DER-encoded INTEGER manually
	// Format: TAG | LENGTH | VALUE
	if len(bytes) < 2 {
		return nil, fmt.Errorf("invalid ASN.1 INTEGER: too short")
	}
	
	if bytes[0] != TagInteger {
		return nil, fmt.Errorf("invalid ASN.1 INTEGER: wrong tag 0x%02x", bytes[0])
	}
	
	// Parse length
	length := int(bytes[1])
	dataStart := 2
	
	if length&0x80 != 0 {
		// Long form length
		numBytes := length & 0x7F
		if len(bytes) < 2+numBytes {
			return nil, fmt.Errorf("invalid ASN.1 INTEGER: truncated length")
		}
		length = 0
		for i := 0; i < numBytes; i++ {
			length = (length << 8) | int(bytes[2+i])
		}
		dataStart = 2 + numBytes
	}
	
	if len(bytes) < dataStart+length {
		return nil, fmt.Errorf("invalid ASN.1 INTEGER: truncated value")
	}
	
	// Extract value bytes
	valueBytes := bytes[dataStart : dataStart+length]
	
	// Convert to big.Int (handles negative numbers via two's complement)
	value := new(big.Int).SetBytes(valueBytes)
	
	// Check if negative (MSB is set)
	if len(valueBytes) > 0 && valueBytes[0]&0x80 != 0 {
		// Convert from two's complement
		// Create a mask of all 1s for the bit length
		mask := new(big.Int).Lsh(big.NewInt(1), uint(len(valueBytes)*8))
		value.Sub(value, mask)
	}
	
	return &ASN1Integer{
		ASN1Object: ASN1Object{
			tag:   TagInteger,
			bytes: bytes[:dataStart+length], // Store only the TLV
		},
		value: value,
	}, nil
}

// GetValue returns the integer value.
func (i *ASN1Integer) GetValue() *big.Int {
	return new(big.Int).Set(i.value)
}

// GetPositiveValue returns the absolute value.
func (i *ASN1Integer) GetPositiveValue() *big.Int {
	if i.value.Sign() >= 0 {
		return i.GetValue()
	}
	return new(big.Int).Abs(i.value)
}

// ToASN1Primitive returns itself.
func (i *ASN1Integer) ToASN1Primitive() ASN1Primitive {
	return i
}

// GetEncoded returns the DER-encoded bytes.
func (i *ASN1Integer) GetEncoded() ([]byte, error) {
	if i.bytes != nil {
		// Return a copy to prevent modification
		result := make([]byte, len(i.bytes))
		copy(result, i.bytes)
		return result, nil
	}
	
	// Use asn1.Marshal which properly handles big.Int encoding
	bytes, err := asn1.Marshal(i.value)
	if err != nil {
		return nil, err
	}
	i.bytes = bytes
	
	// Return a copy
	result := make([]byte, len(bytes))
	copy(result, bytes)
	return result, nil
}
