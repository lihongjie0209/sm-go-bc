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
	// Marshal as ASN.1 INTEGER
	bytes, _ := asn1.Marshal(value)
	
	return &ASN1Integer{
		ASN1Object: ASN1Object{
			tag:   TagInteger,
			bytes: bytes,
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
	// Use Go's standard asn1.Unmarshal to decode big.Int properly
	// This handles negative numbers correctly
	var value big.Int
	_, err := asn1.Unmarshal(bytes, &value)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal INTEGER: %w", err)
	}
	
	return &ASN1Integer{
		ASN1Object: ASN1Object{
			tag:   TagInteger,
			bytes: bytes,
		},
		value: &value,
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
		return i.bytes, nil
	}
	
	bytes, err := asn1.Marshal(i.value)
	if err != nil {
		return nil, err
	}
	i.bytes = bytes
	return bytes, nil
}
