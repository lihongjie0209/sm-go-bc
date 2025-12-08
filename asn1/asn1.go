// Package asn1 provides ASN.1 encoding and decoding utilities.
//
// This package wraps Go's standard encoding/asn1 with a Bouncy Castle-compatible API.
package asn1

import (
	"encoding/asn1"
	"fmt"
)

// ASN1Encodable represents an object that can be encoded to ASN.1.
//
// This interface matches org.bouncycastle.asn1.ASN1Encodable.
type ASN1Encodable interface {
	// ToASN1Primitive converts this object to an ASN1Primitive.
	ToASN1Primitive() ASN1Primitive
	
	// GetEncoded returns the DER-encoded representation.
	GetEncoded() ([]byte, error)
}

// ASN1Primitive represents a primitive ASN.1 object.
//
// This interface matches org.bouncycastle.asn1.ASN1Primitive.
type ASN1Primitive interface {
	ASN1Encodable
	
	// GetTag returns the ASN.1 tag for this primitive.
	GetTag() int
}

// ASN1Object is a base struct for ASN.1 objects.
type ASN1Object struct {
	tag   int
	bytes []byte
}

// GetTag returns the ASN.1 tag.
func (o *ASN1Object) GetTag() int {
	return o.tag
}

// ToASN1Primitive returns itself.
func (o *ASN1Object) ToASN1Primitive() ASN1Primitive {
	return o
}

// GetEncoded returns the DER-encoded bytes.
func (o *ASN1Object) GetEncoded() ([]byte, error) {
	if o.bytes == nil {
		return nil, fmt.Errorf("ASN.1 object not initialized")
	}
	return o.bytes, nil
}

// ParseDER parses DER-encoded ASN.1 data.
func ParseDER(data []byte) (interface{}, error) {
	var result interface{}
	rest, err := asn1.Unmarshal(data, &result)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DER: %w", err)
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("extra data after DER object: %d bytes", len(rest))
	}
	return result, nil
}

// EncodeDER encodes a value to DER format.
func EncodeDER(val interface{}) ([]byte, error) {
	bytes, err := asn1.Marshal(val)
	if err != nil {
		return nil, fmt.Errorf("failed to encode DER: %w", err)
	}
	return bytes, nil
}
