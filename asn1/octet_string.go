package asn1

import (
	"encoding/asn1"
)

// ASN1OctetString represents an ASN.1 OCTET STRING.
//
// This struct matches org.bouncycastle.asn1.ASN1OctetString.
type ASN1OctetString struct {
	ASN1Object
	octets []byte
}

// NewASN1OctetString creates a new ASN1OctetString.
func NewASN1OctetString(octets []byte) *ASN1OctetString {
	bytes, _ := asn1.Marshal(octets)
	
	// Make a copy to avoid external modification
	octetsCopy := make([]byte, len(octets))
	copy(octetsCopy, octets)
	
	return &ASN1OctetString{
		ASN1Object: ASN1Object{
			tag:   TagOctetString,
			bytes: bytes,
		},
		octets: octetsCopy,
	}
}

// NewASN1OctetStringFromBytes creates a new ASN1OctetString from encoded bytes.
func NewASN1OctetStringFromBytes(bytes []byte) (*ASN1OctetString, error) {
	var octets []byte
	_, err := asn1.Unmarshal(bytes, &octets)
	if err != nil {
		return nil, err
	}
	
	return &ASN1OctetString{
		ASN1Object: ASN1Object{
			tag:   TagOctetString,
			bytes: bytes,
		},
		octets: octets,
	}, nil
}

// GetOctets returns a copy of the octet string value.
func (o *ASN1OctetString) GetOctets() []byte {
	result := make([]byte, len(o.octets))
	copy(result, o.octets)
	return result
}

// ToASN1Primitive returns itself.
func (o *ASN1OctetString) ToASN1Primitive() ASN1Primitive {
	return o
}

// GetEncoded returns the DER-encoded bytes.
func (o *ASN1OctetString) GetEncoded() ([]byte, error) {
	if o.bytes != nil {
		return o.bytes, nil
	}
	
	bytes, err := asn1.Marshal(o.octets)
	if err != nil {
		return nil, err
	}
	o.bytes = bytes
	return bytes, nil
}
