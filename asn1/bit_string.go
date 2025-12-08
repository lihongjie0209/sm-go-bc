package asn1

import (
	"encoding/asn1"
)

// ASN1BitString represents an ASN.1 BIT STRING.
//
// This struct matches org.bouncycastle.asn1.ASN1BitString.
type ASN1BitString struct {
	ASN1Object
	bytes      []byte
	padBits    int
}

// NewASN1BitString creates a new ASN1BitString from bytes.
// padBits indicates the number of unused bits in the last byte.
func NewASN1BitString(bytes []byte, padBits int) *ASN1BitString {
	// Make a copy to avoid external modification
	bytesCopy := make([]byte, len(bytes))
	copy(bytesCopy, bytes)
	
	// Encode using Go's asn1 package
	bitString := asn1.BitString{
		Bytes:     bytesCopy,
		BitLength: len(bytesCopy)*8 - padBits,
	}
	encoded, _ := asn1.Marshal(bitString)
	
	return &ASN1BitString{
		ASN1Object: ASN1Object{
			tag:   TagBitString,
			bytes: encoded,
		},
		bytes:   bytesCopy,
		padBits: padBits,
	}
}

// NewASN1BitStringFromBytes creates a new ASN1BitString with no padding.
func NewASN1BitStringFromBytes(bytes []byte) *ASN1BitString {
	return NewASN1BitString(bytes, 0)
}

// NewASN1BitStringFromEncoded creates a new ASN1BitString from encoded bytes.
func NewASN1BitStringFromEncoded(encoded []byte) (*ASN1BitString, error) {
	var bitString asn1.BitString
	_, err := asn1.Unmarshal(encoded, &bitString)
	if err != nil {
		return nil, err
	}
	
	padBits := len(bitString.Bytes)*8 - bitString.BitLength
	
	return &ASN1BitString{
		ASN1Object: ASN1Object{
			tag:   TagBitString,
			bytes: encoded,
		},
		bytes:   bitString.Bytes,
		padBits: padBits,
	}, nil
}

// GetBytes returns a copy of the bytes.
func (b *ASN1BitString) GetBytes() []byte {
	result := make([]byte, len(b.bytes))
	copy(result, b.bytes)
	return result
}

// GetPadBits returns the number of pad bits.
func (b *ASN1BitString) GetPadBits() int {
	return b.padBits
}

// ToASN1Primitive returns itself.
func (b *ASN1BitString) ToASN1Primitive() ASN1Primitive {
	return b
}

// GetEncoded returns the DER-encoded bytes.
func (b *ASN1BitString) GetEncoded() ([]byte, error) {
	if b.bytes != nil {
		return b.bytes, nil
	}
	
	bitString := asn1.BitString{
		Bytes:     b.bytes,
		BitLength: len(b.bytes)*8 - b.padBits,
	}
	encoded, err := asn1.Marshal(bitString)
	if err != nil {
		return nil, err
	}
	b.bytes = encoded
	return encoded, nil
}
