package asn1

import (
	"bytes"
	"encoding/asn1"
	"fmt"
)

// ASN1Sequence represents an ASN.1 SEQUENCE.
//
// This struct matches org.bouncycastle.asn1.ASN1Sequence.
type ASN1Sequence struct {
	ASN1Object
	elements []ASN1Encodable
}

// NewASN1Sequence creates a new ASN1Sequence from a slice of encodables.
func NewASN1Sequence(elements []ASN1Encodable) (*ASN1Sequence, error) {
	// Encode each element and concatenate
	var buf bytes.Buffer
	for _, elem := range elements {
		elemBytes, err := elem.GetEncoded()
		if err != nil {
			return nil, fmt.Errorf("failed to encode sequence element: %w", err)
		}
		buf.Write(elemBytes)
	}
	
	// Wrap in SEQUENCE tag
	sequenceBytes, err := asn1.Marshal(asn1.RawValue{
		Tag:        TagSequence,
		Class:      ClassUniversal,
		IsCompound: true,
		Bytes:      buf.Bytes(),
	})
	if err != nil {
		return nil, err
	}
	
	// Copy elements slice
	elemsCopy := make([]ASN1Encodable, len(elements))
	copy(elemsCopy, elements)
	
	return &ASN1Sequence{
		ASN1Object: ASN1Object{
			tag:   TagSequence | TagConstructed,
			bytes: sequenceBytes,
		},
		elements: elemsCopy,
	}, nil
}

// NewASN1SequenceFromBytes creates a new ASN1Sequence from encoded bytes.
func NewASN1SequenceFromBytes(bytes []byte) (*ASN1Sequence, error) {
	var rawValue asn1.RawValue
	_, err := asn1.Unmarshal(bytes, &rawValue)
	if err != nil {
		return nil, err
	}
	
	if rawValue.Tag != TagSequence {
		return nil, fmt.Errorf("expected SEQUENCE tag, got %d", rawValue.Tag)
	}
	
	// For now, we store the raw bytes
	// Parsing individual elements would require type information
	return &ASN1Sequence{
		ASN1Object: ASN1Object{
			tag:   TagSequence | TagConstructed,
			bytes: bytes,
		},
		elements: []ASN1Encodable{},
	}, nil
}

// Size returns the number of elements in the sequence.
func (s *ASN1Sequence) Size() int {
	return len(s.elements)
}

// GetObjectAt returns the element at the specified index.
func (s *ASN1Sequence) GetObjectAt(index int) ASN1Encodable {
	if index < 0 || index >= len(s.elements) {
		return nil
	}
	return s.elements[index]
}

// GetElements returns a copy of the elements slice.
func (s *ASN1Sequence) GetElements() []ASN1Encodable {
	result := make([]ASN1Encodable, len(s.elements))
	copy(result, s.elements)
	return result
}

// ToASN1Primitive returns itself.
func (s *ASN1Sequence) ToASN1Primitive() ASN1Primitive {
	return s
}

// GetEncoded returns the DER-encoded bytes.
func (s *ASN1Sequence) GetEncoded() ([]byte, error) {
	if s.bytes != nil {
		return s.bytes, nil
	}
	
	// Re-encode if needed
	var buf bytes.Buffer
	for _, elem := range s.elements {
		elemBytes, err := elem.GetEncoded()
		if err != nil {
			return nil, fmt.Errorf("failed to encode sequence element: %w", err)
		}
		buf.Write(elemBytes)
	}
	
	sequenceBytes, err := asn1.Marshal(asn1.RawValue{
		Tag:        TagSequence,
		Class:      ClassUniversal,
		IsCompound: true,
		Bytes:      buf.Bytes(),
	})
	if err != nil {
		return nil, err
	}
	
	s.bytes = sequenceBytes
	return sequenceBytes, nil
}
