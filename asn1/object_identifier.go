package asn1

import (
	"encoding/asn1"
	"fmt"
	"strings"
)

// ASN1ObjectIdentifier represents an ASN.1 OBJECT IDENTIFIER.
//
// This struct matches org.bouncycastle.asn1.ASN1ObjectIdentifier.
type ASN1ObjectIdentifier struct {
	ASN1Object
	oid asn1.ObjectIdentifier
}

// NewASN1ObjectIdentifier creates a new ASN1ObjectIdentifier from a dotted string.
func NewASN1ObjectIdentifier(oidString string) (*ASN1ObjectIdentifier, error) {
	// Parse OID string like "1.2.156.10197.1.301"
	parts := strings.Split(oidString, ".")
	oid := make([]int, len(parts))
	
	for i, part := range parts {
		var num int
		_, err := fmt.Sscanf(part, "%d", &num)
		if err != nil {
			return nil, fmt.Errorf("invalid OID component: %s", part)
		}
		oid[i] = num
	}
	
	bytes, err := asn1.Marshal(asn1.ObjectIdentifier(oid))
	if err != nil {
		return nil, err
	}
	
	return &ASN1ObjectIdentifier{
		ASN1Object: ASN1Object{
			tag:   TagObjectIdentifier,
			bytes: bytes,
		},
		oid: oid,
	}, nil
}

// NewASN1ObjectIdentifierFromInts creates a new ASN1ObjectIdentifier from integer components.
func NewASN1ObjectIdentifierFromInts(components ...int) (*ASN1ObjectIdentifier, error) {
	bytes, err := asn1.Marshal(asn1.ObjectIdentifier(components))
	if err != nil {
		return nil, err
	}
	
	return &ASN1ObjectIdentifier{
		ASN1Object: ASN1Object{
			tag:   TagObjectIdentifier,
			bytes: bytes,
		},
		oid: components,
	}, nil
}

// NewASN1ObjectIdentifierFromBytes creates a new ASN1ObjectIdentifier from encoded bytes.
func NewASN1ObjectIdentifierFromBytes(bytes []byte) (*ASN1ObjectIdentifier, error) {
	var oid asn1.ObjectIdentifier
	_, err := asn1.Unmarshal(bytes, &oid)
	if err != nil {
		return nil, err
	}
	
	return &ASN1ObjectIdentifier{
		ASN1Object: ASN1Object{
			tag:   TagObjectIdentifier,
			bytes: bytes,
		},
		oid: oid,
	}, nil
}

// GetID returns the OID as a dotted string.
func (o *ASN1ObjectIdentifier) GetID() string {
	parts := make([]string, len(o.oid))
	for i, component := range o.oid {
		parts[i] = fmt.Sprintf("%d", component)
	}
	return strings.Join(parts, ".")
}

// GetOID returns the OID as an asn1.ObjectIdentifier.
func (o *ASN1ObjectIdentifier) GetOID() asn1.ObjectIdentifier {
	result := make([]int, len(o.oid))
	copy(result, o.oid)
	return result
}

// Equal returns true if this OID equals another.
func (o *ASN1ObjectIdentifier) Equal(other *ASN1ObjectIdentifier) bool {
	if len(o.oid) != len(other.oid) {
		return false
	}
	for i := range o.oid {
		if o.oid[i] != other.oid[i] {
			return false
		}
	}
	return true
}

// ToASN1Primitive returns itself.
func (o *ASN1ObjectIdentifier) ToASN1Primitive() ASN1Primitive {
	return o
}

// GetEncoded returns the DER-encoded bytes.
func (o *ASN1ObjectIdentifier) GetEncoded() ([]byte, error) {
	if o.bytes != nil {
		return o.bytes, nil
	}
	
	bytes, err := asn1.Marshal(o.oid)
	if err != nil {
		return nil, err
	}
	o.bytes = bytes
	return bytes, nil
}

// Common OIDs for SM algorithms
var (
	// SM2 OID: 1.2.156.10197.1.301
	OID_SM2, _ = NewASN1ObjectIdentifier("1.2.156.10197.1.301")
	
	// SM3 OID: 1.2.156.10197.1.401
	OID_SM3, _ = NewASN1ObjectIdentifier("1.2.156.10197.1.401")
	
	// SM4 OID: 1.2.156.10197.1.104
	OID_SM4, _ = NewASN1ObjectIdentifier("1.2.156.10197.1.104")
	
	// SM2 with SM3 signature OID: 1.2.156.10197.1.501
	OID_SM2_WITH_SM3, _ = NewASN1ObjectIdentifier("1.2.156.10197.1.501")
)
