package pkcs8

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	
	asn "github.com/lihongjie0209/sm-go-bc/asn1"
)

// PrivateKeyInfo represents a PKCS#8 private key structure.
//
// PrivateKeyInfo ::= SEQUENCE {
//   version         INTEGER,
//   algorithm       AlgorithmIdentifier,
//   privateKey      OCTET STRING
// }
//
// This matches org.bouncycastle.asn1.pkcs.PrivateKeyInfo.
type PrivateKeyInfo struct {
	Version    int
	Algorithm  pkix.AlgorithmIdentifier
	PrivateKey []byte
}

// SubjectPublicKeyInfo represents a public key structure.
//
// SubjectPublicKeyInfo ::= SEQUENCE {
//   algorithm       AlgorithmIdentifier,
//   subjectPublicKey BIT STRING
// }
//
// This matches org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.
type SubjectPublicKeyInfo struct {
	Algorithm        pkix.AlgorithmIdentifier
	SubjectPublicKey asn1.BitString
}

// ParsePrivateKeyInfo parses a PKCS#8 private key from DER-encoded bytes.
func ParsePrivateKeyInfo(der []byte) (*PrivateKeyInfo, error) {
	var pki PrivateKeyInfo
	_, err := asn1.Unmarshal(der, &pki)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS#8 private key: %w", err)
	}
	return &pki, nil
}

// MarshalPrivateKeyInfo marshals a PrivateKeyInfo to DER-encoded bytes.
func MarshalPrivateKeyInfo(pki *PrivateKeyInfo) ([]byte, error) {
	return asn1.Marshal(*pki)
}

// ParseSubjectPublicKeyInfo parses a SubjectPublicKeyInfo from DER-encoded bytes.
func ParseSubjectPublicKeyInfo(der []byte) (*SubjectPublicKeyInfo, error) {
	var spki SubjectPublicKeyInfo
	_, err := asn1.Unmarshal(der, &spki)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SubjectPublicKeyInfo: %w", err)
	}
	return &spki, nil
}

// MarshalSubjectPublicKeyInfo marshals a SubjectPublicKeyInfo to DER-encoded bytes.
func MarshalSubjectPublicKeyInfo(spki *SubjectPublicKeyInfo) ([]byte, error) {
	return asn1.Marshal(*spki)
}

// SM2 OIDs
var (
	// OID for SM2 signature algorithm with SM3 hash (1.2.156.10197.1.501)
	OidSM2 = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 501}
	
	// OID for SM2 encryption (1.2.156.10197.1.301.1)
	OidSM2Encryption = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 301, 1}
	
	// OID for SM3 hash (1.2.156.10197.1.401)
	OidSM3 = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 401}
	
	// OID for SM2 curve parameters (1.2.156.10197.1.301)
	OidSM2Curve = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 301}
)

// NewSM2AlgorithmIdentifier creates an AlgorithmIdentifier for SM2.
func NewSM2AlgorithmIdentifier() pkix.AlgorithmIdentifier {
	// SM2 uses the curve OID as the algorithm parameter
	curveBytes, _ := asn1.Marshal(OidSM2Curve)
	
	// Extract just the OID value bytes, skipping the tag (1 byte) and length (1 byte)
	// DER encoding: TAG | LENGTH | VALUE
	// For standard OIDs, tag=0x06 and length is usually 1 byte
	const derHeaderSize = 2 // TAG (1 byte) + LENGTH (1 byte)
	
	return pkix.AlgorithmIdentifier{
		Algorithm:  OidSM2,
		Parameters: asn1.RawValue{
			Tag:   asn.TagObjectIdentifier,
			Bytes: curveBytes[derHeaderSize:],
		},
	}
}

// NewSM2PublicKeyAlgorithmIdentifier creates an AlgorithmIdentifier for SM2 public key.
func NewSM2PublicKeyAlgorithmIdentifier() pkix.AlgorithmIdentifier {
	// For public keys, we use the encryption OID
	curveBytes, _ := asn1.Marshal(OidSM2Curve)
	
	// Extract just the OID value bytes, skipping the tag (1 byte) and length (1 byte)
	// DER encoding: TAG | LENGTH | VALUE
	const derHeaderSize = 2
	
	return pkix.AlgorithmIdentifier{
		Algorithm:  OidSM2Encryption,
		Parameters: asn1.RawValue{
			Tag:   asn.TagObjectIdentifier,
			Bytes: curveBytes[derHeaderSize:],
		},
	}
}
