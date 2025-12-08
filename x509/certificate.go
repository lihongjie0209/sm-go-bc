package x509

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"time"
	
	"github.com/lihongjie0209/sm-go-bc/math/ec"
	"github.com/lihongjie0209/sm-go-bc/pkcs8"
)

// Certificate represents an X.509 certificate.
//
// This is a simplified implementation focused on SM2 certificates.
// For production use, consider using Go's standard x509 package with SM2 extensions.
type Certificate struct {
	Raw                     []byte // Complete ASN.1 DER content
	RawTBSCertificate       []byte // Certificate info part (TBS = "To Be Signed")
	RawSubjectPublicKeyInfo []byte // DER encoded public key
	
	Signature          []byte
	SignatureAlgorithm pkix.AlgorithmIdentifier
	
	PublicKeyAlgorithm pkix.AlgorithmIdentifier
	PublicKey          *ec.Point
	
	Version            int
	SerialNumber       *big.Int
	Issuer             pkix.Name
	Subject            pkix.Name
	NotBefore, NotAfter time.Time
	
	// Extensions
	KeyUsage               KeyUsage
	ExtKeyUsage            []ExtKeyUsage
	SubjectKeyId           []byte
	AuthorityKeyId         []byte
	IsCA                   bool
	MaxPathLen             int
	MaxPathLenZero         bool
	
	// SM2-specific
	IssuerUniqueId  asn1.BitString `asn1:"optional,tag:1"`
	SubjectUniqueId asn1.BitString `asn1:"optional,tag:2"`
}

// KeyUsage represents the set of actions that are valid for a given key.
type KeyUsage int

const (
	KeyUsageDigitalSignature KeyUsage = 1 << iota
	KeyUsageContentCommitment
	KeyUsageKeyEncipherment
	KeyUsageDataEncipherment
	KeyUsageKeyAgreement
	KeyUsageCertSign
	KeyUsageCRLSign
	KeyUsageEncipherOnly
	KeyUsageDecipherOnly
)

// ExtKeyUsage represents an extended set of actions for which a certificate can be used.
type ExtKeyUsage int

const (
	ExtKeyUsageAny ExtKeyUsage = iota
	ExtKeyUsageServerAuth
	ExtKeyUsageClientAuth
	ExtKeyUsageCodeSigning
	ExtKeyUsageEmailProtection
	ExtKeyUsageTimeStamping
	ExtKeyUsageOCSPSigning
)

// ParseCertificate parses an X.509 certificate from DER-encoded bytes.
func ParseCertificate(der []byte) (*Certificate, error) {
	cert := &Certificate{
		Raw: der,
	}
	
	// Parse the outer certificate structure
	var rawCert struct {
		TBSCertificate     asn1.RawValue
		SignatureAlgorithm pkix.AlgorithmIdentifier
		SignatureValue     asn1.BitString
	}
	
	rest, err := asn1.Unmarshal(der, &rawCert)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("trailing data after certificate")
	}
	
	cert.RawTBSCertificate = rawCert.TBSCertificate.FullBytes
	cert.SignatureAlgorithm = rawCert.SignatureAlgorithm
	cert.Signature = rawCert.SignatureValue.RightAlign()
	
	// Parse TBS Certificate
	err = parseTBSCertificate(cert)
	if err != nil {
		return nil, fmt.Errorf("failed to parse TBS certificate: %w", err)
	}
	
	return cert, nil
}

// parseTBSCertificate parses the TBSCertificate portion.
func parseTBSCertificate(cert *Certificate) error {
	var tbs struct {
		Version            int `asn1:"optional,explicit,default:0,tag:0"`
		SerialNumber       *big.Int
		SignatureAlgorithm pkix.AlgorithmIdentifier
		Issuer             asn1.RawValue
		Validity           struct {
			NotBefore, NotAfter time.Time
		}
		Subject         asn1.RawValue
		PublicKey       asn1.RawValue
		IssuerUniqueId  asn1.BitString   `asn1:"optional,tag:1"`
		SubjectUniqueId asn1.BitString   `asn1:"optional,tag:2"`
		Extensions      []pkix.Extension `asn1:"optional,explicit,tag:3"`
	}
	
	rest, err := asn1.Unmarshal(cert.RawTBSCertificate, &tbs)
	if err != nil {
		return err
	}
	if len(rest) > 0 {
		return fmt.Errorf("trailing data in TBS certificate")
	}
	
	cert.Version = tbs.Version
	cert.SerialNumber = tbs.SerialNumber
	cert.NotBefore = tbs.Validity.NotBefore
	cert.NotAfter = tbs.Validity.NotAfter
	cert.IssuerUniqueId = tbs.IssuerUniqueId
	cert.SubjectUniqueId = tbs.SubjectUniqueId
	
	// Parse names
	var issuerRDN pkix.RDNSequence
	_, err = asn1.Unmarshal(tbs.Issuer.FullBytes, &issuerRDN)
	if err != nil {
		return fmt.Errorf("failed to parse issuer: %w", err)
	}
	cert.Issuer.FillFromRDNSequence(&issuerRDN)
	
	var subjectRDN pkix.RDNSequence
	_, err = asn1.Unmarshal(tbs.Subject.FullBytes, &subjectRDN)
	if err != nil {
		return fmt.Errorf("failed to parse subject: %w", err)
	}
	cert.Subject.FillFromRDNSequence(&subjectRDN)
	
	// Parse public key
	cert.RawSubjectPublicKeyInfo = tbs.PublicKey.FullBytes
	pubKey, err := pkcs8.ParseSM2PublicKey(tbs.PublicKey.FullBytes)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}
	cert.PublicKey = pubKey
	
	// Parse extensions
	err = parseExtensions(cert, tbs.Extensions)
	if err != nil {
		return fmt.Errorf("failed to parse extensions: %w", err)
	}
	
	return nil
}

// parseExtensions parses certificate extensions.
func parseExtensions(cert *Certificate, extensions []pkix.Extension) error {
	for _, ext := range extensions {
		switch {
		case ext.Id.Equal(oidExtensionKeyUsage):
			var usageBits asn1.BitString
			_, err := asn1.Unmarshal(ext.Value, &usageBits)
			if err != nil {
				return fmt.Errorf("failed to parse key usage: %w", err)
			}
			if len(usageBits.Bytes) > 0 {
				cert.KeyUsage = KeyUsage(usageBits.Bytes[0])
				if len(usageBits.Bytes) > 1 {
					cert.KeyUsage |= KeyUsage(usageBits.Bytes[1]) << 8
				}
			}
			
		case ext.Id.Equal(oidExtensionBasicConstraints):
			var constraints struct {
				IsCA       bool `asn1:"optional"`
				MaxPathLen int  `asn1:"optional,default:-1"`
			}
			_, err := asn1.Unmarshal(ext.Value, &constraints)
			if err != nil {
				return fmt.Errorf("failed to parse basic constraints: %w", err)
			}
			cert.IsCA = constraints.IsCA
			cert.MaxPathLen = constraints.MaxPathLen
			if constraints.MaxPathLen == 0 {
				cert.MaxPathLenZero = true
			}
			
		case ext.Id.Equal(oidExtensionSubjectKeyId):
			_, err := asn1.Unmarshal(ext.Value, &cert.SubjectKeyId)
			if err != nil {
				return fmt.Errorf("failed to parse subject key ID: %w", err)
			}
			
		case ext.Id.Equal(oidExtensionAuthorityKeyId):
			var authKeyId struct {
				KeyIdentifier []byte `asn1:"optional,tag:0"`
			}
			_, err := asn1.Unmarshal(ext.Value, &authKeyId)
			if err != nil {
				return fmt.Errorf("failed to parse authority key ID: %w", err)
			}
			cert.AuthorityKeyId = authKeyId.KeyIdentifier
		}
	}
	
	return nil
}

// VerifySignature verifies the signature on the certificate using the provided public key.
// Note: This is a simplified implementation. For production use, consider using
// Go's standard x509 package with SM2 extensions for full certificate chain validation.
func (c *Certificate) VerifySignature(publicKey *ec.Point) error {
	// Note: Full implementation requires importing crypto/signers which would create
	// a circular dependency (signers -> sm2 -> this package might import signers).
	// Users should use the verifyCertificateSignature pattern shown in tests.
	return fmt.Errorf("certificate signature verification not yet implemented - see test file for pattern")
}

// OIDs for certificate extensions
var (
	oidExtensionSubjectKeyId        = asn1.ObjectIdentifier{2, 5, 29, 14}
	oidExtensionKeyUsage            = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidExtensionExtendedKeyUsage    = asn1.ObjectIdentifier{2, 5, 29, 37}
	oidExtensionAuthorityKeyId      = asn1.ObjectIdentifier{2, 5, 29, 35}
	oidExtensionBasicConstraints    = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidExtensionSubjectAltName      = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidExtensionCertificatePolicies = asn1.ObjectIdentifier{2, 5, 29, 32}
)
