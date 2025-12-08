package pkcs10

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	
	"github.com/lihongjie0209/sm-go-bc/crypto/signers"
	"github.com/lihongjie0209/sm-go-bc/math/ec"
	"github.com/lihongjie0209/sm-go-bc/pkcs8"
)

// CertificationRequest represents a PKCS#10 certificate signing request.
//
// CertificationRequest ::= SEQUENCE {
//   certificationRequestInfo CertificationRequestInfo,
//   signatureAlgorithm       AlgorithmIdentifier,
//   signature                BIT STRING
// }
//
// CertificationRequestInfo ::= SEQUENCE {
//   version       INTEGER { v1(0) },
//   subject       Name,
//   subjectPKInfo SubjectPublicKeyInfo,
//   attributes    [0] Attributes
// }
type CertificationRequest struct {
	Raw                     []byte // Complete ASN.1 DER content
	RawTBSCertificationRequest []byte // Request info part (TBS = "To Be Signed")
	
	Version            int
	Subject            pkix.Name
	PublicKey          *ec.Point
	RawSubjectPublicKeyInfo []byte
	Attributes         []pkix.AttributeTypeAndValue
	
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          []byte
}

// ParseCertificationRequest parses a PKCS#10 CSR from DER-encoded bytes.
func ParseCertificationRequest(der []byte) (*CertificationRequest, error) {
	csr := &CertificationRequest{
		Raw: der,
	}
	
	// Parse the top-level structure
	var rawCSR struct {
		Raw                asn1.RawContent
		TBSCertificationRequest asn1.RawContent
		SignatureAlgorithm pkix.AlgorithmIdentifier
		SignatureValue     asn1.BitString
	}
	
	_, err := asn1.Unmarshal(der, &rawCSR)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CSR: %w", err)
	}
	
	csr.RawTBSCertificationRequest = rawCSR.TBSCertificationRequest
	csr.SignatureAlgorithm = rawCSR.SignatureAlgorithm
	csr.Signature = rawCSR.SignatureValue.RightAlign()
	
	// Parse TBS CertificationRequest
	var tbs struct {
		Version       int
		Subject       asn1.RawValue
		PublicKey     asn1.RawContent
		Attributes    []pkix.AttributeTypeAndValue `asn1:"tag:0,optional"`
	}
	
	_, err = asn1.Unmarshal(csr.RawTBSCertificationRequest, &tbs)
	if err != nil {
		return nil, fmt.Errorf("failed to parse TBS CSR: %w", err)
	}
	
	csr.Version = tbs.Version
	csr.Attributes = tbs.Attributes
	
	// Parse subject name
	var subjectRDN pkix.RDNSequence
	_, err = asn1.Unmarshal(tbs.Subject.FullBytes, &subjectRDN)
	if err != nil {
		return nil, fmt.Errorf("failed to parse subject: %w", err)
	}
	csr.Subject.FillFromRDNSequence(&subjectRDN)
	
	// Parse public key
	csr.RawSubjectPublicKeyInfo = tbs.PublicKey
	pubKey, err := pkcs8.ParseSM2PublicKey(tbs.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}
	csr.PublicKey = pubKey
	
	return csr, nil
}

// CreateCertificationRequest creates a new PKCS#10 CSR.
func CreateCertificationRequest(
	subject pkix.Name,
	publicKey *ec.Point,
	privateKey *big.Int,
	attributes []pkix.AttributeTypeAndValue,
) ([]byte, error) {
	// Validate inputs
	if privateKey == nil {
		return nil, fmt.Errorf("private key is required")
	}
	if publicKey == nil {
		return nil, fmt.Errorf("public key is required")
	}
	
	// Encode public key
	pubKeyBytes, err := pkcs8.MarshalSM2PublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encode public key: %w", err)
	}
	
	var spki pkcs8.SubjectPublicKeyInfo
	_, err = asn1.Unmarshal(pubKeyBytes, &spki)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key info: %w", err)
	}
	
	// Build TBS CertificationRequest
	tbs := struct {
		Version    int
		Subject    pkix.RDNSequence
		PublicKey  pkcs8.SubjectPublicKeyInfo
		Attributes []pkix.AttributeTypeAndValue `asn1:"tag:0,optional"`
	}{
		Version:    0, // v1
		Subject:    subject.ToRDNSequence(),
		PublicKey:  spki,
		Attributes: attributes,
	}
	
	tbsBytes, err := asn1.Marshal(tbs)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal TBS CSR: %w", err)
	}
	
	// Sign the TBS CSR
	signer := signers.NewSM2Signer()
	err = signer.Init(true, publicKey, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize signer: %w", err)
	}
	signer.Update(tbsBytes)
	signature, err := signer.GenerateSignature()
	if err != nil {
		return nil, fmt.Errorf("failed to sign CSR: %w", err)
	}
	
	// Build final CSR
	sigAlg := pkcs8.NewSM2AlgorithmIdentifier()
	csr := struct {
		TBSCertificationRequest asn1.RawContent
		SignatureAlgorithm      pkix.AlgorithmIdentifier
		SignatureValue          asn1.BitString
	}{
		TBSCertificationRequest: tbsBytes,
		SignatureAlgorithm:      sigAlg,
		SignatureValue: asn1.BitString{
			Bytes:     signature,
			BitLength: len(signature) * 8,
		},
	}
	
	return asn1.Marshal(csr)
}

// VerifySignature verifies the signature on the CSR.
func (csr *CertificationRequest) VerifySignature() error {
	// Verify it's an SM2 CSR
	if !csr.SignatureAlgorithm.Algorithm.Equal(pkcs8.OidSM2) {
		return fmt.Errorf("unsupported signature algorithm: %v", csr.SignatureAlgorithm.Algorithm)
	}
	
	// Verify using SM2Signer
	verifier := signers.NewSM2Signer()
	err := verifier.Init(false, csr.PublicKey, nil)
	if err != nil {
		return fmt.Errorf("failed to initialize verifier: %w", err)
	}
	verifier.Update(csr.RawTBSCertificationRequest)
	
	valid, err := verifier.VerifySignature(csr.Signature)
	if err != nil {
		return fmt.Errorf("verification error: %w", err)
	}
	if !valid {
		return fmt.Errorf("signature verification failed")
	}
	
	return nil
}
