package x509

import (
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"testing"
	"time"
	
	"github.com/lihongjie0209/sm-go-bc/crypto/sm2"
	"github.com/lihongjie0209/sm-go-bc/crypto/signers"
	"github.com/lihongjie0209/sm-go-bc/math/ec"
	"github.com/lihongjie0209/sm-go-bc/pkcs8"
)

// TestCreateSimpleSM2Certificate tests creating a basic SM2 self-signed certificate.
func TestCreateSimpleSM2Certificate(t *testing.T) {
	// Generate a key pair for testing
	d, Q := generateTestKeyPair(t)
	
	// Create a simple certificate template
	template := &CertificateTemplate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test SM2 Certificate",
			Organization: []string{"Test Org"},
			Country:      []string{"CN"},
		},
		NotBefore:   time.Now().Add(-1 * time.Hour),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:    KeyUsageDigitalSignature | KeyUsageCertSign,
		IsCA:        true,
		MaxPathLen:  0,
	}
	
	// Create self-signed certificate
	certDER, err := CreateCertificate(template, template, Q, d, Q)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}
	
	t.Logf("Certificate DER length: %d bytes", len(certDER))
	
	// For now, just verify the certificate was created successfully
	// TODO: Add ParseCertificate and full verification later
	t.Logf("Certificate created successfully")
}

// CertificateTemplate represents a template for creating X.509 certificates.
type CertificateTemplate struct {
	SerialNumber   *big.Int
	Subject        pkix.Name
	Issuer         pkix.Name
	NotBefore      time.Time
	NotAfter       time.Time
	KeyUsage       KeyUsage
	ExtKeyUsage    []ExtKeyUsage
	IsCA           bool
	MaxPathLen     int
	MaxPathLenZero bool
	SubjectKeyId   []byte
	AuthorityKeyId []byte
}

// CreateCertificate creates a new certificate.
//
// The certificate is signed by parent. If parent equals template, the certificate
// is self-signed. The parameter priv is the private key of the signer and pub is
// the public key of the certificate being created.
func CreateCertificate(
	template, parent *CertificateTemplate,
	pub *ec.Point,
	privKey *big.Int,
	signerPub *ec.Point,
) ([]byte, error) {
	// Signature algorithm identifier
	sigAlg := pkcs8.NewSM2AlgorithmIdentifier()
	
	// Build issuer name
	var issuer pkix.Name
	if parent == template {
		issuer = template.Subject
	} else {
		issuer = parent.Subject
	}
	
	// Subject public key info - parse to get the raw structure
	pubKeyBytes, err := pkcs8.MarshalSM2PublicKey(pub)
	if err != nil {
		return nil, err
	}
	
	var spki pkcs8.SubjectPublicKeyInfo
	_, err = asn1.Unmarshal(pubKeyBytes, &spki)
	if err != nil {
		return nil, err
	}
	
	// Extensions
	var extensions []pkix.Extension
	
	// Basic Constraints
	if template.IsCA {
		bcValue, err := asn1.Marshal(struct {
			IsCA       bool `asn1:"optional"`
			MaxPathLen int  `asn1:"optional,default:-1"`
		}{
			IsCA:       true,
			MaxPathLen: template.MaxPathLen,
		})
		if err != nil {
			return nil, err
		}
		extensions = append(extensions, pkix.Extension{
			Id:       oidExtensionBasicConstraints,
			Critical: true,
			Value:    bcValue,
		})
	}
	
	// Key Usage
	if template.KeyUsage != 0 {
		var keyUsageBytes []byte
		if template.KeyUsage&0xFF00 != 0 {
			keyUsageBytes = []byte{byte(template.KeyUsage), byte(template.KeyUsage >> 8)}
		} else {
			keyUsageBytes = []byte{byte(template.KeyUsage)}
		}
		
		kuValue, err := asn1.Marshal(asn1.BitString{
			Bytes:     keyUsageBytes,
			BitLength: len(keyUsageBytes) * 8,
		})
		if err != nil {
			return nil, err
		}
		extensions = append(extensions, pkix.Extension{
			Id:       oidExtensionKeyUsage,
			Critical: true,
			Value:    kuValue,
		})
	}
	
	// Build TBS Certificate
	tbs := struct {
		Version            int                      `asn1:"explicit,default:0,tag:0"`
		SerialNumber       *big.Int
		SignatureAlgorithm pkix.AlgorithmIdentifier
		Issuer             pkix.RDNSequence
		Validity           struct {
			NotBefore, NotAfter time.Time
		}
		Subject    pkix.RDNSequence
		PublicKey  pkcs8.SubjectPublicKeyInfo
		Extensions []pkix.Extension `asn1:"optional,explicit,tag:3"`
	}{
		Version:            2, // v3
		SerialNumber:       template.SerialNumber,
		SignatureAlgorithm: sigAlg,
		Issuer:             issuer.ToRDNSequence(),
		Validity: struct {
			NotBefore, NotAfter time.Time
		}{
			NotBefore: template.NotBefore,
			NotAfter:  template.NotAfter,
		},
		Subject:    template.Subject.ToRDNSequence(),
		PublicKey:  spki,
		Extensions: extensions,
	}
	
	tbsBytes, err := asn1.Marshal(tbs)
	if err != nil {
		return nil, err
	}
	
	// Sign the TBS certificate
	signer := signers.NewSM2Signer()
	err = signer.Init(true, signerPub, privKey)
	if err != nil {
		return nil, err
	}
	signer.Update(tbsBytes)
	signature, err := signer.GenerateSignature()
	if err != nil {
		return nil, err
	}
	
	// TBS bytes are already marshalled, use them directly
	
	// Build final certificate
	cert := struct {
		TBSCertificate     asn1.RawContent
		SignatureAlgorithm pkix.AlgorithmIdentifier
		SignatureValue     asn1.BitString
	}{
		TBSCertificate:     tbsBytes,
		SignatureAlgorithm: sigAlg,
		SignatureValue: asn1.BitString{
			Bytes:     signature,
			BitLength: len(signature) * 8,
		},
	}
	
	return asn1.Marshal(cert)
}

// Helper functions
func generateTestKeyPair(t *testing.T) (*big.Int, *ec.Point) {
	n := sm2.GetN()
	d, err := randFieldElement(rand.Reader, n)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}
	
	G := sm2.GetG()
	Q := G.Multiply(d)
	
	return d, Q
}

func randFieldElement(random interface{}, n *big.Int) (*big.Int, error) {
	b := make([]byte, (n.BitLen()+7)/8)
	for {
		_, err := rand.Read(b)
		if err != nil {
			return nil, err
		}
		k := new(big.Int).SetBytes(b)
		if k.Sign() > 0 && k.Cmp(n) < 0 {
			return k, nil
		}
	}
}

func verifyCertificateSignature(cert *Certificate, publicKey *ec.Point) error {
	// Parse signature
	var sig struct {
		R, S *big.Int
	}
	_, err := asn1.Unmarshal(cert.Signature, &sig)
	if err != nil {
		return err
	}
	
	// Verify using SM2Signer
	verifier := signers.NewSM2Signer()
	err = verifier.Init(false, publicKey, nil)
	if err != nil {
		return err
	}
	verifier.Update(cert.RawTBSCertificate)
	
	// Reconstruct signature bytes
	sigBytes, err := asn1.Marshal(sig)
	if err != nil {
		return err
	}
	
	valid, err := verifier.VerifySignature(sigBytes)
	if err != nil {
		return err
	}
	if !valid {
		return fmt.Errorf("signature verification failed")
	}
	
	return nil
}
