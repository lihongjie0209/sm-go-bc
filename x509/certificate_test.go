package x509

import (
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"io"
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
	t.Logf("Certificate created successfully")
}

// TestCertificateRoundtrip tests creating and parsing a certificate.
func TestCertificateRoundtrip(t *testing.T) {
	// Generate a key pair
	d, Q := generateTestKeyPair(t)
	
	// Create certificate
	template := &CertificateTemplate{
		SerialNumber: big.NewInt(12345),
		Subject: pkix.Name{
			CommonName:   "Test Certificate",
			Organization: []string{"Test Organization"},
			Country:      []string{"CN"},
		},
		NotBefore:  time.Now().Add(-1 * time.Hour).Truncate(time.Second),
		NotAfter:   time.Now().Add(365 * 24 * time.Hour).Truncate(time.Second),
		KeyUsage:   KeyUsageDigitalSignature | KeyUsageCertSign,
		IsCA:       true,
		MaxPathLen: 0,
	}
	
	certDER, err := CreateCertificate(template, template, Q, d, Q)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}
	
	// Parse the certificate
	cert, err := ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}
	
	// Verify fields
	if cert.SerialNumber.Cmp(template.SerialNumber) != 0 {
		t.Errorf("Serial number mismatch: got %v, want %v", cert.SerialNumber, template.SerialNumber)
	}
	
	if cert.Subject.CommonName != template.Subject.CommonName {
		t.Errorf("Subject CN mismatch: got %v, want %v", cert.Subject.CommonName, template.Subject.CommonName)
	}
	
	if !cert.NotBefore.Equal(template.NotBefore) {
		t.Errorf("NotBefore mismatch: got %v, want %v", cert.NotBefore, template.NotBefore)
	}
	
	if !cert.NotAfter.Equal(template.NotAfter) {
		t.Errorf("NotAfter mismatch: got %v, want %v", cert.NotAfter, template.NotAfter)
	}
	
	if cert.IsCA != template.IsCA {
		t.Errorf("IsCA mismatch: got %v, want %v", cert.IsCA, template.IsCA)
	}
	
	if cert.KeyUsage != template.KeyUsage {
		t.Errorf("KeyUsage mismatch: got %v, want %v", cert.KeyUsage, template.KeyUsage)
	}
	
	// Verify signature
	if err := verifyCertificateSignature(cert, Q); err != nil {
		t.Errorf("Signature verification failed: %v", err)
	}
	
	t.Log("Certificate roundtrip successful")
}

// TestCertificateWithExtensions tests creating a certificate with various extensions.
func TestCertificateWithExtensions(t *testing.T) {
	d, Q := generateTestKeyPair(t)
	
	template := &CertificateTemplate{
		SerialNumber: big.NewInt(54321),
		Subject: pkix.Name{
			CommonName:         "Extended Certificate",
			Organization:       []string{"Org"},
			OrganizationalUnit: []string{"Unit"},
			Country:            []string{"CN"},
			Locality:           []string{"Beijing"},
			Province:           []string{"Beijing"},
		},
		NotBefore:  time.Now().Add(-1 * time.Hour).Truncate(time.Second),
		NotAfter:   time.Now().Add(730 * 24 * time.Hour).Truncate(time.Second),
		KeyUsage:   KeyUsageDigitalSignature | KeyUsageKeyEncipherment | KeyUsageCertSign,
		IsCA:       true,
		MaxPathLen: 2,
	}
	
	certDER, err := CreateCertificate(template, template, Q, d, Q)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}
	
	// Parse and verify
	cert, err := ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}
	
	// Check all subject fields
	if cert.Subject.CommonName != template.Subject.CommonName {
		t.Errorf("CN mismatch")
	}
	if len(cert.Subject.Organization) == 0 || cert.Subject.Organization[0] != template.Subject.Organization[0] {
		t.Errorf("Organization mismatch")
	}
	if len(cert.Subject.OrganizationalUnit) == 0 || cert.Subject.OrganizationalUnit[0] != template.Subject.OrganizationalUnit[0] {
		t.Errorf("OrganizationalUnit mismatch")
	}
	if len(cert.Subject.Locality) == 0 || cert.Subject.Locality[0] != template.Subject.Locality[0] {
		t.Errorf("Locality mismatch")
	}
	if len(cert.Subject.Province) == 0 || cert.Subject.Province[0] != template.Subject.Province[0] {
		t.Errorf("Province mismatch")
	}
	
	if cert.MaxPathLen != template.MaxPathLen {
		t.Errorf("MaxPathLen mismatch: got %v, want %v", cert.MaxPathLen, template.MaxPathLen)
	}
	
	t.Log("Certificate with extensions successful")
}

// TestCertificateChain tests creating a certificate chain (CA -> intermediate -> leaf).
func TestCertificateChain(t *testing.T) {
	// Create CA
	caPriv, caPub := generateTestKeyPair(t)
	caTemplate := &CertificateTemplate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Root CA",
			Organization: []string{"Test CA"},
		},
		NotBefore:  time.Now().Add(-1 * time.Hour).Truncate(time.Second),
		NotAfter:   time.Now().Add(3650 * 24 * time.Hour).Truncate(time.Second),
		KeyUsage:   KeyUsageCertSign | KeyUsageCRLSign,
		IsCA:       true,
		MaxPathLen: 2,
	}
	
	caCertDER, err := CreateCertificate(caTemplate, caTemplate, caPub, caPriv, caPub)
	if err != nil {
		t.Fatalf("Failed to create CA cert: %v", err)
	}
	
	caCert, err := ParseCertificate(caCertDER)
	if err != nil {
		t.Fatalf("Failed to parse CA cert: %v", err)
	}
	
	// Create intermediate cert signed by CA
	intPriv, intPub := generateTestKeyPair(t)
	intTemplate := &CertificateTemplate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName:   "Intermediate CA",
			Organization: []string{"Test CA"},
		},
		NotBefore:  time.Now().Add(-1 * time.Hour).Truncate(time.Second),
		NotAfter:   time.Now().Add(1825 * 24 * time.Hour).Truncate(time.Second),
		KeyUsage:   KeyUsageCertSign | KeyUsageCRLSign,
		IsCA:       true,
		MaxPathLen: 1,
	}
	
	intCertDER, err := CreateCertificate(intTemplate, caTemplate, intPub, caPriv, caPub)
	if err != nil {
		t.Fatalf("Failed to create intermediate cert: %v", err)
	}
	
	intCert, err := ParseCertificate(intCertDER)
	if err != nil {
		t.Fatalf("Failed to parse intermediate cert: %v", err)
	}
	
	// Verify intermediate cert is signed by CA
	if err := verifyCertificateSignature(intCert, caPub); err != nil {
		t.Errorf("Failed to verify intermediate cert signature: %v", err)
	}
	
	// Create leaf cert signed by intermediate
	_, leafPub := generateTestKeyPair(t)
	leafTemplate := &CertificateTemplate{
		SerialNumber: big.NewInt(3),
		Subject: pkix.Name{
			CommonName: "leaf.example.com",
		},
		NotBefore: time.Now().Add(-1 * time.Hour).Truncate(time.Second),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour).Truncate(time.Second),
		KeyUsage:  KeyUsageDigitalSignature | KeyUsageKeyEncipherment,
		IsCA:      false,
	}
	
	leafCertDER, err := CreateCertificate(leafTemplate, intTemplate, leafPub, intPriv, intPub)
	if err != nil {
		t.Fatalf("Failed to create leaf cert: %v", err)
	}
	
	leafCert, err := ParseCertificate(leafCertDER)
	if err != nil {
		t.Fatalf("Failed to parse leaf cert: %v", err)
	}
	
	// Verify leaf cert is signed by intermediate
	if err := verifyCertificateSignature(leafCert, intPub); err != nil {
		t.Errorf("Failed to verify leaf cert signature: %v", err)
	}
	
	// Verify the chain
	if caCert.IsCA != true {
		t.Error("CA cert should be CA")
	}
	if intCert.IsCA != true {
		t.Error("Intermediate cert should be CA")
	}
	if leafCert.IsCA != false {
		t.Error("Leaf cert should not be CA")
	}
	
	t.Log("Certificate chain verification successful")
}

// TestMultipleCertificates tests creating multiple independent certificates.
func TestMultipleCertificates(t *testing.T) {
	for i := 0; i < 3; i++ {
		d, Q := generateTestKeyPair(t)
		
		template := &CertificateTemplate{
			SerialNumber: big.NewInt(int64(100 + i)),
			Subject: pkix.Name{
				CommonName: fmt.Sprintf("Test Cert %d", i),
			},
			NotBefore: time.Now().Add(-1 * time.Hour).Truncate(time.Second),
			NotAfter:  time.Now().Add(365 * 24 * time.Hour).Truncate(time.Second),
			KeyUsage:  KeyUsageDigitalSignature,
			IsCA:      false,
		}
		
		certDER, err := CreateCertificate(template, template, Q, d, Q)
		if err != nil {
			t.Fatalf("Failed to create cert %d: %v", i, err)
		}
		
		cert, err := ParseCertificate(certDER)
		if err != nil {
			t.Fatalf("Failed to parse cert %d: %v", i, err)
		}
		
		if cert.SerialNumber.Int64() != int64(100+i) {
			t.Errorf("Cert %d: serial number mismatch", i)
		}
		
		if err := verifyCertificateSignature(cert, Q); err != nil {
			t.Errorf("Cert %d: signature verification failed: %v", i, err)
		}
	}
	
	t.Log("Multiple certificates test passed")
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
	
	// Build final certificate structure manually
	// Certificate ::= SEQUENCE {
	//   tbsCertificate       TBSCertificate,
	//   signatureAlgorithm   AlgorithmIdentifier,
	//   signatureValue       BIT STRING  }
	
	// Marshal signature algorithm
	sigAlgBytes, err := asn1.Marshal(sigAlg)
	if err != nil {
		return nil, err
	}
	
	// Marshal signature value
	sigValueBytes, err := asn1.Marshal(asn1.BitString{
		Bytes:     signature,
		BitLength: len(signature) * 8,
	})
	if err != nil {
		return nil, err
	}
	
	// Build certificate as raw ASN.1 SEQUENCE
	certBytes := append([]byte{}, tbsBytes...)
	certBytes = append(certBytes, sigAlgBytes...)
	certBytes = append(certBytes, sigValueBytes...)
	
	// Wrap in SEQUENCE
	certLen := len(certBytes)
	var lengthBytes []byte
	if certLen < 128 {
		lengthBytes = []byte{byte(certLen)}
	} else {
		// Long form
		var lenBuf []byte
		for l := certLen; l > 0; l >>= 8 {
			lenBuf = append([]byte{byte(l)}, lenBuf...)
		}
		lengthBytes = append([]byte{0x80 | byte(len(lenBuf))}, lenBuf...)
	}
	
	result := append([]byte{0x30}, lengthBytes...)  // SEQUENCE tag
	result = append(result, certBytes...)
	
	return result, nil
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

func randFieldElement(random io.Reader, n *big.Int) (*big.Int, error) {
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
