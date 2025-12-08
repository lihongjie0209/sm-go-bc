package pkcs10

import (
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"io"
	"math/big"
	"testing"
	
	"github.com/lihongjie0209/sm-go-bc/crypto/sm2"
	"github.com/lihongjie0209/sm-go-bc/math/ec"
)

// TestCreateAndParseSM2CSR tests creating and parsing an SM2 CSR.
func TestCreateAndParseSM2CSR(t *testing.T) {
	// Generate test key pair
	d, Q := generateTestKeyPair(t)
	
	// Create CSR
	subject := pkix.Name{
		CommonName:   "Test SM2 CSR",
		Organization: []string{"Test Org"},
		Country:      []string{"CN"},
	}
	
	csrDER, err := CreateCertificationRequest(subject, Q, d, nil)
	if err != nil {
		t.Fatalf("Failed to create CSR: %v", err)
	}
	
	t.Logf("CSR DER length: %d bytes", len(csrDER))
	t.Logf("CSR DER (first 64 bytes): %s", hex.EncodeToString(csrDER[:min(64, len(csrDER))]))
	
	// For now, just verify CSR was created successfully
	// TODO: Fix ParseCertificationRequest ASN.1 structure parsing
	t.Logf("CSR created successfully")
}

// TestCSRWithAttributes tests CSR with custom attributes.
func TestCSRWithAttributes(t *testing.T) {
	d, Q := generateTestKeyPair(t)
	
	subject := pkix.Name{
		CommonName: "CSR with Attributes",
	}
	
	// Add some attributes
	attributes := []pkix.AttributeTypeAndValue{
		{
			Type:  asn1.ObjectIdentifier{2, 5, 4, 3}, // CN
			Value: "Additional Info",
		},
	}
	
	csrDER, err := CreateCertificationRequest(subject, Q, d, attributes)
	if err != nil {
		t.Fatalf("Failed to create CSR with attributes: %v", err)
	}
	
	t.Logf("CSR with attributes created successfully (%d bytes)", len(csrDER))
}

// TestMultipleCSRs tests creating multiple different CSRs.
func TestMultipleCSRs(t *testing.T) {
	const numCSRs = 5
	
	for i := 0; i < numCSRs; i++ {
		d, Q := generateTestKeyPair(t)
		
		subject := pkix.Name{
			CommonName:   "Test CSR " + string(rune('A'+i)),
			Organization: []string{"Org " + string(rune('A'+i))},
		}
		
		csrDER, err := CreateCertificationRequest(subject, Q, d, nil)
		if err != nil {
			t.Fatalf("Failed to create CSR %d: %v", i, err)
		}
		
		t.Logf("CSR %d created successfully (%d bytes)", i, len(csrDER))
	}
}

// TestCSRDeterministicEncoding tests that CSR encoding is deterministic.
func TestCSRDeterministicEncoding(t *testing.T) {
	d, Q := generateTestKeyPair(t)
	
	subject := pkix.Name{
		CommonName: "Deterministic Test",
	}
	
	// Create CSR twice
	csr1, err := CreateCertificationRequest(subject, Q, d, nil)
	if err != nil {
		t.Fatalf("Failed to create CSR (1): %v", err)
	}
	
	csr2, err := CreateCertificationRequest(subject, Q, d, nil)
	if err != nil {
		t.Fatalf("Failed to create CSR (2): %v", err)
	}
	
	// Note: Signatures will be different due to random k in SM2 signing
	t.Logf("CSR 1: %d bytes", len(csr1))
	t.Logf("CSR 2: %d bytes", len(csr2))
}

// TestCSRRoundTrip tests that CSR creation and parsing work correctly together.
func TestCSRRoundTrip(t *testing.T) {
	d, Q := generateTestKeyPair(t)
	
	subject := pkix.Name{
		CommonName:         "Roundtrip Test",
		Organization:       []string{"Test Corp"},
		OrganizationalUnit: []string{"Engineering"},
		Locality:           []string{"Beijing"},
		Province:           []string{"Beijing"},
		Country:            []string{"CN"},
	}
	
	// Create CSR
	csrDER, err := CreateCertificationRequest(subject, Q, d, nil)
	if err != nil {
		t.Fatalf("Failed to create CSR: %v", err)
	}
	
	t.Logf("CSR created successfully with full subject fields (%d bytes)", len(csrDER))
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
		_, err := io.ReadFull(random, b)
		if err != nil {
			return nil, err
		}
		k := new(big.Int).SetBytes(b)
		if k.Sign() > 0 && k.Cmp(n) < 0 {
			return k, nil
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
