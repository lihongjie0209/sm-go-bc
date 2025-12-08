// Package main demonstrates PKI operations with SM2: PKCS#8 key encoding and PKCS#10 CSR creation.
package main

import (
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	
	"github.com/lihongjie0209/sm-go-bc/crypto/sm2"
	"github.com/lihongjie0209/sm-go-bc/math/ec"
	"github.com/lihongjie0209/sm-go-bc/pkcs10"
	"github.com/lihongjie0209/sm-go-bc/pkcs8"
)

func main() {
	fmt.Println("=== SM2 PKI Operations Demo ===\n")
	
	// Demo 1: Generate and encode SM2 key pair
	demonstrateKeyEncoding()
	
	// Demo 2: Create PKCS#10 CSR
	demonstrateCSRCreation()
	
	// Demo 3: Key export/import with PEM
	demonstratePEMEncoding()
}

func demonstrateKeyEncoding() {
	fmt.Println("1. SM2 Key Pair Generation and PKCS#8 Encoding")
	fmt.Println("   " + repeatString("-", 50))
	
	// Generate SM2 key pair
	d, Q := generateKeyPair()
	fmt.Printf("   Generated SM2 key pair\n")
	fmt.Printf("   Private key (d): %s... (%d bits)\n", 
		hex.EncodeToString(d.Bytes())[:32], d.BitLen())
	fmt.Printf("   Public key X: %s...\n", 
		hex.EncodeToString(Q.GetX().ToBigInt().Bytes())[:32])
	fmt.Printf("   Public key Y: %s...\n\n", 
		hex.EncodeToString(Q.GetY().ToBigInt().Bytes())[:32])
	
	// Encode private key to PKCS#8
	privKeyDER, err := pkcs8.MarshalSM2PrivateKey(d, Q)
	if err != nil {
		fmt.Printf("   Error encoding private key: %v\n", err)
		return
	}
	fmt.Printf("   PKCS#8 private key: %d bytes\n", len(privKeyDER))
	fmt.Printf("   First 32 bytes: %s\n\n", hex.EncodeToString(privKeyDER[:32]))
	
	// Encode public key to SubjectPublicKeyInfo
	pubKeyDER, err := pkcs8.MarshalSM2PublicKey(Q)
	if err != nil {
		fmt.Printf("   Error encoding public key: %v\n", err)
		return
	}
	fmt.Printf("   SubjectPublicKeyInfo: %d bytes\n", len(pubKeyDER))
	fmt.Printf("   First 32 bytes: %s\n\n", hex.EncodeToString(pubKeyDER[:32]))
	
	// Parse back
	parsedD, parsedQ, err := pkcs8.ParseSM2PrivateKey(privKeyDER)
	if err != nil {
		fmt.Printf("   Error parsing private key: %v\n", err)
		return
	}
	
	if d.Cmp(parsedD) == 0 {
		fmt.Printf("   ✓ Private key roundtrip successful\n")
	}
	if Q.GetX().ToBigInt().Cmp(parsedQ.GetX().ToBigInt()) == 0 {
		fmt.Printf("   ✓ Public key roundtrip successful\n")
	}
	
	fmt.Println()
}

func demonstrateCSRCreation() {
	fmt.Println("2. PKCS#10 Certificate Signing Request (CSR)")
	fmt.Println("   " + repeatString("-", 50))
	
	// Generate key pair
	d, Q := generateKeyPair()
	
	// Define subject
	subject := pkix.Name{
		CommonName:         "SM2 Test Certificate",
		Organization:       []string{"Example Corporation"},
		OrganizationalUnit: []string{"IT Department"},
		Locality:           []string{"Beijing"},
		Province:           []string{"Beijing"},
		Country:            []string{"CN"},
	}
	
	fmt.Printf("   Creating CSR for:\n")
	fmt.Printf("   - CN: %s\n", subject.CommonName)
	fmt.Printf("   - O:  %s\n", subject.Organization[0])
	fmt.Printf("   - C:  %s\n\n", subject.Country[0])
	
	// Create CSR
	csrDER, err := pkcs10.CreateCertificationRequest(subject, Q, d, nil)
	if err != nil {
		fmt.Printf("   Error creating CSR: %v\n", err)
		return
	}
	
	fmt.Printf("   ✓ CSR created successfully (%d bytes)\n", len(csrDER))
	fmt.Printf("   DER encoding (first 64 bytes):\n   %s\n\n", 
		hex.EncodeToString(csrDER[:min(64, len(csrDER))]))
	
	// Convert to PEM
	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})
	
	fmt.Printf("   PEM encoding:\n%s\n", string(csrPEM))
}

func demonstratePEMEncoding() {
	fmt.Println("3. PEM Encoding for Key Exchange")
	fmt.Println("   " + repeatString("-", 50))
	
	// Generate key pair
	d, Q := generateKeyPair()
	
	// Encode private key to PKCS#8 DER
	privKeyDER, err := pkcs8.MarshalSM2PrivateKey(d, Q)
	if err != nil {
		fmt.Printf("   Error: %v\n", err)
		return
	}
	
	// Convert to PEM
	privKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privKeyDER,
	})
	
	fmt.Printf("   Private Key (PEM format):\n%s\n", string(privKeyPEM))
	
	// Encode public key
	pubKeyDER, err := pkcs8.MarshalSM2PublicKey(Q)
	if err != nil {
		fmt.Printf("   Error: %v\n", err)
		return
	}
	
	pubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyDER,
	})
	
	fmt.Printf("   Public Key (PEM format):\n%s\n", string(pubKeyPEM))
	
	// Demonstrate parsing from PEM
	block, _ := pem.Decode(privKeyPEM)
	if block == nil {
		fmt.Println("   Error decoding PEM")
		return
	}
	
	parsedD, _, err := pkcs8.ParseSM2PrivateKey(block.Bytes)
	if err != nil {
		fmt.Printf("   Error parsing: %v\n", err)
		return
	}
	
	if d.Cmp(parsedD) == 0 {
		fmt.Printf("   ✓ PEM roundtrip successful\n")
	}
	
	fmt.Printf("\n   Note: These PEM files are compatible with OpenSSL\n")
	fmt.Printf("   and other standard PKI tools.\n\n")
}

// Helper functions
func generateKeyPair() (*big.Int, *ec.Point) {
	n := sm2.GetN()
	d, _ := randFieldElement(rand.Reader, n)
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

func repeatString(s string, n int) string {
	result := ""
	for i := 0; i < n; i++ {
		result += s
	}
	return result
}
