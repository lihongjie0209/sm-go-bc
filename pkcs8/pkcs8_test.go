package pkcs8

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"io"
	"math/big"
	"testing"
	
	"github.com/lihongjie0209/sm-go-bc/crypto/sm2"
	"github.com/lihongjie0209/sm-go-bc/crypto/signers"
	"github.com/lihongjie0209/sm-go-bc/math/ec"
)

// TestSM2PrivateKeyEncodingDecoding tests PKCS#8 encoding/decoding of SM2 private keys.
func TestSM2PrivateKeyEncodingDecoding(t *testing.T) {
	// Generate a test SM2 key pair
	d, Q := generateTestKeyPair(t)
	
	// Marshal to PKCS#8
	der, err := MarshalSM2PrivateKey(d, Q)
	if err != nil {
		t.Fatalf("Failed to marshal SM2 private key: %v", err)
	}
	
	t.Logf("PKCS#8 DER length: %d bytes", len(der))
	t.Logf("PKCS#8 DER (first 64 bytes): %s", hex.EncodeToString(der[:min(64, len(der))]))
	
	// Parse back
	parsedD, parsedQ, err := ParseSM2PrivateKey(der)
	if err != nil {
		t.Fatalf("Failed to parse SM2 private key: %v", err)
	}
	
	// Verify private key D matches
	if d.Cmp(parsedD) != 0 {
		t.Errorf("Private key D mismatch")
	}
	
	// Verify public key matches
	if Q.GetX().ToBigInt().Cmp(parsedQ.GetX().ToBigInt()) != 0 {
		t.Errorf("Public key X mismatch")
	}
	if Q.GetY().ToBigInt().Cmp(parsedQ.GetY().ToBigInt()) != 0 {
		t.Errorf("Public key Y mismatch")
	}
}

// TestSM2PublicKeyEncodingDecoding tests SubjectPublicKeyInfo encoding/decoding of SM2 public keys.
func TestSM2PublicKeyEncodingDecoding(t *testing.T) {
	// Generate a test SM2 key pair
	_, Q := generateTestKeyPair(t)
	
	// Marshal to SubjectPublicKeyInfo
	der, err := MarshalSM2PublicKey(Q)
	if err != nil {
		t.Fatalf("Failed to marshal SM2 public key: %v", err)
	}
	
	t.Logf("SubjectPublicKeyInfo DER length: %d bytes", len(der))
	t.Logf("SubjectPublicKeyInfo DER (first 64 bytes): %s", hex.EncodeToString(der[:min(64, len(der))]))
	
	// Parse back
	parsedQ, err := ParseSM2PublicKey(der)
	if err != nil {
		t.Fatalf("Failed to parse SM2 public key: %v", err)
	}
	
	// Verify public key matches
	if Q.GetX().ToBigInt().Cmp(parsedQ.GetX().ToBigInt()) != 0 {
		t.Errorf("Public key X mismatch")
	}
	if Q.GetY().ToBigInt().Cmp(parsedQ.GetY().ToBigInt()) != 0 {
		t.Errorf("Public key Y mismatch")
	}
}

// TestSM2KeyRoundTrip tests that we can sign/verify after encoding/decoding.
func TestSM2KeyRoundTrip(t *testing.T) {
	// Generate original key pair
	d, Q := generateTestKeyPair(t)
	
	// Encode private key
	privDER, err := MarshalSM2PrivateKey(d, Q)
	if err != nil {
		t.Fatalf("Failed to marshal private key: %v", err)
	}
	
	// Decode private key
	decodedD, decodedQ, err := ParseSM2PrivateKey(privDER)
	if err != nil {
		t.Fatalf("Failed to parse private key: %v", err)
	}
	
	// Encode public key
	pubDER, err := MarshalSM2PublicKey(Q)
	if err != nil {
		t.Fatalf("Failed to marshal public key: %v", err)
	}
	
	// Decode public key
	decodedPubQ, err := ParseSM2PublicKey(pubDER)
	if err != nil {
		t.Fatalf("Failed to parse public key: %v", err)
	}
	
	// Test message
	message := []byte("Hello, SM2 PKCS#8!")
	
	// Sign with decoded private key using SM2Signer
	signer := signers.NewSM2Signer()
	err = signer.Init(true, decodedQ, decodedD)
	if err != nil {
		t.Fatalf("Failed to initialize signer: %v", err)
	}
	signer.Update(message)
	signature, err := signer.GenerateSignature()
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}
	
	// Verify with decoded public key
	verifier := signers.NewSM2Signer()
	err = verifier.Init(false, decodedPubQ, nil)
	if err != nil {
		t.Fatalf("Failed to initialize verifier: %v", err)
	}
	verifier.Update(message)
	valid, err := verifier.VerifySignature(signature)
	if err != nil {
		t.Fatalf("Verification error: %v", err)
	}
	if !valid {
		t.Error("Signature verification failed")
	}
	
	// Also verify with original public key
	verifier2 := signers.NewSM2Signer()
	err = verifier2.Init(false, Q, nil)
	if err != nil {
		t.Fatalf("Failed to initialize verifier2: %v", err)
	}
	verifier2.Update(message)
	valid2, err := verifier2.VerifySignature(signature)
	if err != nil {
		t.Fatalf("Verification2 error: %v", err)
	}
	if !valid2 {
		t.Error("Signature verification with original public key failed")
	}
}

// TestMultipleKeys tests encoding/decoding multiple different keys.
func TestMultipleKeys(t *testing.T) {
	const numKeys = 10
	
	type keyPair struct {
		d *big.Int
		Q *ec.Point
	}
	
	var keys []keyPair
	var derKeys [][]byte
	
	// Generate and encode keys
	for i := 0; i < numKeys; i++ {
		d, Q := generateTestKeyPair(t)
		keys = append(keys, keyPair{d, Q})
		
		der, err := MarshalSM2PrivateKey(d, Q)
		if err != nil {
			t.Fatalf("Failed to marshal key %d: %v", i, err)
		}
		derKeys = append(derKeys, der)
	}
	
	// Decode and verify keys
	for i := 0; i < numKeys; i++ {
		parsedD, parsedQ, err := ParseSM2PrivateKey(derKeys[i])
		if err != nil {
			t.Fatalf("Failed to parse key %d: %v", i, err)
		}
		
		if keys[i].d.Cmp(parsedD) != 0 {
			t.Errorf("Key %d: private key D mismatch", i)
		}
		if keys[i].Q.GetX().ToBigInt().Cmp(parsedQ.GetX().ToBigInt()) != 0 {
			t.Errorf("Key %d: public key X mismatch", i)
		}
		if keys[i].Q.GetY().ToBigInt().Cmp(parsedQ.GetY().ToBigInt()) != 0 {
			t.Errorf("Key %d: public key Y mismatch", i)
		}
	}
}

// TestDeterministicEncoding tests that encoding is deterministic.
func TestDeterministicEncoding(t *testing.T) {
	d, Q := generateTestKeyPair(t)
	
	// Encode multiple times
	der1, err := MarshalSM2PrivateKey(d, Q)
	if err != nil {
		t.Fatalf("Failed to marshal (1): %v", err)
	}
	
	der2, err := MarshalSM2PrivateKey(d, Q)
	if err != nil {
		t.Fatalf("Failed to marshal (2): %v", err)
	}
	
	if !bytes.Equal(der1, der2) {
		t.Error("Encoding is not deterministic")
	}
	
	// Same for public key
	pub1, err := MarshalSM2PublicKey(Q)
	if err != nil {
		t.Fatalf("Failed to marshal public key (1): %v", err)
	}
	
	pub2, err := MarshalSM2PublicKey(Q)
	if err != nil {
		t.Fatalf("Failed to marshal public key (2): %v", err)
	}
	
	if !bytes.Equal(pub1, pub2) {
		t.Error("Public key encoding is not deterministic")
	}
}

// Helper functions
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func generateTestKeyPair(t *testing.T) (*big.Int, *ec.Point) {
	// Generate random private key
	n := sm2.GetN()
	
	d, err := randFieldElement(rand.Reader, n)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}
	
	// Compute public key Q = [d]G
	G := sm2.GetG()
	Q := G.Multiply(d)
	
	return d, Q
}

// randFieldElement returns a random element of the order of the given curve
func randFieldElement(random io.Reader, n *big.Int) (k *big.Int, err error) {
	b := make([]byte, (n.BitLen()+7)/8)
	for {
		_, err = io.ReadFull(random, b)
		if err != nil {
			return
		}
		k = new(big.Int).SetBytes(b)
		if k.Sign() > 0 && k.Cmp(n) < 0 {
			return
		}
	}
}
