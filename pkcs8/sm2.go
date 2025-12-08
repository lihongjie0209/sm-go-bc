package pkcs8

import (
	"encoding/asn1"
	"fmt"
	"math/big"
	
	"github.com/lihongjie0209/sm-go-bc/crypto/sm2"
	"github.com/lihongjie0209/sm-go-bc/math/ec"
)

// ECPrivateKey represents an EC private key in SEC 1 format.
//
// ECPrivateKey ::= SEQUENCE {
//   version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
//   privateKey     OCTET STRING,
//   parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
//   publicKey  [1] BIT STRING OPTIONAL
// }
type ECPrivateKey struct {
	Version       int
	PrivateKey    []byte
	NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
}

// MarshalSM2PrivateKey converts an SM2 private key to PKCS#8 DER format.
func MarshalSM2PrivateKey(d *big.Int, Q *ec.Point) ([]byte, error) {
	// Validate inputs
	if !sm2.ValidatePrivateKey(d) {
		return nil, fmt.Errorf("invalid SM2 private key")
	}
	if !sm2.ValidatePublicKey(Q) {
		return nil, fmt.Errorf("invalid SM2 public key")
	}
	
	// Get the private key D value as bytes
	dBytes := d.Bytes()
	// Pad to 32 bytes if needed
	if len(dBytes) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(dBytes):], dBytes)
		dBytes = padded
	}
	
	// Encode public key point as uncompressed: 0x04 || X || Y
	xBytes := Q.GetX().ToBigInt().Bytes()
	yBytes := Q.GetY().ToBigInt().Bytes()
	
	// Pad X and Y to 32 bytes
	if len(xBytes) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(xBytes):], xBytes)
		xBytes = padded
	}
	if len(yBytes) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(yBytes):], yBytes)
		yBytes = padded
	}
	
	pubKeyBytes := make([]byte, 65)
	pubKeyBytes[0] = 0x04 // Uncompressed
	copy(pubKeyBytes[1:33], xBytes)
	copy(pubKeyBytes[33:65], yBytes)
	
	// Create ECPrivateKey structure
	ecPrivKey := ECPrivateKey{
		Version:       1,
		PrivateKey:    dBytes,
		NamedCurveOID: OidSM2Curve,
		PublicKey: asn1.BitString{
			Bytes:     pubKeyBytes,
			BitLength: len(pubKeyBytes) * 8,
		},
	}
	
	// Marshal the EC private key
	ecPrivKeyDER, err := asn1.Marshal(ecPrivKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal EC private key: %w", err)
	}
	
	// Create PKCS#8 PrivateKeyInfo
	pki := PrivateKeyInfo{
		Version:    0,
		Algorithm:  NewSM2AlgorithmIdentifier(),
		PrivateKey: ecPrivKeyDER,
	}
	
	return MarshalPrivateKeyInfo(&pki)
}

// ParseSM2PrivateKey parses an SM2 private key from PKCS#8 DER format.
// Returns the private key d and public key point Q.
func ParseSM2PrivateKey(der []byte) (*big.Int, *ec.Point, error) {
	// Parse PKCS#8 structure
	pki, err := ParsePrivateKeyInfo(der)
	if err != nil {
		return nil, nil, err
	}
	
	// Verify it's an SM2 key
	if !pki.Algorithm.Algorithm.Equal(OidSM2) && !pki.Algorithm.Algorithm.Equal(OidSM2Encryption) {
		return nil, nil, fmt.Errorf("not an SM2 private key (OID: %v)", pki.Algorithm.Algorithm)
	}
	
	// Parse the EC private key
	var ecPrivKey ECPrivateKey
	_, err = asn1.Unmarshal(pki.PrivateKey, &ecPrivKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal EC private key: %w", err)
	}
	
	// Extract private key d
	d := new(big.Int).SetBytes(ecPrivKey.PrivateKey)
	
	// Get SM2 curve
	curve := sm2.GetCurve()
	var Q *ec.Point
	
	// Extract public key if present
	if ecPrivKey.PublicKey.BitLength > 0 {
		pubBytes := ecPrivKey.PublicKey.Bytes
		if len(pubBytes) != 65 || pubBytes[0] != 0x04 {
			return nil, nil, fmt.Errorf("invalid public key format")
		}
		
		x := new(big.Int).SetBytes(pubBytes[1:33])
		y := new(big.Int).SetBytes(pubBytes[33:65])
		Q = curve.CreatePoint(x, y)
	} else {
		// Compute public key from private key
		G := sm2.GetG()
		Q = G.Multiply(d)
	}
	
	// Validate the key pair
	if !sm2.ValidatePrivateKey(d) {
		return nil, nil, fmt.Errorf("invalid private key")
	}
	if !sm2.ValidatePublicKey(Q) {
		return nil, nil, fmt.Errorf("invalid public key")
	}
	
	return d, Q, nil
}

// MarshalSM2PublicKey converts an SM2 public key to SubjectPublicKeyInfo DER format.
func MarshalSM2PublicKey(Q *ec.Point) ([]byte, error) {
	// Validate public key
	if !sm2.ValidatePublicKey(Q) {
		return nil, fmt.Errorf("invalid SM2 public key")
	}
	
	// Encode public key point as uncompressed: 0x04 || X || Y
	xBytes := Q.GetX().ToBigInt().Bytes()
	yBytes := Q.GetY().ToBigInt().Bytes()
	
	// Pad X and Y to 32 bytes
	if len(xBytes) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(xBytes):], xBytes)
		xBytes = padded
	}
	if len(yBytes) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(yBytes):], yBytes)
		yBytes = padded
	}
	
	pubKeyBytes := make([]byte, 65)
	pubKeyBytes[0] = 0x04 // Uncompressed
	copy(pubKeyBytes[1:33], xBytes)
	copy(pubKeyBytes[33:65], yBytes)
	
	// Create SubjectPublicKeyInfo
	spki := SubjectPublicKeyInfo{
		Algorithm: NewSM2PublicKeyAlgorithmIdentifier(),
		SubjectPublicKey: asn1.BitString{
			Bytes:     pubKeyBytes,
			BitLength: len(pubKeyBytes) * 8,
		},
	}
	
	return MarshalSubjectPublicKeyInfo(&spki)
}

// ParseSM2PublicKey parses an SM2 public key from SubjectPublicKeyInfo DER format.
// Returns the public key point Q.
func ParseSM2PublicKey(der []byte) (*ec.Point, error) {
	// Parse SubjectPublicKeyInfo
	spki, err := ParseSubjectPublicKeyInfo(der)
	if err != nil {
		return nil, err
	}
	
	// Verify it's an SM2 key
	if !spki.Algorithm.Algorithm.Equal(OidSM2) && 
	   !spki.Algorithm.Algorithm.Equal(OidSM2Encryption) {
		return nil, fmt.Errorf("not an SM2 public key (OID: %v)", spki.Algorithm.Algorithm)
	}
	
	// Unmarshal the public key point
	pubBytes := spki.SubjectPublicKey.Bytes
	if len(pubBytes) != 65 || pubBytes[0] != 0x04 {
		return nil, fmt.Errorf("invalid public key format")
	}
	
	x := new(big.Int).SetBytes(pubBytes[1:33])
	y := new(big.Int).SetBytes(pubBytes[33:65])
	
	curve := sm2.GetCurve()
	Q := curve.CreatePoint(x, y)
	
	// Validate public key
	if !sm2.ValidatePublicKey(Q) {
		return nil, fmt.Errorf("invalid public key point")
	}
	
	return Q, nil
}
