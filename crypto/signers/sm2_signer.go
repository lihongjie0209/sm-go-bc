package signers

import (
	"crypto/rand"
	"errors"
	"math/big"

	"github.com/lihongjie0209/sm-go-bc/crypto/digests"
	"github.com/lihongjie0209/sm-go-bc/crypto/sm2"
	"github.com/lihongjie0209/sm-go-bc/math/ec"
)

// SM2Signer implements SM2 digital signature algorithm.
// Reference: GM/T 0003-2012 Part 2: Digital Signature Algorithm
type SM2Signer struct {
	forSigning   bool
	digest       *digests.SM3Digest
	curve        *ec.Curve
	publicKey    *ec.Point
	privateKey   *big.Int
	userID       []byte
	z            []byte
	curveLength  int
}

// NewSM2Signer creates a new SM2 signer.
func NewSM2Signer() *SM2Signer {
	curve := sm2.GetCurve()
	return &SM2Signer{
		digest:      digests.NewSM3Digest(),
		curve:       curve,
		userID:      []byte("1234567812345678"), // Default user ID
		curveLength: (curve.GetFieldSize() + 7) / 8,
	}
}

// SetUserID sets the user ID for Z value computation.
func (s *SM2Signer) SetUserID(userID []byte) {
	s.userID = userID
}

// Init initializes the signer for signing or verification.
func (s *SM2Signer) Init(forSigning bool, publicKey *ec.Point, privateKey *big.Int) error {
	s.forSigning = forSigning

	if forSigning {
		if privateKey == nil {
			return errors.New("private key required for signing")
		}
		if !sm2.ValidatePrivateKey(privateKey) {
			return errors.New("invalid private key")
		}
		s.privateKey = privateKey
		// Derive public key from private key
		s.publicKey = sm2.GetG().Multiply(privateKey)
	} else {
		if publicKey == nil || publicKey.IsInfinity() {
			return errors.New("public key required for verification")
		}
		if !sm2.ValidatePublicKey(publicKey) {
			return errors.New("invalid public key")
		}
		s.publicKey = publicKey
	}

	// Compute Z value
	s.z = s.computeZ()

	// Initialize digest with Z
	s.digest.Reset()
	s.digest.BlockUpdate(s.z, 0, len(s.z))

	return nil
}

// Update updates the digest with message data.
func (s *SM2Signer) Update(data []byte) {
	s.digest.BlockUpdate(data, 0, len(data))
}

// UpdateByte updates the digest with a single byte.
func (s *SM2Signer) UpdateByte(b byte) {
	s.digest.Update(b)
}

// GenerateSignature generates an SM2 signature.
// Returns signature in format: r || s (64 bytes total)
func (s *SM2Signer) GenerateSignature() ([]byte, error) {
	if !s.forSigning {
		return nil, errors.New("not initialized for signing")
	}

	n := sm2.GetN()

	// Compute e = H(Z || M)
	eHash := make([]byte, s.digest.GetDigestSize())
	s.digest.DoFinal(eHash, 0)
	e := new(big.Int).SetBytes(eHash)

	// Generate signature
	for {
		// Generate random k in [1, n-1]
		k, err := randRange(n)
		if err != nil {
			return nil, err
		}

		// Compute (x1, y1) = [k]G
		p1 := sm2.GetG().Multiply(k)
		x1 := p1.GetXCoord().ToBigInt()

		// Compute r = (e + x1) mod n
		r := new(big.Int).Add(e, x1)
		r.Mod(r, n)

		// Check if r == 0 or r + k == n
		if r.Sign() == 0 {
			continue
		}
		rPlusK := new(big.Int).Add(r, k)
		if rPlusK.Cmp(n) == 0 {
			continue
		}

		// Compute s = d^-1 * (k - r * d) mod n
		// Rewritten as: s = (1 + d)^-1 * (k - r * d) mod n
		dPlus1 := new(big.Int).Add(s.privateKey, big.NewInt(1))
		dPlus1.Mod(dPlus1, n)
		dPlus1Inv := new(big.Int).ModInverse(dPlus1, n)
		if dPlus1Inv == nil {
			return nil, errors.New("failed to compute modular inverse")
		}

		rd := new(big.Int).Mul(r, s.privateKey)
		rd.Mod(rd, n)
		kMinusRd := new(big.Int).Sub(k, rd)
		kMinusRd.Mod(kMinusRd, n)

		sig := new(big.Int).Mul(dPlus1Inv, kMinusRd)
		sig.Mod(sig, n)

		// Check if s == 0
		if sig.Sign() == 0 {
			continue
		}

		// Encode signature as r || s
		return s.encodeSignature(r, sig), nil
	}
}

// VerifySignature verifies an SM2 signature.
func (s *SM2Signer) VerifySignature(signature []byte) (bool, error) {
	if s.forSigning {
		return false, errors.New("not initialized for verification")
	}

	n := sm2.GetN()

	// Decode signature
	r, sig, err := s.decodeSignature(signature)
	if err != nil {
		return false, err
	}

	// Check r, s in [1, n-1]
	if r.Sign() <= 0 || r.Cmp(n) >= 0 || sig.Sign() <= 0 || sig.Cmp(n) >= 0 {
		return false, nil
	}

	// Compute e = H(Z || M)
	eHash := make([]byte, s.digest.GetDigestSize())
	s.digest.DoFinal(eHash, 0)
	e := new(big.Int).SetBytes(eHash)

	// Compute t = (r + s) mod n
	t := new(big.Int).Add(r, sig)
	t.Mod(t, n)

	if t.Sign() == 0 {
		return false, nil
	}

	// Compute (x1, y1) = [s]G + [t]P
	sG := sm2.GetG().Multiply(sig)
	tP := s.publicKey.Multiply(t)
	p1 := sG.Add(tP)

	if p1.IsInfinity() {
		return false, nil
	}

	// Compute v = (e + x1) mod n
	x1 := p1.GetXCoord().ToBigInt()
	v := new(big.Int).Add(e, x1)
	v.Mod(v, n)

	// Check if v == r
	return v.Cmp(r) == 0, nil
}

// Reset resets the signer state.
func (s *SM2Signer) Reset() {
	s.digest.Reset()
	if len(s.z) > 0 {
		s.digest.BlockUpdate(s.z, 0, len(s.z))
	}
}

// computeZ computes the Z value for SM2 signature.
// Z = SM3(ENTL || ID || a || b || xG || yG || xA || yA)
func (s *SM2Signer) computeZ() []byte {
	zDigest := digests.NewSM3Digest()

	// ENTL: user ID length in bits (2 bytes, big-endian)
	entl := len(s.userID) * 8
	zDigest.Update(byte(entl >> 8))
	zDigest.Update(byte(entl & 0xFF))

	// ID: user ID
	zDigest.BlockUpdate(s.userID, 0, len(s.userID))

	// Curve parameters a, b
	s.addFieldElement(zDigest, s.curve.GetA().ToBigInt())
	s.addFieldElement(zDigest, s.curve.GetB().ToBigInt())

	// Base point G coordinates
	g := sm2.GetG()
	s.addFieldElement(zDigest, g.GetXCoord().ToBigInt())
	s.addFieldElement(zDigest, g.GetYCoord().ToBigInt())

	// Public key coordinates
	s.addFieldElement(zDigest, s.publicKey.GetXCoord().ToBigInt())
	s.addFieldElement(zDigest, s.publicKey.GetYCoord().ToBigInt())

	// Finalize
	z := make([]byte, zDigest.GetDigestSize())
	zDigest.DoFinal(z, 0)
	return z
}

// addFieldElement adds a field element to the digest as fixed-length bytes.
func (s *SM2Signer) addFieldElement(digest *digests.SM3Digest, value *big.Int) {
	bytes := value.Bytes()
	// Pad to curve length
	if len(bytes) < s.curveLength {
		padded := make([]byte, s.curveLength)
		copy(padded[s.curveLength-len(bytes):], bytes)
		bytes = padded
	}
	digest.BlockUpdate(bytes, 0, len(bytes))
}

// encodeSignature encodes r and s in DER format for interoperability.
func (s *SM2Signer) encodeSignature(r, sig *big.Int) []byte {
	return encodeDERSignature(r, sig)
}

// decodeSignature decodes r and s from DER format signature bytes.
func (s *SM2Signer) decodeSignature(signature []byte) (*big.Int, *big.Int, error) {
	return decodeDERSignature(signature)
}

// encodeDERSignature encodes r and s in ASN.1 DER format.
// DER format: 0x30 || length || 0x02 || r_length || r || 0x02 || s_length || s
func encodeDERSignature(r, s *big.Int) []byte {
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	
	// Add leading zero if high bit is set (to keep positive)
	if len(rBytes) > 0 && rBytes[0]&0x80 != 0 {
		rBytes = append([]byte{0x00}, rBytes...)
	}
	if len(sBytes) > 0 && sBytes[0]&0x80 != 0 {
		sBytes = append([]byte{0x00}, sBytes...)
	}
	
	// Build DER sequence
	der := make([]byte, 0, 6+len(rBytes)+len(sBytes))
	
	// SEQUENCE tag
	der = append(der, 0x30)
	// Total length (will be filled later)
	totalLen := 2 + len(rBytes) + 2 + len(sBytes)
	der = append(der, byte(totalLen))
	
	// INTEGER tag for r
	der = append(der, 0x02)
	der = append(der, byte(len(rBytes)))
	der = append(der, rBytes...)
	
	// INTEGER tag for s
	der = append(der, 0x02)
	der = append(der, byte(len(sBytes)))
	der = append(der, sBytes...)
	
	return der
}

// decodeDERSignature decodes r and s from ASN.1 DER format.
func decodeDERSignature(signature []byte) (*big.Int, *big.Int, error) {
	if len(signature) < 8 {
		return nil, nil, errors.New("invalid signature length")
	}
	
	// Check SEQUENCE tag
	if signature[0] != 0x30 {
		return nil, nil, errors.New("invalid DER signature: expected SEQUENCE tag")
	}
	
	// Get total length
	totalLen := int(signature[1])
	if len(signature) != totalLen+2 {
		return nil, nil, errors.New("invalid DER signature: length mismatch")
	}
	
	pos := 2
	
	// Parse r
	if signature[pos] != 0x02 {
		return nil, nil, errors.New("invalid DER signature: expected INTEGER tag for r")
	}
	pos++
	rLen := int(signature[pos])
	pos++
	if pos+rLen > len(signature) {
		return nil, nil, errors.New("invalid DER signature: r length out of bounds")
	}
	r := new(big.Int).SetBytes(signature[pos : pos+rLen])
	pos += rLen
	
	// Parse s
	if signature[pos] != 0x02 {
		return nil, nil, errors.New("invalid DER signature: expected INTEGER tag for s")
	}
	pos++
	sLen := int(signature[pos])
	pos++
	if pos+sLen > len(signature) {
		return nil, nil, errors.New("invalid DER signature: s length out of bounds")
	}
	s := new(big.Int).SetBytes(signature[pos : pos+sLen])
	
	return r, s, nil
}

// randRange generates a random number in [1, max-1].
func randRange(max *big.Int) (*big.Int, error) {
	for {
		k, err := rand.Int(rand.Reader, max)
		if err != nil {
			return nil, err
		}
		if k.Sign() > 0 {
			return k, nil
		}
	}
}
