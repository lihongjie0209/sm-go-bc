package sm2

import (
	"crypto/rand"
	"errors"
	"math/big"
	"github.com/lihongjie0209/sm-go-bc/crypto/digests"
	"github.com/lihongjie0209/sm-go-bc/math/ec"
	"github.com/lihongjie0209/sm-go-bc/util"
)

// SM2Engine implements SM2 public key encryption.
// Reference: GM/T 0003-2012 Part 4: Public Key Encryption
type SM2Engine struct {
	forEncryption bool
	publicKey     *ec.Point
	privateKey    *big.Int
	curve         *ec.Curve
	mode          int // 0 = C1C2C3, 1 = C1C3C2
}

const (
	// Mode_C1C2C3 is the default mode (old standard)
	Mode_C1C2C3 = 0
	// Mode_C1C3C2 is the new standard mode
	Mode_C1C3C2 = 1
)

// NewSM2Engine creates a new SM2 encryption engine.
func NewSM2Engine() *SM2Engine {
	return &SM2Engine{
		curve: GetCurve(),
		mode:  Mode_C1C2C3, // Default to old standard for compatibility with JS/other implementations
	}
}

// SetMode sets the output mode (C1C2C3 or C1C3C2).
func (e *SM2Engine) SetMode(mode int) {
	e.mode = mode
}

// Init initializes the engine for encryption or decryption.
func (e *SM2Engine) Init(forEncryption bool, publicKey *ec.Point, privateKey *big.Int) error {
	e.forEncryption = forEncryption
	
	if forEncryption {
		if publicKey == nil || publicKey.IsInfinity() {
			return errors.New("invalid public key")
		}
		if !ValidatePublicKey(publicKey) {
			return errors.New("public key validation failed")
		}
		e.publicKey = publicKey
	} else {
		if privateKey == nil {
			return errors.New("invalid private key")
		}
		if !ValidatePrivateKey(privateKey) {
			return errors.New("private key validation failed")
		}
		e.privateKey = privateKey
	}
	
	return nil
}

// Encrypt encrypts plaintext using SM2 public key encryption.
// Output format: C1 || C3 || C2 (new standard) or C1 || C2 || C3 (old)
// where:
//   C1 = encoded point (65 bytes uncompressed or 33 bytes compressed)
//   C2 = ciphertext (same length as plaintext)
//   C3 = hash/MAC (32 bytes for SM3)
func (e *SM2Engine) Encrypt(plaintext []byte) ([]byte, error) {
	if !e.forEncryption {
		return nil, errors.New("engine not initialized for encryption")
	}
	
	curve := e.curve
	n := curve.GetOrder()
	
	for {
		// Step 1: Generate random k in [1, n-1]
		k, err := randRange(n)
		if err != nil {
			return nil, err
		}
		
		// Step 2: Compute C1 = [k]G
		c1Point := GetG().Multiply(k)
		c1 := c1Point.GetEncoded(false) // Uncompressed
		
		// Step 3: Compute S = h * Pb (h=1 for SM2, so S = Pb)
		// Check if S is infinity (should not happen for valid key)
		if e.publicKey.IsInfinity() {
			return nil, errors.New("invalid public key point")
		}
		
		// Step 4: Compute [k]Pb = (x2, y2)
		kPb := e.publicKey.Multiply(k)
		x2 := kPb.GetXCoord().ToBigInt()
		y2 := kPb.GetYCoord().ToBigInt()
		
		// Step 5: Compute t = KDF(x2 || y2, klen)
		x2Bytes := util.BigIntToBytes(x2, 32)
		y2Bytes := util.BigIntToBytes(y2, 32)
		
		kdfInput := append(x2Bytes, y2Bytes...)
		t := KDF(kdfInput, len(plaintext))
		
		// Check if t is all zeros (retry if so)
		// Skip check if plaintext is empty
		if len(plaintext) > 0 {
			allZero := true
			for _, b := range t {
				if b != 0 {
					allZero = false
					break
				}
			}
			if allZero {
				continue // Retry with different k
			}
		}
		
		// Step 6: Compute C2 = M ⊕ t
		c2 := make([]byte, len(plaintext))
		for i := 0; i < len(plaintext); i++ {
			c2[i] = plaintext[i] ^ t[i]
		}
		
		// Step 7: Compute C3 = Hash(x2 || M || y2)
		digest := digests.NewSM3Digest()
		digest.BlockUpdate(x2Bytes, 0, len(x2Bytes))
		digest.BlockUpdate(plaintext, 0, len(plaintext))
		digest.BlockUpdate(y2Bytes, 0, len(y2Bytes))
		
		c3 := make([]byte, digest.GetDigestSize())
		digest.DoFinal(c3, 0)
		
		// Step 8: Output C = C1 || C3 || C2 or C1 || C2 || C3
		var ciphertext []byte
		if e.mode == Mode_C1C3C2 {
			ciphertext = append(c1, c3...)
			ciphertext = append(ciphertext, c2...)
		} else {
			ciphertext = append(c1, c2...)
			ciphertext = append(ciphertext, c3...)
		}
		
		return ciphertext, nil
	}
}

// Decrypt decrypts ciphertext using SM2 private key.
func (e *SM2Engine) Decrypt(ciphertext []byte) ([]byte, error) {
	if e.forEncryption {
		return nil, errors.New("engine not initialized for decryption")
	}
	
	// Parse ciphertext
	// C1 is either 65 bytes (uncompressed) or 33 bytes (compressed)
	if len(ciphertext) < 97 { // Minimum: 65 (C1) + 32 (C3) + 0 (C2)
		return nil, errors.New("ciphertext too short")
	}
	
	// Determine C1 length based on first byte
	var c1Len int
	if ciphertext[0] == 0x04 {
		c1Len = 65 // Uncompressed
	} else if ciphertext[0] == 0x02 || ciphertext[0] == 0x03 {
		c1Len = 33 // Compressed
	} else {
		return nil, errors.New("invalid ciphertext format")
	}
	
	c3Len := 32 // SM3 output size
	c2Len := len(ciphertext) - c1Len - c3Len
	
	if c2Len < 0 {
		return nil, errors.New("invalid ciphertext length")
	}
	
	// Extract C1, C2, C3 based on mode
	c1 := ciphertext[0:c1Len]
	var c2, c3 []byte
	
	if e.mode == Mode_C1C3C2 {
		c3 = ciphertext[c1Len : c1Len+c3Len]
		c2 = ciphertext[c1Len+c3Len:]
	} else {
		c2 = ciphertext[c1Len : c1Len+c2Len]
		c3 = ciphertext[c1Len+c2Len:]
	}
	
	// Step 1: Decode C1 to point
	c1Point := e.curve.DecodePoint(c1)
	if c1Point.IsInfinity() {
		return nil, errors.New("invalid C1 point")
	}
	
	// Step 2: Compute S = h * C1 (h=1, so S = C1)
	// Check if S is infinity
	if c1Point.IsInfinity() {
		return nil, errors.New("invalid point")
	}
	
	// Step 3: Compute [d]C1 = (x2, y2)
	dC1 := c1Point.Multiply(e.privateKey)
	x2 := dC1.GetXCoord().ToBigInt()
	y2 := dC1.GetYCoord().ToBigInt()
	
	// Step 4: Compute t = KDF(x2 || y2, klen)
	x2Bytes := util.BigIntToBytes(x2, 32)
	y2Bytes := util.BigIntToBytes(y2, 32)
	
	kdfInput := append(x2Bytes, y2Bytes...)
	t := KDF(kdfInput, len(c2))
	
	// Check if t is all zeros (skip if c2 is empty)
	if len(c2) > 0 {
		allZero := true
		for _, b := range t {
			if b != 0 {
				allZero = false
				break
			}
		}
		if allZero {
			return nil, errors.New("KDF output is all zeros")
		}
	}
	
	// Step 5: Compute M' = C2 ⊕ t
	plaintext := make([]byte, len(c2))
	for i := 0; i < len(c2); i++ {
		plaintext[i] = c2[i] ^ t[i]
	}
	
	// Step 6: Compute u = Hash(x2 || M' || y2)
	digest := digests.NewSM3Digest()
	digest.BlockUpdate(x2Bytes, 0, len(x2Bytes))
	digest.BlockUpdate(plaintext, 0, len(plaintext))
	digest.BlockUpdate(y2Bytes, 0, len(y2Bytes))
	
	u := make([]byte, digest.GetDigestSize())
	digest.DoFinal(u, 0)
	
	// Step 7: Verify u == C3
	for i := 0; i < len(c3); i++ {
		if c3[i] != u[i] {
			return nil, errors.New("MAC verification failed")
		}
	}
	
	return plaintext, nil
}

// randRange generates a random number in [1, max-1].
func randRange(max *big.Int) (*big.Int, error) {
	// Generate random in [1, max-1]
	for {
		k, err := rand.Int(rand.Reader, max)
		if err != nil {
			return nil, err
		}
		// Ensure k is not zero
		if k.Sign() > 0 {
			return k, nil
		}
	}
}
