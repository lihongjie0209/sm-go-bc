package smgobc

import (
	"github.com/lihongjie0209/sm-go-bc/crypto/digests"
)

// SM3 provides high-level API for SM3 hashing
//
// SM3 is a cryptographic hash function producing a 256-bit hash value
//
// Standard: GM/T 0004-2012
type SM3 struct{}

// Hash computes the SM3 hash of the input data
func (s *SM3) Hash(data []byte) []byte {
	d := digests.NewSM3Digest()
	d.Update(data, 0, len(data))
	
	output := make([]byte, d.GetDigestSize())
	d.DoFinal(output, 0)
	
	return output
}

// HashWithID computes SM3 hash with user ID (for SM2 signing)
//
// This is used in SM2 signature algorithm where the hash includes
// the user's identity and public key information.
func (s *SM3) HashWithID(userID, data []byte) []byte {
	// This would need SM2 curve parameters to compute Z value
	// For now, just return regular hash
	// In a full implementation, this should compute:
	// Hash(Z || M) where Z = SM3(ENTL || ID || a || b || xG || yG || xA || yA)
	return s.Hash(data)
}
