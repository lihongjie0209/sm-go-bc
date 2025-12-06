package sm2

import (
	"github.com/lihongjie0209/sm-go-bc/crypto/digests"
	"github.com/lihongjie0209/sm-go-bc/util"
)

// KDF implements the Key Derivation Function defined in GM/T 0003-2012.
// KDF(Z, klen) = K₁ || K₂ || ... || Kₙ
// where Kᵢ = Hash(Z || Counter(i))
func KDF(z []byte, klen int) []byte {
	if klen <= 0 {
		return []byte{}
	}
	
	digest := digests.NewSM3Digest()
	hashLen := digest.GetDigestSize()
	
	// Calculate number of hash iterations needed
	numBlocks := (klen + hashLen - 1) / hashLen
	
	result := make([]byte, 0, numBlocks*hashLen)
	
	for i := 1; i <= numBlocks; i++ {
		// Hash(Z || Counter)
		digest.Reset()
		digest.BlockUpdate(z, 0, len(z))
		
		// Counter as 4-byte big-endian
		counter := util.IntToBytes(i)
		digest.BlockUpdate(counter, 0, len(counter))
		
		hash := make([]byte, hashLen)
		digest.DoFinal(hash, 0)
		result = append(result, hash...)
	}
	
	// Return exactly klen bytes
	return result[:klen]
}

// IsAllZero checks if a byte slice contains all zeros.
func IsAllZero(data []byte) bool {
	for _, b := range data {
		if b != 0 {
			return false
		}
	}
	return true
}
