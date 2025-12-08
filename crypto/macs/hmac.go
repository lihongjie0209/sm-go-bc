// Package macs implements Message Authentication Code algorithms.
package macs

import (
	"errors"

	"github.com/lihongjie0209/sm-go-bc/crypto"
	"github.com/lihongjie0209/sm-go-bc/crypto/params"
)

// HMAC constants for padding
const (
	IPAD = 0x36
	OPAD = 0x5C
)

// HMac implements HMAC (Hash-based Message Authentication Code) as defined in RFC 2104.
// It can work with any hash function that implements the Digest interface.
//
// Reference: org.bouncycastle.crypto.macs.HMac
// Reference: RFC 2104 - HMAC: Keyed-Hashing for Message Authentication
type HMac struct {
	digest      crypto.Digest
	digestSize  int
	blockLength int
	inputPad    []byte
	outputBuf   []byte
}

// NewHMac creates a new HMAC instance with the given digest algorithm.
//
// Parameters:
//   - digest: the underlying hash function (e.g., SM3Digest)
//
// Returns:
//   - *HMac: a new HMAC instance
func NewHMac(digest crypto.Digest) *HMac {
	hmac := &HMac{
		digest:     digest,
		digestSize: digest.GetDigestSize(),
	}

	// Get the block length from the digest
	// For digests that implement GetByteLength(), use that
	// Otherwise, default to 64 bytes (suitable for SHA-1, SHA-256, SM3)
	if extDigest, ok := digest.(interface{ GetByteLength() int }); ok {
		hmac.blockLength = extDigest.GetByteLength()
	} else {
		hmac.blockLength = 64
	}

	hmac.inputPad = make([]byte, hmac.blockLength)
	hmac.outputBuf = make([]byte, hmac.blockLength+hmac.digestSize)

	return hmac
}

// GetAlgorithmName returns the algorithm name in format "HMac/{digest-name}".
func (h *HMac) GetAlgorithmName() string {
	return "HMac/" + h.digest.GetAlgorithmName()
}

// GetMacSize returns the MAC size (same as the underlying digest size).
func (h *HMac) GetMacSize() int {
	return h.digestSize
}

// Init initializes the HMAC with a key.
//
// Parameters:
//   - params: the key parameter (must be KeyParameter)
//
// Returns:
//   - error: nil on success, error if params is not a KeyParameter
func (h *HMac) Init(p crypto.CipherParameters) error {
	h.digest.Reset()

	// Params must be a KeyParameter
	keyParam, ok := p.(*params.KeyParameter)
	if !ok {
		return errors.New("HMac requires KeyParameter")
	}

	key := keyParam.GetKey()
	keyLength := len(key)

	// If the key is longer than the block size, hash it first
	if keyLength > h.blockLength {
		h.digest.BlockUpdate(key, 0, keyLength)
		h.digest.DoFinal(h.inputPad, 0)
		keyLength = h.digestSize
	} else {
		// Copy the key to inputPad
		copy(h.inputPad[:keyLength], key)
	}

	// Pad the key with zeros if necessary
	for i := keyLength; i < h.blockLength; i++ {
		h.inputPad[i] = 0
	}

	// Copy inputPad to outputBuf (first blockLength bytes)
	copy(h.outputBuf[:h.blockLength], h.inputPad)

	// XOR the key with ipad for the input padding
	h.xorPad(h.inputPad, h.blockLength, IPAD)

	// XOR the key with opad for the output padding
	h.xorPad(h.outputBuf, h.blockLength, OPAD)

	// Initialize the inner hash
	h.digest.BlockUpdate(h.inputPad, 0, len(h.inputPad))

	return nil
}

// xorPad XORs a pad with a specific byte value.
//
// Parameters:
//   - pad: the padding buffer
//   - len: the length to XOR
//   - n: the byte value to XOR with
func (h *HMac) xorPad(pad []byte, length int, n byte) {
	for i := 0; i < length; i++ {
		pad[i] ^= n
	}
}

// Update adds a single byte to the MAC calculation.
func (h *HMac) Update(in byte) {
	h.digest.Update(in)
}

// UpdateArray adds multiple bytes to the MAC calculation.
//
// Parameters:
//   - in: the byte array containing the data
//   - inOff: the offset into the input array where the data starts
//   - len: the length of the data to add
func (h *HMac) UpdateArray(in []byte, inOff int, length int) {
	h.digest.BlockUpdate(in, inOff, length)
}

// DoFinal completes the MAC calculation and writes the result to the output array.
//
// Parameters:
//   - out: the output array to write the MAC to
//   - outOff: the offset into the output array to start writing
//
// Returns:
//   - int: the number of bytes written
//   - error: nil on success, error if output buffer is too small
func (h *HMac) DoFinal(out []byte, outOff int) (int, error) {
	if len(out)-outOff < h.digestSize {
		return 0, errors.New("output buffer too small")
	}

	// Complete the inner hash: H(K ⊕ ipad || message)
	h.digest.DoFinal(h.outputBuf, h.blockLength)

	// Compute the outer hash: H(K ⊕ opad || inner_hash)
	h.digest.BlockUpdate(h.outputBuf, 0, h.blockLength+h.digestSize)
	result := h.digest.DoFinal(out, outOff)

	// Reset for next use
	// Re-initialize the inner hash with the input pad
	h.digest.BlockUpdate(h.inputPad, 0, len(h.inputPad))

	return result, nil
}

// Reset resets the MAC to its initialized state.
func (h *HMac) Reset() {
	// Reset the underlying digest
	h.digest.Reset()

	// Re-initialize with the input pad (K ⊕ ipad)
	h.digest.BlockUpdate(h.inputPad, 0, len(h.inputPad))
}
