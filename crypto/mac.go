// Package crypto provides core cryptographic interfaces for SM algorithms.
package crypto

// Mac defines the interface for Message Authentication Code algorithms.
// Reference: org.bouncycastle.crypto.Mac
type Mac interface {
	// Init initializes the MAC with the given parameters
	// params: the cipher parameters (typically KeyParameter)
	Init(params CipherParameters) error

	// GetAlgorithmName returns the algorithm name
	GetAlgorithmName() string

	// GetMacSize returns the size (in bytes) of the MAC
	GetMacSize() int

	// Update adds a single byte to the MAC calculation
	Update(in byte)

	// UpdateArray adds multiple bytes to the MAC calculation
	// in: the byte array containing the data
	// inOff: the offset into the input array where the data starts
	// len: the length of the data to add
	UpdateArray(in []byte, inOff int, len int)

	// DoFinal completes the MAC calculation and writes the result to the output array
	// out: the output array to write the MAC to
	// outOff: the offset into the output array to start writing
	// Returns: the number of bytes written
	DoFinal(out []byte, outOff int) (int, error)

	// Reset resets the MAC to its initial state
	Reset()
}
