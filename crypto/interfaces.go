// Package crypto provides core cryptographic interfaces for SM algorithms.
// This mirrors the structure of Bouncy Castle's crypto package.
package crypto

// Digest defines the interface for cryptographic hash functions.
// Reference: org.bouncycastle.crypto.Digest
type Digest interface {
	// GetAlgorithmName returns the algorithm name
	GetAlgorithmName() string

	// GetDigestSize returns the size in bytes of the digest produced by this hash
	GetDigestSize() int

	// Update adds a single byte to the hash
	Update(in byte)

	// BlockUpdate adds multiple bytes to the hash
	BlockUpdate(in []byte, inOff int, len int)

	// DoFinal completes the hash computation and returns the digest
	DoFinal(out []byte, outOff int) int

	// Reset resets the digest back to its initial state
	Reset()
}

// BlockCipher defines the interface for block cipher engines.
// Reference: org.bouncycastle.crypto.BlockCipher
type BlockCipher interface {
	// Init initializes the cipher for encryption or decryption
	// forEncryption: true for encryption, false for decryption
	// params: the key material
	Init(forEncryption bool, params CipherParameters)

	// GetAlgorithmName returns the algorithm name
	GetAlgorithmName() string

	// GetBlockSize returns the block size for this cipher (in bytes)
	GetBlockSize() int

	// ProcessBlock processes a single block
	ProcessBlock(in []byte, inOff int, out []byte, outOff int) int

	// Reset resets the cipher back to its initial state
	Reset()
}

// Signer defines the interface for digital signature algorithms.
// Reference: org.bouncycastle.crypto.Signer
type Signer interface {
	// Init initializes the signer for signing or verification
	Init(forSigning bool, params CipherParameters)

	// Update adds a single byte to the message
	Update(b byte)

	// BlockUpdate adds multiple bytes to the message
	BlockUpdate(in []byte, inOff int, len int)

	// GenerateSignature generates the signature for the message
	GenerateSignature() ([]byte, error)

	// VerifySignature verifies the signature against the message
	VerifySignature(signature []byte) bool

	// Reset resets the signer back to its initial state
	Reset()
}

// AsymmetricBlockCipher defines the interface for asymmetric encryption engines.
// Reference: org.bouncycastle.crypto.AsymmetricBlockCipher
type AsymmetricBlockCipher interface {
	// Init initializes the cipher for encryption or decryption
	Init(forEncryption bool, params CipherParameters)

	// GetInputBlockSize returns the maximum size of input block
	GetInputBlockSize() int

	// GetOutputBlockSize returns the maximum size of output block
	GetOutputBlockSize() int

	// ProcessBlock processes the input block
	ProcessBlock(in []byte, inOff int, inLen int) ([]byte, error)

	// Reset resets the cipher
	Reset()
}

// CipherParameters is a marker interface for cipher parameters.
// Reference: org.bouncycastle.crypto.CipherParameters
type CipherParameters interface {
	// Marker method to identify cipher parameters
	IsCipherParameters() bool
}

// BlockCipherMode defines the interface for block cipher modes of operation.
type BlockCipherMode interface {
	BlockCipher
	// GetUnderlyingCipher returns the underlying block cipher
	GetUnderlyingCipher() BlockCipher
}

// BufferedBlockCipher defines the interface for buffered block cipher operations.
// Reference: org.bouncycastle.crypto.BufferedBlockCipher
type BufferedBlockCipher interface {
	// Init initializes the cipher
	Init(forEncryption bool, params CipherParameters)

	// GetAlgorithmName returns the algorithm name
	GetAlgorithmName() string

	// GetBlockSize returns the block size
	GetBlockSize() int

	// GetUpdateOutputSize returns the size of the output buffer required for an update
	GetUpdateOutputSize(length int) int

	// GetOutputSize returns the size of the output buffer required for the data
	GetOutputSize(length int) int

	// ProcessByte processes a single byte
	ProcessByte(in byte, out []byte, outOff int) (int, error)

	// ProcessBytes processes multiple bytes
	ProcessBytes(in []byte, inOff int, length int, out []byte, outOff int) (int, error)

	// DoFinal completes the encryption/decryption
	DoFinal(out []byte, outOff int) (int, error)

	// Reset resets the cipher
	Reset()
}

// BlockCipherPadding defines the interface for padding schemes.
// Reference: org.bouncycastle.crypto.paddings.BlockCipherPadding
type BlockCipherPadding interface {
	// Init initializes the padding
	Init(random []byte)

	// GetPaddingName returns the name of the padding
	GetPaddingName() string

	// AddPadding adds padding to the last block
	AddPadding(in []byte, inOff int) int

	// PadCount returns the number of pad bytes in the block
	PadCount(in []byte) (int, error)
}

// Memoable defines the interface for objects that can save and restore their state.
// Reference: org.bouncycastle.util.Memoable
type Memoable interface {
	// Copy creates a copy of the object
	Copy() Memoable

	// ResetMemoable restores the object to a previous state
	ResetMemoable(other Memoable)
}

// KeyGenerator defines the interface for key generation.
type KeyGenerator interface {
	// Init initializes the key generator
	Init(params interface{})

	// GenerateKey generates a new key
	GenerateKey() ([]byte, error)
}

// Agreement defines the interface for key agreement protocols.
// Reference: org.bouncycastle.crypto.Agreement
type Agreement interface {
	// Init initializes the agreement with parameters
	Init(params CipherParameters)

	// CalculateAgreement calculates the agreement value
	CalculateAgreement(params CipherParameters) []byte
}
