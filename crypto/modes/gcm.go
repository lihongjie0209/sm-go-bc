// Package modes implements block cipher modes of operation.
package modes

import (
	"errors"

	"github.com/lihongjie0209/sm-go-bc/crypto"
	"github.com/lihongjie0209/sm-go-bc/crypto/params"
	"github.com/lihongjie0209/sm-go-bc/util"
)

// GCMBlockCipher implements Galois/Counter Mode (GCM) as detailed in NIST SP 800-38D.
//
// GCM is an AEAD (Authenticated Encryption with Associated Data) mode that provides:
// - Confidentiality (encryption)
// - Authenticity (authentication tag)
// - Optional additional authenticated data (AAD) - data that is authenticated but not encrypted
//
// Reference: NIST SP 800-38D, org.bouncycastle.crypto.modes.GCMBlockCipher
type GCMBlockCipher struct {
	cipher crypto.BlockCipher

	// Initialization state
	forEncryption  bool
	initialised    bool
	macSize        int // MAC size in bytes
	nonce          []byte
	associatedText []byte

	// GCM state
	H       []byte // Hash subkey (E(K, 0^128))
	J0      []byte // Initial counter block
	counter []byte // Current counter
	S       []byte // Authentication state
	S_at    []byte // AAD authentication state

	// Buffering
	bufBlock    []byte
	bufOff      int
	totalLength int64

	// AAD processing
	atBlock    []byte
	atBlockPos int
	atLength   int64

	// Final state
	macBlock []byte

	// Decryption buffer (buffer all data for MAC verification)
	ciphertextBuffer       []byte
	ciphertextBufferLength int
}

const gcmBlockSize = 16

// NewGCMBlockCipher creates a new GCM mode cipher.
// The cipher must have a block size of 16 bytes.
func NewGCMBlockCipher(cipher crypto.BlockCipher) *GCMBlockCipher {
	if cipher.GetBlockSize() != gcmBlockSize {
		panic("cipher required with a block size of 16")
	}

	return &GCMBlockCipher{
		cipher:  cipher,
		H:       make([]byte, gcmBlockSize),
		J0:      make([]byte, gcmBlockSize),
		counter: make([]byte, gcmBlockSize),
		S:       make([]byte, gcmBlockSize),
		S_at:    make([]byte, gcmBlockSize),
		bufBlock: make([]byte, gcmBlockSize),
		atBlock:  make([]byte, gcmBlockSize),
	}
}

// GetUnderlyingCipher returns the underlying block cipher.
func (g *GCMBlockCipher) GetUnderlyingCipher() crypto.BlockCipher {
	return g.cipher
}

// Init initializes the cipher for encryption or decryption.
//
// Parameters:
//   - forEncryption: true for encryption, false for decryption
//   - parameters: AEADParameters or ParametersWithIV
func (g *GCMBlockCipher) Init(forEncryption bool, parameters crypto.CipherParameters) {
	g.forEncryption = forEncryption
	g.macBlock = nil
	g.initialised = true

	var keyParam *params.KeyParameter
	var newNonce []byte

	// Parse parameters
	if aeadParams, ok := parameters.(*params.AEADParameters); ok {
		newNonce = aeadParams.GetNonce()
		g.associatedText = aeadParams.GetAssociatedText()

		macSizeBits := aeadParams.GetMacSize()
		if macSizeBits < 32 || macSizeBits > 128 || macSizeBits%8 != 0 {
			panic("Invalid value for MAC size")
		}

		g.macSize = macSizeBits / 8
		keyParam = aeadParams.GetKey()
	} else if ivParams, ok := parameters.(*params.ParametersWithIV); ok {
		newNonce = ivParams.GetIV()
		g.associatedText = nil
		g.macSize = 16
		keyParam = ivParams.GetParameters().(*params.KeyParameter)
	} else {
		panic("invalid parameters passed to GCM")
	}

	// Adjust buffer size
	bufLength := gcmBlockSize
	if !forEncryption {
		bufLength = gcmBlockSize + g.macSize
	}
	g.bufBlock = make([]byte, bufLength)

	if newNonce == nil || len(newNonce) < 1 {
		panic("IV must be at least 1 byte")
	}

	g.nonce = newNonce

	// Initialize cipher and compute H = E(K, 0)
	g.cipher.Init(true, keyParam)
	for i := range g.H {
		g.H[i] = 0
	}
	g.cipher.ProcessBlock(g.H, 0, g.H, 0)

	// Compute J0 from nonce
	for i := range g.J0 {
		g.J0[i] = 0
	}

	if len(newNonce) == 12 {
		// Standard case: 96-bit nonce
		copy(g.J0, newNonce)
		g.J0[15] = 0x01
	} else {
		// Non-standard: hash the nonce
		g.gHash(g.J0, newNonce)
		lenBlock := make([]byte, 16)
		util.Uint64ToBigEndian(uint64(len(newNonce))*8, lenBlock, 8)
		g.gHashBlock(g.J0, lenBlock)
	}

	// Initialize state
	for i := range g.S {
		g.S[i] = 0
	}
	for i := range g.S_at {
		g.S_at[i] = 0
	}
	for i := range g.atBlock {
		g.atBlock[i] = 0
	}
	g.atBlockPos = 0
	g.atLength = 0
	copy(g.counter, g.J0)
	g.bufOff = 0
	g.totalLength = 0

	// Reset decryption buffer
	g.ciphertextBufferLength = 0

	// Process AAD if provided
	if g.associatedText != nil && len(g.associatedText) > 0 {
		g.processAADBytes(g.associatedText, 0, len(g.associatedText))
	}
}

// GetAlgorithmName returns the algorithm name.
func (g *GCMBlockCipher) GetAlgorithmName() string {
	return g.cipher.GetAlgorithmName() + "/GCM"
}

// GetBlockSize returns the block size (always 16 for GCM).
func (g *GCMBlockCipher) GetBlockSize() int {
	return gcmBlockSize
}

// ProcessBlock is not supported for GCM mode (use ProcessBytes and DoFinal).
func (g *GCMBlockCipher) ProcessBlock(in []byte, inOff int, out []byte, outOff int) int {
	panic("processBlock not supported for GCM mode (use ProcessBytes and DoFinal)")
}

// Reset resets the cipher to initial state.
func (g *GCMBlockCipher) Reset() {
	for i := range g.S {
		g.S[i] = 0
	}
	for i := range g.S_at {
		g.S_at[i] = 0
	}
	for i := range g.atBlock {
		g.atBlock[i] = 0
	}
	g.atBlockPos = 0
	g.atLength = 0

	if g.J0 != nil {
		copy(g.counter, g.J0)
	}

	g.bufOff = 0
	g.totalLength = 0
	g.macBlock = nil
	g.ciphertextBufferLength = 0

	// Reprocess AAD
	if g.associatedText != nil && len(g.associatedText) > 0 {
		g.processAADBytes(g.associatedText, 0, len(g.associatedText))
	}

	g.cipher.Reset()
}

// ProcessBytes processes multiple bytes of data.
// For encryption, returns encrypted data immediately.
// For decryption, buffers all data for MAC verification in DoFinal.
func (g *GCMBlockCipher) ProcessBytes(in []byte, inOff int, length int, out []byte, outOff int) (int, error) {
	if !g.initialised {
		return 0, errors.New("GCM cipher not initialised")
	}

	if inOff+length > len(in) {
		return 0, errors.New("input buffer too short")
	}

	if g.forEncryption {
		// Encryption: process immediately
		return g.encryptBytes(in, inOff, length, out, outOff), nil
	}

	// Decryption: buffer all data for MAC verification
	newLength := g.ciphertextBufferLength + length

	// Expand buffer if needed
	if newLength > len(g.ciphertextBuffer) {
		newCap := len(g.ciphertextBuffer) * 2
		if newCap < newLength {
			newCap = newLength
		}
		newBuffer := make([]byte, newCap)
		copy(newBuffer, g.ciphertextBuffer[:g.ciphertextBufferLength])
		g.ciphertextBuffer = newBuffer
	}

	// Copy data to buffer
	copy(g.ciphertextBuffer[g.ciphertextBufferLength:], in[inOff:inOff+length])
	g.ciphertextBufferLength += length

	return 0, nil // No output until DoFinal verifies MAC
}

// DoFinal completes the encryption/decryption and generates/verifies the authentication tag.
func (g *GCMBlockCipher) DoFinal(out []byte, outOff int) (int, error) {
	if !g.initialised {
		return 0, errors.New("GCM cipher not initialised")
	}

	if g.forEncryption {
		return g.encryptDoFinal(out, outOff)
	}
	return g.decryptDoFinal(out, outOff)
}

// GetMac returns the authentication tag (MAC).
func (g *GCMBlockCipher) GetMac() []byte {
	if g.macBlock == nil {
		return make([]byte, g.macSize)
	}
	result := make([]byte, len(g.macBlock))
	copy(result, g.macBlock)
	return result
}

// GetOutputSize returns the output size for the given input length.
func (g *GCMBlockCipher) GetOutputSize(length int) int {
	totalData := length + g.bufOff

	if g.forEncryption {
		return totalData + g.macSize
	}

	if totalData < g.macSize {
		return 0
	}
	return totalData - g.macSize
}

// Private helper methods

func (g *GCMBlockCipher) processAADBytes(aad []byte, offset int, length int) {
	inOff := offset
	remaining := length

	// Fill partial block
	if g.atBlockPos > 0 {
		available := gcmBlockSize - g.atBlockPos
		if remaining < available {
			copy(g.atBlock[g.atBlockPos:], aad[inOff:inOff+remaining])
			g.atBlockPos += remaining
			return
		}

		copy(g.atBlock[g.atBlockPos:], aad[inOff:inOff+available])
		g.gHashBlock(g.S_at, g.atBlock)
		g.atLength += int64(gcmBlockSize)
		inOff += available
		remaining -= available
		g.atBlockPos = 0
	}

	// Process complete blocks
	for remaining >= gcmBlockSize {
		g.gHashBlock(g.S_at, aad[inOff:inOff+gcmBlockSize])
		g.atLength += int64(gcmBlockSize)
		inOff += gcmBlockSize
		remaining -= gcmBlockSize
	}

	// Buffer remaining bytes
	if remaining > 0 {
		copy(g.atBlock, aad[inOff:inOff+remaining])
		g.atBlockPos = remaining
	}
}

func (g *GCMBlockCipher) encryptBytes(in []byte, inOff int, length int, out []byte, outOff int) int {
	processed := 0

	for i := 0; i < length; i++ {
		g.bufBlock[g.bufOff] = in[inOff+i]
		g.bufOff++

		if g.bufOff == gcmBlockSize {
			g.encryptBlock(g.bufBlock, out, outOff+processed)
			processed += gcmBlockSize
			g.bufOff = 0
		}
	}

	return processed
}

func (g *GCMBlockCipher) encryptBlock(block []byte, out []byte, outOff int) {
	// Initialize cipher state if this is the first block
	if g.totalLength == 0 {
		g.initCipher()
	}

	// Increment counter
	GCMIncrement(g.counter)

	// Encrypt counter
	counterBlock := make([]byte, gcmBlockSize)
	g.cipher.ProcessBlock(g.counter, 0, counterBlock, 0)

	// XOR with plaintext
	ciphertext := make([]byte, gcmBlockSize)
	for i := 0; i < gcmBlockSize; i++ {
		ciphertext[i] = block[i] ^ counterBlock[i]
	}

	// Update authentication hash with ciphertext
	g.gHashBlock(g.S, ciphertext)
	g.totalLength += int64(gcmBlockSize)

	// Output ciphertext
	copy(out[outOff:], ciphertext)
}

func (g *GCMBlockCipher) encryptDoFinal(out []byte, outOff int) (int, error) {
	// Initialize cipher state if not done yet
	if g.totalLength == 0 {
		g.initCipher()
	}

	resultLen := 0

	// Process any remaining bytes
	if g.bufOff > 0 {
		// Increment counter
		GCMIncrement(g.counter)

		// Encrypt counter
		counterBlock := make([]byte, gcmBlockSize)
		g.cipher.ProcessBlock(g.counter, 0, counterBlock, 0)

		// XOR with plaintext (partial block)
		ciphertext := make([]byte, g.bufOff)
		for i := 0; i < g.bufOff; i++ {
			ciphertext[i] = g.bufBlock[i] ^ counterBlock[i]
		}

		// Update authentication hash (pad to block size)
		paddedCiphertext := make([]byte, gcmBlockSize)
		copy(paddedCiphertext, ciphertext)
		g.gHashBlock(g.S, paddedCiphertext)
		g.totalLength += int64(g.bufOff)

		// Output ciphertext
		copy(out[outOff:], ciphertext)
		resultLen = g.bufOff
	}

	// Hash the lengths
	lenBlock := make([]byte, gcmBlockSize)
	util.Uint64ToBigEndian(uint64(g.atLength*8), lenBlock, 0)
	util.Uint64ToBigEndian(uint64(g.totalLength*8), lenBlock, 8)
	g.gHashBlock(g.S, lenBlock)

	// Compute tag: T = GCTR_K(J0, S)
	tag := make([]byte, gcmBlockSize)
	g.cipher.ProcessBlock(g.J0, 0, tag, 0)
	gcmXOR(tag, g.S)

	// Output tag (truncated to macSize)
	g.macBlock = make([]byte, g.macSize)
	copy(g.macBlock, tag[:g.macSize])
	copy(out[outOff+resultLen:], g.macBlock)

	resultLen += g.macSize
	g.Reset()

	return resultLen, nil
}

func (g *GCMBlockCipher) decryptDoFinal(out []byte, outOff int) (int, error) {
	if g.ciphertextBufferLength < g.macSize {
		return 0, errors.New("data too short")
	}

	// Initialize cipher state if not done yet
	if g.totalLength == 0 {
		g.initCipher()
	}

	// ciphertextBuffer contains all ciphertext + MAC
	dataLen := g.ciphertextBufferLength - g.macSize
	ciphertext := g.ciphertextBuffer[:g.ciphertextBufferLength]

	// First, hash all ciphertext blocks for MAC computation
	pos := 0
	for pos+gcmBlockSize <= dataLen {
		g.gHashBlock(g.S, ciphertext[pos:pos+gcmBlockSize])
		g.totalLength += int64(gcmBlockSize)
		pos += gcmBlockSize
	}

	// Hash any remaining partial block
	if pos < dataLen {
		paddedBlock := make([]byte, gcmBlockSize)
		copy(paddedBlock, ciphertext[pos:dataLen])
		g.gHashBlock(g.S, paddedBlock)
		g.totalLength += int64(dataLen - pos)
	}

	// Extract the received MAC/tag
	receivedTag := ciphertext[dataLen:g.ciphertextBufferLength]

	// Hash the lengths
	lenBlock := make([]byte, gcmBlockSize)
	util.Uint64ToBigEndian(uint64(g.atLength*8), lenBlock, 0)
	util.Uint64ToBigEndian(uint64(g.totalLength*8), lenBlock, 8)
	g.gHashBlock(g.S, lenBlock)

	// Compute expected tag
	expectedTag := make([]byte, gcmBlockSize)
	g.cipher.ProcessBlock(g.J0, 0, expectedTag, 0)
	gcmXOR(expectedTag, g.S)

	// Verify tag (constant-time comparison)
	tagMatch := true
	for i := 0; i < g.macSize; i++ {
		if expectedTag[i] != receivedTag[i] {
			tagMatch = false
		}
	}

	if !tagMatch {
		return 0, errors.New("mac check in GCM failed")
	}

	// MAC verified! Now decrypt all data
	pos = 0
	for pos+gcmBlockSize <= dataLen {
		GCMIncrement(g.counter)
		counterBlock := make([]byte, gcmBlockSize)
		g.cipher.ProcessBlock(g.counter, 0, counterBlock, 0)

		for i := 0; i < gcmBlockSize; i++ {
			out[outOff+pos+i] = ciphertext[pos+i] ^ counterBlock[i]
		}
		pos += gcmBlockSize
	}

	// Decrypt any remaining partial block
	if pos < dataLen {
		GCMIncrement(g.counter)
		counterBlock := make([]byte, gcmBlockSize)
		g.cipher.ProcessBlock(g.counter, 0, counterBlock, 0)

		for i := 0; i < dataLen-pos; i++ {
			out[outOff+pos+i] = ciphertext[pos+i] ^ counterBlock[i]
		}
	}

	g.macBlock = make([]byte, g.macSize)
	copy(g.macBlock, receivedTag)

	g.Reset()
	return dataLen, nil
}

func (g *GCMBlockCipher) initCipher() {
	// Finalize AAD processing
	if g.atBlockPos > 0 {
		g.gHashBlock(g.S_at, g.atBlock)
		g.atLength += int64(g.atBlockPos)
	}

	// Initialize S with AAD hash
	if g.atLength > 0 {
		copy(g.S, g.S_at)
	}
}

// gHashBlock performs GHASH: multiply and XOR in Galois field.
func (g *GCMBlockCipher) gHashBlock(Y []byte, X []byte) {
	gcmXOR(Y, X)
	result := GCMMultiply(Y, g.H)
	copy(Y, result)
}

// gHash performs GHASH over multiple blocks.
func (g *GCMBlockCipher) gHash(Y []byte, data []byte) {
	pos := 0
	for pos+gcmBlockSize <= len(data) {
		g.gHashBlock(Y, data[pos:pos+gcmBlockSize])
		pos += gcmBlockSize
	}

	if pos < len(data) {
		paddedBlock := make([]byte, gcmBlockSize)
		copy(paddedBlock, data[pos:])
		g.gHashBlock(Y, paddedBlock)
	}
}

// Ensure GCMBlockCipher implements BlockCipher interface
var _ crypto.BlockCipher = (*GCMBlockCipher)(nil)
