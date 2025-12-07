package smgobc

import (
	"errors"
	"github.com/lihongjie0209/sm-go-bc/crypto/engines"
	"github.com/lihongjie0209/sm-go-bc/crypto/modes"
	"github.com/lihongjie0209/sm-go-bc/crypto/paddings"
	"github.com/lihongjie0209/sm-go-bc/crypto/params"
)

// SM4 provides high-level API for SM4 encryption/decryption
//
// SM4 is a 128-bit block cipher algorithm using a 128-bit key
//
// Standard: GB/T 32907-2016
type SM4 struct{}

const (
	sm4KeySize   = 16 // 128 bits = 16 bytes
	sm4BlockSize = 16 // 128 bits = 16 bytes
)

// Encrypt encrypts data using ECB mode with PKCS7 padding
//
// Note: ECB mode is not secure and should only be used for demonstration
// and compatibility testing. Use CBC, CTR or GCM mode in production.
func (s *SM4) Encrypt(plaintext, key []byte) ([]byte, error) {
	if len(key) != sm4KeySize {
		return nil, errors.New("SM4 requires a 128 bit (16 byte) key")
	}

	// Create SM4 engine
	engine := engines.NewSM4Engine()
	mode := modes.NewECBBlockCipher(engine)
	padding := paddings.NewPKCS7Padding()
	cipher := modes.NewPaddedBufferedBlockCipher(mode, padding)

	// Init for encryption
	err := cipher.Init(true, key)
	if err != nil {
		return nil, err
	}

	// Encrypt
	return cipher.DoFinal(plaintext)
}

// Decrypt decrypts data using ECB mode with PKCS7 padding
func (s *SM4) Decrypt(ciphertext, key []byte) ([]byte, error) {
	if len(key) != sm4KeySize {
		return nil, errors.New("SM4 requires a 128 bit (16 byte) key")
	}

	if len(ciphertext)%sm4BlockSize != 0 {
		return nil, errors.New("ciphertext length must be a multiple of block size (16 bytes)")
	}

	// Create SM4 engine
	engine := engines.NewSM4Engine()
	mode := modes.NewECBBlockCipher(engine)
	padding := paddings.NewPKCS7Padding()
	cipher := modes.NewPaddedBufferedBlockCipher(mode, padding)

	// Init for decryption
	err := cipher.Init(false, key)
	if err != nil {
		return nil, err
	}

	// Decrypt
	return cipher.DoFinal(ciphertext)
}

// EncryptCBC encrypts data using CBC mode
func (s *SM4) EncryptCBC(plaintext, key, iv []byte) ([]byte, error) {
	if len(key) != sm4KeySize {
		return nil, errors.New("SM4 requires a 128 bit (16 byte) key")
	}
	if len(iv) != sm4BlockSize {
		return nil, errors.New("IV must be 16 bytes")
	}

	engine := engines.NewSM4Engine()
	mode := modes.NewCBCBlockCipher(engine)
	padding := paddings.NewPKCS7Padding()
	cipher := modes.NewPaddedBufferedBlockCipher(mode, padding)

	ivParams := params.NewParametersWithIV(key, iv)
	err := cipher.Init(true, ivParams)
	if err != nil {
		return nil, err
	}

	return cipher.DoFinal(plaintext)
}

// DecryptCBC decrypts data using CBC mode
func (s *SM4) DecryptCBC(ciphertext, key, iv []byte) ([]byte, error) {
	if len(key) != sm4KeySize {
		return nil, errors.New("SM4 requires a 128 bit (16 byte) key")
	}
	if len(iv) != sm4BlockSize {
		return nil, errors.New("IV must be 16 bytes")
	}

	engine := engines.NewSM4Engine()
	mode := modes.NewCBCBlockCipher(engine)
	padding := paddings.NewPKCS7Padding()
	cipher := modes.NewPaddedBufferedBlockCipher(mode, padding)

	ivParams := params.NewParametersWithIV(key, iv)
	err := cipher.Init(false, ivParams)
	if err != nil {
		return nil, err
	}

	return cipher.DoFinal(ciphertext)
}
