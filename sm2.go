package smgobc

import (
	"errors"

	"github.com/lihongjie0209/sm-go-bc/api"
)

// SM2 provides high-level API for SM2 operations
//
// SM2 is an elliptic curve cryptography algorithm based on 256-bit curves
//
// Standard: GM/T 0003-2012
type SM2 struct{}

// KeyPair represents an SM2 key pair
type KeyPair struct {
	PrivateKey []byte
	PublicKey  []byte
}

// GenerateKeyPair generates a new SM2 key pair
func (s *SM2) GenerateKeyPair() (*KeyPair, error) {
	keyPair, err := api.SM2GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	
	// Encode private key (32 bytes)
	privateKey := keyPair.PrivateKey.Bytes()
	if len(privateKey) < 32 {
		// Pad with leading zeros if necessary
		padded := make([]byte, 32)
		copy(padded[32-len(privateKey):], privateKey)
		privateKey = padded
	}

	// Encode public key (uncompressed format: 0x04 || x || y)
	publicKey, err := api.EncodePublicKey(keyPair.PublicKey)
	if err != nil {
		return nil, err
	}

	return &KeyPair{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
	}, nil
}

// Sign signs a message using SM2 signature algorithm
func (s *SM2) Sign(message, privateKey []byte, userID []byte) ([]byte, error) {
	if len(privateKey) != 32 {
		return nil, errors.New("private key must be 32 bytes")
	}

	if userID == nil {
		userID = []byte("1234567812345678") // Default user ID
	}

	return api.SM2Sign(message, privateKey, userID)
}

// Verify verifies an SM2 signature
func (s *SM2) Verify(message, signature, publicKey []byte, userID []byte) (bool, error) {
	if len(publicKey) < 65 {
		return false, errors.New("invalid public key")
	}

	if userID == nil {
		userID = []byte("1234567812345678") // Default user ID
	}

	return api.SM2Verify(message, signature, publicKey, userID)
}

// Encrypt encrypts a message using SM2 encryption
func (s *SM2) Encrypt(plaintext, publicKey []byte) ([]byte, error) {
	if len(publicKey) < 65 {
		return nil, errors.New("invalid public key")
	}

	return api.SM2Encrypt(plaintext, publicKey)
}

// Decrypt decrypts a message using SM2 decryption
func (s *SM2) Decrypt(ciphertext, privateKey []byte) ([]byte, error) {
	if len(privateKey) != 32 {
		return nil, errors.New("private key must be 32 bytes")
	}

	return api.SM2Decrypt(ciphertext, privateKey)
}
