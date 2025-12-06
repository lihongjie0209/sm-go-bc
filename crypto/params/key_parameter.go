// Package params provides cryptographic parameter types.
package params

import "github.com/lihongjie0209/sm-go-bc/crypto"

// KeyParameter holds a symmetric key.
// Reference: org.bouncycastle.crypto.params.KeyParameter
type KeyParameter struct {
	key []byte
}

// NewKeyParameter creates a new key parameter.
func NewKeyParameter(key []byte) *KeyParameter {
	// Make a defensive copy
	keyCopy := make([]byte, len(key))
	copy(keyCopy, key)
	return &KeyParameter{key: keyCopy}
}

// GetKey returns the key bytes.
func (kp *KeyParameter) GetKey() []byte {
	return kp.key
}

// IsCipherParameters implements the CipherParameters marker interface.
func (kp *KeyParameter) IsCipherParameters() bool {
	return true
}

// Ensure KeyParameter implements CipherParameters
var _ crypto.CipherParameters = (*KeyParameter)(nil)
