// Package params provides cipher parameter types.
package params

import "github.com/lihongjie0209/sm-go-bc/crypto"

// AsymmetricKeyParameter is the base interface for asymmetric key parameters.
// Based on: org.bouncycastle.crypto.params.AsymmetricKeyParameter
type AsymmetricKeyParameter interface {
	crypto.CipherParameters
	IsPrivate() bool
}

// BaseAsymmetricKeyParameter provides a base implementation of AsymmetricKeyParameter.
type BaseAsymmetricKeyParameter struct {
	privateKey bool
}

// NewBaseAsymmetricKeyParameter creates a new base asymmetric key parameter.
func NewBaseAsymmetricKeyParameter(privateKey bool) *BaseAsymmetricKeyParameter {
	return &BaseAsymmetricKeyParameter{
		privateKey: privateKey,
	}
}

// IsPrivate returns true if this is a private key.
func (p *BaseAsymmetricKeyParameter) IsPrivate() bool {
	return p.privateKey
}
