package agreement

import (
	"errors"

	"github.com/lihongjie0209/sm-go-bc/math/ec"
)

// SM2KeyExchangePublicParameters contains public parameters for SM2 key exchange.
type SM2KeyExchangePublicParameters struct {
	staticPublicKey    *ec.Point
	ephemeralPublicKey *ec.Point
}

// NewSM2KeyExchangePublicParameters creates new SM2 key exchange public parameters.
func NewSM2KeyExchangePublicParameters(
	staticPublicKey *ec.Point,
	ephemeralPublicKey *ec.Point,
) (*SM2KeyExchangePublicParameters, error) {
	if staticPublicKey == nil {
		return nil, errors.New("staticPublicKey cannot be nil")
	}
	if ephemeralPublicKey == nil {
		return nil, errors.New("ephemeralPublicKey cannot be nil")
	}

	return &SM2KeyExchangePublicParameters{
		staticPublicKey:    staticPublicKey,
		ephemeralPublicKey: ephemeralPublicKey,
	}, nil
}

// GetStaticPublicKey returns the static public key.
func (p *SM2KeyExchangePublicParameters) GetStaticPublicKey() *ec.Point {
	return p.staticPublicKey
}

// GetEphemeralPublicKey returns the ephemeral public key.
func (p *SM2KeyExchangePublicParameters) GetEphemeralPublicKey() *ec.Point {
	return p.ephemeralPublicKey
}

// IsCipherParameters implements the CipherParameters interface.
func (p *SM2KeyExchangePublicParameters) IsCipherParameters() bool {
	return true
}
