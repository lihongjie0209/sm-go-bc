package agreement

import (
	"errors"
	"math/big"

	"github.com/lihongjie0209/sm-go-bc/math/ec"
)

// SM2KeyExchangePrivateParameters contains private parameters for SM2 key exchange.
type SM2KeyExchangePrivateParameters struct {
	initiator            bool
	staticPrivateKey     *big.Int
	staticPublicPoint    *ec.Point
	ephemeralPrivateKey  *big.Int
	ephemeralPublicPoint *ec.Point
	curve                *ec.Curve
}

// NewSM2KeyExchangePrivateParameters creates new SM2 key exchange private parameters.
func NewSM2KeyExchangePrivateParameters(
	initiator bool,
	staticPrivateKey *big.Int,
	ephemeralPrivateKey *big.Int,
	curve *ec.Curve,
) (*SM2KeyExchangePrivateParameters, error) {
	if staticPrivateKey == nil {
		return nil, errors.New("staticPrivateKey cannot be nil")
	}
	if ephemeralPrivateKey == nil {
		return nil, errors.New("ephemeralPrivateKey cannot be nil")
	}
	if curve == nil {
		return nil, errors.New("curve cannot be nil")
	}

	// Calculate public points
	staticPublicPoint := curve.ScalarBaseMult(staticPrivateKey.Bytes())
	ephemeralPublicPoint := curve.ScalarBaseMult(ephemeralPrivateKey.Bytes())

	return &SM2KeyExchangePrivateParameters{
		initiator:            initiator,
		staticPrivateKey:     staticPrivateKey,
		staticPublicPoint:    staticPublicPoint,
		ephemeralPrivateKey:  ephemeralPrivateKey,
		ephemeralPublicPoint: ephemeralPublicPoint,
		curve:                curve,
	}, nil
}

// IsInitiator returns true if this party is the initiator.
func (p *SM2KeyExchangePrivateParameters) IsInitiator() bool {
	return p.initiator
}

// GetStaticPrivateKey returns the static private key.
func (p *SM2KeyExchangePrivateParameters) GetStaticPrivateKey() *big.Int {
	return p.staticPrivateKey
}

// GetStaticPublicPoint returns the computed static public point.
func (p *SM2KeyExchangePrivateParameters) GetStaticPublicPoint() *ec.Point {
	return p.staticPublicPoint
}

// GetEphemeralPrivateKey returns the ephemeral private key.
func (p *SM2KeyExchangePrivateParameters) GetEphemeralPrivateKey() *big.Int {
	return p.ephemeralPrivateKey
}

// GetEphemeralPublicPoint returns the computed ephemeral public point.
func (p *SM2KeyExchangePrivateParameters) GetEphemeralPublicPoint() *ec.Point {
	return p.ephemeralPublicPoint
}

// GetCurve returns the curve.
func (p *SM2KeyExchangePrivateParameters) GetCurve() *ec.Curve {
	return p.curve
}

// IsCipherParameters implements the CipherParameters interface.
func (p *SM2KeyExchangePrivateParameters) IsCipherParameters() bool {
	return true
}
