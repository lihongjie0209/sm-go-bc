// Package params provides cipher parameter types.
package params

import (
	"github.com/lihongjie0209/sm-go-bc/math/ec"
)

// ECPublicKeyParameters represents EC public key parameters.
// Based on: org.bouncycastle.crypto.params.ECPublicKeyParameters
type ECPublicKeyParameters struct {
	*ECKeyParameters
	q *ec.Point
}

// NewECPublicKeyParameters creates new EC public key parameters.
func NewECPublicKeyParameters(q *ec.Point, parameters *ECDomainParameters) *ECPublicKeyParameters {
	return &ECPublicKeyParameters{
		ECKeyParameters: NewECKeyParameters(false, parameters),
		q:               q,
	}
}

// GetQ returns the public key point.
func (p *ECPublicKeyParameters) GetQ() *ec.Point {
	return p.q
}
