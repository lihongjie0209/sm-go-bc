// Package params provides cipher parameter types.
package params

// ECKeyParameters is the base type for EC key parameters.
// Based on: org.bouncycastle.crypto.params.ECKeyParameters
type ECKeyParameters struct {
	*BaseAsymmetricKeyParameter
	parameters *ECDomainParameters
}

// NewECKeyParameters creates new EC key parameters.
func NewECKeyParameters(privateKey bool, parameters *ECDomainParameters) *ECKeyParameters {
	return &ECKeyParameters{
		BaseAsymmetricKeyParameter: NewBaseAsymmetricKeyParameter(privateKey),
		parameters:                 parameters,
	}
}

// GetParameters returns the EC domain parameters.
func (p *ECKeyParameters) GetParameters() *ECDomainParameters {
	return p.parameters
}
