package crypto

// ParametersWithID wraps cipher parameters with a user ID.
type ParametersWithID struct {
	parameters CipherParameters
	id         []byte
}

// NewParametersWithID creates a new ParametersWithID.
func NewParametersWithID(parameters CipherParameters, id []byte) *ParametersWithID {
	return &ParametersWithID{
		parameters: parameters,
		id:         id,
	}
}

// GetParameters returns the wrapped parameters.
func (p *ParametersWithID) GetParameters() CipherParameters {
	return p.parameters
}

// GetID returns the user ID.
func (p *ParametersWithID) GetID() []byte {
	return p.id
}

// IsCipherParameters implements the CipherParameters interface.
func (p *ParametersWithID) IsCipherParameters() bool {
	return true
}
