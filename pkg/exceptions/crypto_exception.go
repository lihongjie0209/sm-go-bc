package exceptions

// CryptoException is the base exception class for cryptographic errors
type CryptoException struct {
	message string
}

func NewCryptoException(message string) *CryptoException {
	return &CryptoException{message: message}
}

func (e *CryptoException) Error() string {
	return e.message
}
