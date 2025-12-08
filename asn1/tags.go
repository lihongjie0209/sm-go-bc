package asn1

// ASN.1 Universal tags as defined in X.690
const (
	// Universal class tags
	TagBoolean          = 0x01
	TagInteger          = 0x02
	TagBitString        = 0x03
	TagOctetString      = 0x04
	TagNull             = 0x05
	TagObjectIdentifier = 0x06
	TagEnumerated       = 0x0a
	TagUTF8String       = 0x0c
	TagSequence         = 0x10
	TagSet              = 0x11
	TagPrintableString  = 0x13
	TagT61String        = 0x14
	TagIA5String        = 0x16
	TagUTCTime          = 0x17
	TagGeneralizedTime  = 0x18
	
	// Constructed flag
	TagConstructed = 0x20
	
	// Context-specific class
	TagContextSpecific = 0x80
	
	// Application class
	TagApplication = 0x40
	
	// Private class
	TagPrivate = 0xc0
)

// Tag class masks
const (
	ClassUniversal       = 0x00
	ClassApplication     = 0x40
	ClassContextSpecific = 0x80
	ClassPrivate         = 0xc0
)

// IsConstructed returns true if the tag indicates a constructed encoding.
func IsConstructed(tag int) bool {
	return (tag & TagConstructed) != 0
}

// GetClass returns the class of the tag.
func GetClass(tag int) int {
	return tag & 0xc0
}

// GetTagNumber returns the tag number from a tag byte.
func GetTagNumber(tag int) int {
	return tag & 0x1f
}
