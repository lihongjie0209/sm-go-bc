package agreement

import (
	"crypto/subtle"
	"errors"
	"math"
	"math/big"

	"github.com/lihongjie0209/sm-go-bc/crypto"
	"github.com/lihongjie0209/sm-go-bc/crypto/digests"
	"github.com/lihongjie0209/sm-go-bc/math/ec"
)

// SM2KeyExchange implements SM2 key exchange protocol.
type SM2KeyExchange struct {
	digest            crypto.Digest
	userID            []byte
	staticKey         *big.Int
	staticPubPoint    *ec.Point
	ephemeralPubPoint *ec.Point
	curve             *ec.Curve
	w                 int
	ephemeralKey      *big.Int
	initiator         bool
}

// NewSM2KeyExchange creates a new SM2 key exchange instance.
func NewSM2KeyExchange(digest crypto.Digest) *SM2KeyExchange {
	if digest == nil {
		digest = digests.NewSM3Digest()
	}
	return &SM2KeyExchange{
		digest: digest,
	}
}

// Init initializes the key exchange with private parameters.
func (ke *SM2KeyExchange) Init(privParam crypto.CipherParameters) error {
	var baseParam *SM2KeyExchangePrivateParameters

	if pwid, ok := privParam.(*crypto.ParametersWithID); ok {
		param := pwid.GetParameters()
		baseParam, ok = param.(*SM2KeyExchangePrivateParameters)
		if !ok {
			return errors.New("expected SM2KeyExchangePrivateParameters")
		}
		ke.userID = pwid.GetID()
	} else if p, ok := privParam.(*SM2KeyExchangePrivateParameters); ok {
		baseParam = p
		ke.userID = []byte{}
	} else {
		return errors.New("invalid parameter type")
	}

	ke.initiator = baseParam.IsInitiator()
	ke.staticKey = baseParam.GetStaticPrivateKey()
	ke.ephemeralKey = baseParam.GetEphemeralPrivateKey()
	ke.curve = baseParam.GetCurve()
	ke.staticPubPoint = baseParam.GetStaticPublicPoint()
	ke.ephemeralPubPoint = baseParam.GetEphemeralPublicPoint()

	// Calculate w = floor((field_size - 1) / 2)
	fieldSize := ke.curve.FieldSize()
	ke.w = (fieldSize - 1) / 2

	return nil
}

// CalculateKey calculates the shared key.
func (ke *SM2KeyExchange) CalculateKey(kLen int, pubParam crypto.CipherParameters) ([]byte, error) {
	if kLen <= 0 {
		return nil, errors.New("key length must be positive")
	}

	var otherPub *SM2KeyExchangePublicParameters
	var otherUserID []byte

	if pwid, ok := pubParam.(*crypto.ParametersWithID); ok {
		param := pwid.GetParameters()
		otherPub, ok = param.(*SM2KeyExchangePublicParameters)
		if !ok {
			return nil, errors.New("expected SM2KeyExchangePublicParameters")
		}
		otherUserID = pwid.GetID()
	} else if p, ok := pubParam.(*SM2KeyExchangePublicParameters); ok {
		otherPub = p
		otherUserID = []byte{}
	} else {
		return nil, errors.New("invalid parameter type")
	}

	za := ke.getZ(ke.userID, ke.staticPubPoint)
	zb := ke.getZ(otherUserID, otherPub.GetStaticPublicKey())

	u, err := ke.calculateU(otherPub)
	if err != nil {
		return nil, err
	}

	var rv []byte
	if ke.initiator {
		rv = ke.kdf(u, za, zb, kLen)
	} else {
		rv = ke.kdf(u, zb, za, kLen)
	}

	return rv, nil
}

// CalculateKeyWithConfirmation calculates key with confirmation tags.
func (ke *SM2KeyExchange) CalculateKeyWithConfirmation(
	kLen int,
	confirmationTag []byte,
	pubParam crypto.CipherParameters,
) ([][]byte, error) {
	if kLen <= 0 {
		return nil, errors.New("key length must be positive")
	}

	var otherPub *SM2KeyExchangePublicParameters
	var otherUserID []byte

	if pwid, ok := pubParam.(*crypto.ParametersWithID); ok {
		param := pwid.GetParameters()
		otherPub, ok = param.(*SM2KeyExchangePublicParameters)
		if !ok {
			return nil, errors.New("expected SM2KeyExchangePublicParameters")
		}
		otherUserID = pwid.GetID()
	} else if p, ok := pubParam.(*SM2KeyExchangePublicParameters); ok {
		otherPub = p
		otherUserID = []byte{}
	} else {
		return nil, errors.New("invalid parameter type")
	}

	if ke.initiator && confirmationTag == nil {
		return nil, errors.New("if initiating, confirmationTag must be set")
	}

	za := ke.getZ(ke.userID, ke.staticPubPoint)
	zb := ke.getZ(otherUserID, otherPub.GetStaticPublicKey())

	u, err := ke.calculateU(otherPub)
	if err != nil {
		return nil, err
	}

	if ke.initiator {
		rv := ke.kdf(u, za, zb, kLen)

		inner := ke.calculateInnerHash(
			u,
			za,
			zb,
			ke.ephemeralPubPoint,
			otherPub.GetEphemeralPublicKey(),
		)

		s1 := ke.s1(u, inner)

		if subtle.ConstantTimeCompare(s1, confirmationTag) != 1 {
			return nil, errors.New("confirmation tag mismatch")
		}

		return [][]byte{rv, ke.s2(u, inner)}, nil
	}

	rv := ke.kdf(u, zb, za, kLen)

	inner := ke.calculateInnerHash(
		u,
		zb,
		za,
		otherPub.GetEphemeralPublicKey(),
		ke.ephemeralPubPoint,
	)

	return [][]byte{rv, ke.s1(u, inner), ke.s2(u, inner)}, nil
}

// calculateU calculates the U point for key derivation.
func (ke *SM2KeyExchange) calculateU(otherPub *SM2KeyExchangePublicParameters) (*ec.Point, error) {
	p1 := otherPub.GetStaticPublicKey()
	p2 := otherPub.GetEphemeralPublicKey()

	x1 := ke.reduce(ke.ephemeralPubPoint.X)
	x2 := ke.reduce(p2.X)

	tA := new(big.Int).Add(ke.staticKey, new(big.Int).Mul(x1, ke.ephemeralKey))
	k1 := new(big.Int).Mul(big.NewInt(int64(ke.curve.H)), tA)
	k1.Mod(k1, ke.curve.N)

	k2 := new(big.Int).Mul(k1, x2)
	k2.Mod(k2, ke.curve.N)

	// U = k1*P1 + k2*P2
	u1 := ke.curve.ScalarMult(p1, k1.Bytes())
	u2 := ke.curve.ScalarMult(p2, k2.Bytes())
	u := ke.curve.Add(u1, u2)

	return u, nil
}

// kdf implements Key Derivation Function.
func (ke *SM2KeyExchange) kdf(u *ec.Point, za, zb []byte, klen int) []byte {
	digestSize := ke.digest.GetDigestSize()
	rv := make([]byte, int(math.Ceil(float64(klen)/8.0)))
	off := 0
	ct := uint32(0)

	for off < len(rv) {
		ke.digest.Reset()
		ke.addFieldElement(u.X)
		ke.addFieldElement(u.Y)
		ke.digest.BlockUpdate(za, 0, len(za))
		ke.digest.BlockUpdate(zb, 0, len(zb))

		ct++
		ctBytes := make([]byte, 4)
		ctBytes[0] = byte(ct >> 24)
		ctBytes[1] = byte(ct >> 16)
		ctBytes[2] = byte(ct >> 8)
		ctBytes[3] = byte(ct)
		ke.digest.BlockUpdate(ctBytes, 0, 4)

		hash := make([]byte, digestSize)
		ke.digest.DoFinal(hash, 0)

		copyLen := digestSize
		if copyLen > len(rv)-off {
			copyLen = len(rv) - off
		}
		copy(rv[off:], hash[:copyLen])
		off += copyLen
	}

	return rv
}

// reduce implements the reduction function: x~ = 2^w + (x AND (2^w - 1))
func (ke *SM2KeyExchange) reduce(x *big.Int) *big.Int {
	mask := new(big.Int).Lsh(big.NewInt(1), uint(ke.w))
	mask.Sub(mask, big.NewInt(1))

	result := new(big.Int).And(x, mask)
	result.Or(result, new(big.Int).Lsh(big.NewInt(1), uint(ke.w)))

	return result
}

// s1 calculates S1 confirmation tag.
func (ke *SM2KeyExchange) s1(u *ec.Point, inner []byte) []byte {
	ke.digest.Reset()
	ke.digest.BlockUpdate([]byte{0x02}, 0, 1)
	ke.addFieldElement(u.Y)
	ke.digest.BlockUpdate(inner, 0, len(inner))
	result := make([]byte, ke.digest.GetDigestSize())
	ke.digest.DoFinal(result, 0)
	return result
}

// s2 calculates S2 confirmation tag.
func (ke *SM2KeyExchange) s2(u *ec.Point, inner []byte) []byte {
	ke.digest.Reset()
	ke.digest.BlockUpdate([]byte{0x03}, 0, 1)
	ke.addFieldElement(u.Y)
	ke.digest.BlockUpdate(inner, 0, len(inner))
	result := make([]byte, ke.digest.GetDigestSize())
	ke.digest.DoFinal(result, 0)
	return result
}

// calculateInnerHash calculates inner hash for confirmation.
func (ke *SM2KeyExchange) calculateInnerHash(u *ec.Point, za, zb []byte, p1, p2 *ec.Point) []byte {
	ke.digest.Reset()
	ke.addFieldElement(u.X)
	ke.digest.BlockUpdate(za, 0, len(za))
	ke.digest.BlockUpdate(zb, 0, len(zb))
	ke.addFieldElement(p1.X)
	ke.addFieldElement(p1.Y)
	ke.addFieldElement(p2.X)
	ke.addFieldElement(p2.Y)
	result := make([]byte, ke.digest.GetDigestSize())
	ke.digest.DoFinal(result, 0)
	return result
}

// getZ calculates Z value (user identification hash).
func (ke *SM2KeyExchange) getZ(userID []byte, pubPoint *ec.Point) []byte {
	ke.digest.Reset()
	ke.addUserID(userID)

	ke.addFieldElement(ke.curve.A)
	ke.addFieldElement(ke.curve.B)
	ke.addFieldElement(ke.curve.G.X)
	ke.addFieldElement(ke.curve.G.Y)
	ke.addFieldElement(pubPoint.X)
	ke.addFieldElement(pubPoint.Y)

	result := make([]byte, ke.digest.GetDigestSize())
	ke.digest.DoFinal(result, 0)
	return result
}

// addUserID adds user ID to crypto.Digest with length prefix.
func (ke *SM2KeyExchange) addUserID(userID []byte) {
	length := len(userID) * 8 // Length in bits
	ke.digest.BlockUpdate([]byte{byte(length >> 8), byte(length & 0xFF)}, 0, 2)
	ke.digest.BlockUpdate(userID, 0, len(userID))
}

// addFieldElement adds field element to crypto.Digest.
func (ke *SM2KeyExchange) addFieldElement(v interface{}) {
	var bytes []byte
	
	switch val := v.(type) {
	case *big.Int:
		bytes = val.Bytes()
	case ec.FieldElement:
		bytes = val.ToBigInt().Bytes()
	default:
		return
	}
	
	// Pad to 32 bytes for SM2
	if len(bytes) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(bytes):], bytes)
		bytes = padded
	}
	ke.digest.BlockUpdate(bytes, 0, len(bytes))
}
