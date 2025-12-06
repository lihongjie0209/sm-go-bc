// Package sm2 implements SM2 elliptic curve cryptography.
// Reference: GM/T 0003-2012
package sm2

import (
"math/big"
"github.com/lihongjie0209/sm-go-bc/math/ec"
)

// SM2 curve parameters (SM2P256V1)
var (
// Prime p
SM2_P = fromHex("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF")

// Curve coefficient a
SM2_A = fromHex("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC")

// Curve coefficient b
SM2_B = fromHex("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93")

// Base point order n
SM2_N = fromHex("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123")

// Cofactor h
SM2_H = 1

// Base point G coordinates
SM2_Gx = fromHex("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7")
SM2_Gy = fromHex("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0")
)

var sm2Curve *ec.Curve
var sm2BasePoint *ec.Point

// GetCurve returns the SM2 curve.
func GetCurve() *ec.Curve {
if sm2Curve == nil {
sm2Curve = ec.NewCurve(SM2_P, SM2_A, SM2_B, SM2_N, SM2_H)
sm2BasePoint = sm2Curve.CreatePoint(SM2_Gx, SM2_Gy)
sm2Curve.SetG(sm2BasePoint)
}
return sm2Curve
}

// GetG returns the base point G.
func GetG() *ec.Point {
if sm2BasePoint == nil {
GetCurve() // Initialize if not already done
}
return sm2BasePoint
}

// GetN returns the order n.
func GetN() *big.Int {
return new(big.Int).Set(SM2_N)
}

// GetP returns the prime p.
func GetP() *big.Int {
return new(big.Int).Set(SM2_P)
}

// ValidatePublicKey validates a public key point.
func ValidatePublicKey(Q *ec.Point) bool {
if Q.IsInfinity() {
return false
}

if !Q.IsValid() {
return false
}

// Check [n]Q = O
nQ := Q.Multiply(SM2_N)
return nQ.IsInfinity()
}

// ValidatePrivateKey validates a private key.
func ValidatePrivateKey(d *big.Int) bool {
return d.Sign() > 0 && d.Cmp(SM2_N) < 0
}

// fromHex converts a hex string to big.Int.
func fromHex(s string) *big.Int {
n, _ := new(big.Int).SetString(s, 16)
return n
}

// KeyPair represents an SM2 key pair.
type KeyPair struct {
PrivateKey *big.Int
PublicKey  *ec.Point
}

// DomainParameters holds SM2 domain parameters.
type DomainParameters struct {
Curve *ec.Curve
G     *ec.Point
N     *big.Int
H     int
}

// GetDomainParameters returns SM2 domain parameters.
func GetDomainParameters() *DomainParameters {
return &DomainParameters{
Curve: GetCurve(),
G:     GetG(),
N:     GetN(),
H:     SM2_H,
}
}
