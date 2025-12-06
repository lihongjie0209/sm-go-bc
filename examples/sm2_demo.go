package main

import (
	"fmt"
	"math/big"
	"github.com/lihongjie0209/sm-go-bc/crypto/sm2"
)

func main() {
	fmt.Println("=== SM2 Elliptic Curve Demo ===\n")
	
	// Get SM2 domain parameters
	fmt.Println("1. SM2 Domain Parameters:")
	params := sm2.GetDomainParameters()
	fmt.Printf("   Curve: y² = x³ + ax + b (mod p)\n")
	fmt.Printf("   Field size: %d bits\n", params.Curve.GetFieldSize())
	fmt.Printf("   Cofactor: %d\n\n", params.H)
	
	// Get base point
	fmt.Println("2. Base Point G:")
	g := sm2.GetG()
	gEncoded := g.GetEncoded(false)
	fmt.Printf("   Uncompressed (65 bytes): %x...\n", gEncoded[:16])
	gEncodedComp := g.GetEncoded(true)
	fmt.Printf("   Compressed (33 bytes): %x...\n\n", gEncodedComp[:16])
	
	// Point operations
	fmt.Println("3. Point Operations:")
	
	// 2*G
	g2 := g.Twice()
	fmt.Printf("   2*G: %s...\n", g2.String()[:40])
	
	// 3*G = 2*G + G
	g3 := g2.Add(g)
	fmt.Printf("   3*G: %s...\n\n", g3.String()[:40])
	
	// Scalar multiplication
	fmt.Println("4. Scalar Multiplication:")
	k := big.NewInt(12345)
	kG := g.Multiply(k)
	fmt.Printf("   k = %s\n", k.String())
	fmt.Printf("   k*G = %s...\n\n", kG.String()[:40])
	
	// Key generation example
	fmt.Println("5. Key Pair Example:")
	privateKey := big.NewInt(123456789)
	publicKey := g.Multiply(privateKey)
	
	fmt.Printf("   Private key (d): %s\n", privateKey.String())
	fmt.Printf("   Public key (Q): %s...\n", publicKey.String()[:40])
	
	// Validate keys
	if sm2.ValidatePrivateKey(privateKey) {
		fmt.Println("   ✓ Private key is valid")
	}
	if sm2.ValidatePublicKey(publicKey) {
		fmt.Println("   ✓ Public key is valid")
	}
	
	// Point encoding/decoding
	fmt.Println("\n6. Point Encoding/Decoding:")
	encoded := publicKey.GetEncoded(false)
	fmt.Printf("   Encoded: %x... (%d bytes)\n", encoded[:16], len(encoded))
	
	decoded := params.Curve.DecodePoint(encoded)
	if decoded.Equals(publicKey) {
		fmt.Println("   ✓ Decoding successful")
	}
	
	// Verify base point order
	fmt.Println("\n7. Verify Base Point Order:")
	n := sm2.GetN()
	fmt.Printf("   Order n: %s...\n", n.Text(16)[:40])
	nG := g.Multiply(n)
	if nG.IsInfinity() {
		fmt.Println("   ✓ n*G = O (point at infinity)")
	}
	
	fmt.Println("\n✅ SM2 elliptic curve operations complete!")
}
