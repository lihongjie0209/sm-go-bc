package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"

	"github.com/lihongjie0209/sm-go-bc/crypto"
	"github.com/lihongjie0209/sm-go-bc/crypto/sm2"
	"github.com/lihongjie0209/sm-go-bc/math/ec"
)

func main() {
	fmt.Println("=== SM2 Key Exchange Example ===\n")

	// Get SM2 curve
	curve := sm2.GetCurve()

	// Party A (Alice - Initiator)
	fmt.Println("1. Alice generates her static and ephemeral key pairs")
	staticPrivA := generateRandomKey(curve)
	ephemeralPrivA := generateRandomKey(curve)

	privParamA, err := crypto.NewSM2KeyExchangePrivateParameters(true, staticPrivA, ephemeralPrivA, curve)
	if err != nil {
		log.Fatalf("Failed to create private parameters for Alice: %v", err)
	}

	// Party B (Bob - Responder)
	fmt.Println("2. Bob generates his static and ephemeral key pairs")
	staticPrivB := generateRandomKey(curve)
	ephemeralPrivB := generateRandomKey(curve)

	privParamB, err := crypto.NewSM2KeyExchangePrivateParameters(false, staticPrivB, ephemeralPrivB, curve)
	if err != nil {
		log.Fatalf("Failed to create private parameters for Bob: %v", err)
	}

	// Exchange public keys
	fmt.Println("\n3. Alice and Bob exchange their public keys")
	pubParamA, _ := crypto.NewSM2KeyExchangePublicParameters(
		privParamA.GetStaticPublicPoint(),
		privParamA.GetEphemeralPublicPoint())

	pubParamB, _ := crypto.NewSM2KeyExchangePublicParameters(
		privParamB.GetStaticPublicPoint(),
		privParamB.GetEphemeralPublicPoint())

	// Basic key exchange without confirmation
	fmt.Println("\n4. Performing basic key exchange (without confirmation)")
	keA := crypto.NewSM2KeyExchange(nil)
	keA.Init(privParamA)

	keB := crypto.NewSM2KeyExchange(nil)
	keB.Init(privParamB)

	keyA, err := keA.CalculateKey(128, pubParamB)
	if err != nil {
		log.Fatalf("Alice failed to calculate key: %v", err)
	}

	keyB, err := keB.CalculateKey(128, pubParamA)
	if err != nil {
		log.Fatalf("Bob failed to calculate key: %v", err)
	}

	fmt.Printf("   Alice's shared key: %s\n", hex.EncodeToString(keyA))
	fmt.Printf("   Bob's shared key:   %s\n", hex.EncodeToString(keyB))
	fmt.Printf("   Keys match: %v\n", hex.EncodeToString(keyA) == hex.EncodeToString(keyB))

	// Key exchange with confirmation
	fmt.Println("\n5. Performing key exchange with confirmation")

	// Reset key exchange objects
	keA = crypto.NewSM2KeyExchange(nil)
	keA.Init(privParamA)

	keB = crypto.NewSM2KeyExchange(nil)
	keB.Init(privParamB)

	// Bob (responder) calculates key and confirmation tags
	resultB, err := keB.CalculateKeyWithConfirmation(128, nil, pubParamA)
	if err != nil {
		log.Fatalf("Bob failed to calculate key with confirmation: %v", err)
	}
	keyB = resultB[0]
	s1 := resultB[1]  // Bob's confirmation tag for Alice
	s2 := resultB[2]  // Bob's confirmation tag (Alice will verify this)

	fmt.Printf("   Bob's shared key: %s\n", hex.EncodeToString(keyB))
	fmt.Printf("   Bob's S1 (for Alice): %s\n", hex.EncodeToString(s1))
	fmt.Printf("   Bob's S2: %s\n", hex.EncodeToString(s2))

	// Alice (initiator) verifies Bob's confirmation and generates her own
	resultA, err := keA.CalculateKeyWithConfirmation(128, s1, pubParamB)
	if err != nil {
		log.Fatalf("Alice failed to verify and calculate key: %v", err)
	}
	keyA = resultA[0]
	s2A := resultA[1]  // Alice's S2 for Bob to verify

	fmt.Printf("   Alice's shared key: %s\n", hex.EncodeToString(keyA))
	fmt.Printf("   Alice's S2: %s\n", hex.EncodeToString(s2A))

	fmt.Printf("\n   Keys match: %v\n", hex.EncodeToString(keyA) == hex.EncodeToString(keyB))
	fmt.Printf("   S2 tags match: %v\n", hex.EncodeToString(s2) == hex.EncodeToString(s2A))

	// Key exchange with user IDs
	fmt.Println("\n6. Performing key exchange with user IDs")

	privParamAWithID := crypto.NewParametersWithID(privParamA, []byte("alice@example.com"))
	privParamBWithID := crypto.NewParametersWithID(privParamB, []byte("bob@example.com"))

	pubParamAWithID := crypto.NewParametersWithID(pubParamA, []byte("alice@example.com"))
	pubParamBWithID := crypto.NewParametersWithID(pubParamB, []byte("bob@example.com"))

	keA = crypto.NewSM2KeyExchange(nil)
	keA.Init(privParamAWithID)

	keB = crypto.NewSM2KeyExchange(nil)
	keB.Init(privParamBWithID)

	keyA, _ = keA.CalculateKey(256, pubParamBWithID)
	keyB, _ = keB.CalculateKey(256, pubParamAWithID)

	fmt.Printf("   Alice's shared key (256-bit): %s\n", hex.EncodeToString(keyA))
	fmt.Printf("   Bob's shared key (256-bit):   %s\n", hex.EncodeToString(keyB))
	fmt.Printf("   Keys match: %v\n", hex.EncodeToString(keyA) == hex.EncodeToString(keyB))

	fmt.Println("\n✓ SM2 Key Exchange demonstration complete!")
}

// generateRandomKey generates a random private key
func generateRandomKey(curve *ec.Curve) *big.Int {
	// Generate random bytes
	max := curve.N
	for {
		b := make([]byte, 32)
		rand.Read(b)
		d := new(big.Int).SetBytes(b)
		if d.Cmp(big.NewInt(0)) > 0 && d.Cmp(max) < 0 {
			return d
		}
	}
}
