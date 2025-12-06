package main

import (
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/lihongjie0209/sm-go-bc/crypto/signers"
	"github.com/lihongjie0209/sm-go-bc/crypto/sm2"
)

func main() {
	fmt.Println("=== SM2 Digital Signature Demo ===\n")

	// Generate a key pair (in practice, use secure key generation)
	privateKey := fromHex("128B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C23661D15897263")
	publicKey := sm2.GetG().Multiply(privateKey)

	fmt.Println("Private Key:", hex.EncodeToString(privateKey.Bytes()))
	fmt.Printf("Public Key: (%s, %s)\n\n",
		hex.EncodeToString(publicKey.GetXCoord().ToBigInt().Bytes()),
		hex.EncodeToString(publicKey.GetYCoord().ToBigInt().Bytes()))

	// Message to sign
	message := []byte("Hello, SM2 Digital Signature!")
	fmt.Println("Message:", string(message), "\n")

	// === Signing ===
	fmt.Println("--- Signing ---")
	signer := signers.NewSM2Signer()

	// Optional: Set custom user ID
	signer.SetUserID([]byte("alice@example.com"))

	// Initialize for signing
	err := signer.Init(true, nil, privateKey)
	if err != nil {
		fmt.Println("Init error:", err)
		return
	}

	// Update with message data
	signer.Update(message)

	// Generate signature
	signature, err := signer.GenerateSignature()
	if err != nil {
		fmt.Println("Sign error:", err)
		return
	}

	fmt.Println("Signature (hex):", hex.EncodeToString(signature))
	fmt.Printf("Signature length: %d bytes\n\n", len(signature))

	// === Verification ===
	fmt.Println("--- Verification ---")
	verifier := signers.NewSM2Signer()

	// Must use same user ID as signing
	verifier.SetUserID([]byte("alice@example.com"))

	// Initialize for verification
	err = verifier.Init(false, publicKey, nil)
	if err != nil {
		fmt.Println("Init error:", err)
		return
	}

	// Update with message data
	verifier.Update(message)

	// Verify signature
	valid, err := verifier.VerifySignature(signature)
	if err != nil {
		fmt.Println("Verify error:", err)
		return
	}

	if valid {
		fmt.Println("✓ Signature is VALID")
	} else {
		fmt.Println("✗ Signature is INVALID")
	}

	// === Test with wrong message ===
	fmt.Println("\n--- Verification with Wrong Message ---")
	verifier2 := signers.NewSM2Signer()
	verifier2.SetUserID([]byte("alice@example.com"))
	verifier2.Init(false, publicKey, nil)
	verifier2.Update([]byte("Wrong message"))
	valid2, _ := verifier2.VerifySignature(signature)

	if !valid2 {
		fmt.Println("✓ Correctly rejected invalid signature")
	} else {
		fmt.Println("✗ Incorrectly accepted invalid signature")
	}

	// === Multiple signatures ===
	fmt.Println("\n--- Multiple Signatures (different random k) ---")
	signer.Reset()
	signer.Update(message)
	signature2, _ := signer.GenerateSignature()
	fmt.Println("Signature 1:", hex.EncodeToString(signature)[:32]+"...")
	fmt.Println("Signature 2:", hex.EncodeToString(signature2)[:32]+"...")
	fmt.Println("Note: Signatures are different due to random k, but both valid")

	// Verify second signature
	verifier.Reset()
	verifier.Update(message)
	valid3, _ := verifier.VerifySignature(signature2)
	if valid3 {
		fmt.Println("✓ Second signature also VALID")
	}
}

func fromHex(s string) *big.Int {
	b, _ := hex.DecodeString(s)
	return new(big.Int).SetBytes(b)
}
