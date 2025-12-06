package signers

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/lihongjie0209/sm-go-bc/crypto/sm2"
)

func TestSM2SignerBasic(t *testing.T) {
	// Generate a key pair
	privKey := fromHex("128B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C23661D15897263")
	pubKey := sm2.GetG().Multiply(privKey)

	// Message to sign
	message := []byte("message digest")

	// Create signer for signing
	signer := NewSM2Signer()
	err := signer.Init(true, nil, privKey)
	if err != nil {
		t.Fatalf("Init for signing failed: %v", err)
	}

	// Sign the message
	signer.Update(message)
	signature, err := signer.GenerateSignature()
	if err != nil {
		t.Fatalf("GenerateSignature failed: %v", err)
	}

	if len(signature) != 64 {
		t.Errorf("Expected signature length 64, got %d", len(signature))
	}

	// Verify the signature
	verifier := NewSM2Signer()
	err = verifier.Init(false, pubKey, nil)
	if err != nil {
		t.Fatalf("Init for verification failed: %v", err)
	}

	verifier.Update(message)
	valid, err := verifier.VerifySignature(signature)
	if err != nil {
		t.Fatalf("VerifySignature failed: %v", err)
	}

	if !valid {
		t.Error("Signature verification failed")
	}
}

func TestSM2SignerWrongMessage(t *testing.T) {
	privKey := fromHex("128B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C23661D15897263")
	pubKey := sm2.GetG().Multiply(privKey)

	// Sign message 1
	signer := NewSM2Signer()
	_ = signer.Init(true, nil, privKey)
	signer.Update([]byte("message 1"))
	signature, _ := signer.GenerateSignature()

	// Verify with message 2
	verifier := NewSM2Signer()
	_ = verifier.Init(false, pubKey, nil)
	verifier.Update([]byte("message 2"))
	valid, _ := verifier.VerifySignature(signature)

	if valid {
		t.Error("Signature should not verify with wrong message")
	}
}

func TestSM2SignerWrongKey(t *testing.T) {
	privKey1 := fromHex("128B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C23661D15897263")
	privKey2 := fromHex("228B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C23661D15897263")
	pubKey2 := sm2.GetG().Multiply(privKey2)

	message := []byte("test message")

	// Sign with privKey1
	signer := NewSM2Signer()
	_ = signer.Init(true, nil, privKey1)
	signer.Update(message)
	signature, _ := signer.GenerateSignature()

	// Verify with pubKey2
	verifier := NewSM2Signer()
	_ = verifier.Init(false, pubKey2, nil)
	verifier.Update(message)
	valid, _ := verifier.VerifySignature(signature)

	if valid {
		t.Error("Signature should not verify with wrong public key")
	}
}

func TestSM2SignerEmptyMessage(t *testing.T) {
	privKey := fromHex("128B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C23661D15897263")
	pubKey := sm2.GetG().Multiply(privKey)

	// Sign empty message
	signer := NewSM2Signer()
	_ = signer.Init(true, nil, privKey)
	signer.Update([]byte{})
	signature, err := signer.GenerateSignature()
	if err != nil {
		t.Fatalf("GenerateSignature failed: %v", err)
	}

	// Verify empty message
	verifier := NewSM2Signer()
	_ = verifier.Init(false, pubKey, nil)
	verifier.Update([]byte{})
	valid, _ := verifier.VerifySignature(signature)

	if !valid {
		t.Error("Signature should verify for empty message")
	}
}

func TestSM2SignerLongMessage(t *testing.T) {
	privKey := fromHex("128B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C23661D15897263")
	pubKey := sm2.GetG().Multiply(privKey)

	// Create a long message (1KB)
	message := make([]byte, 1024)
	for i := range message {
		message[i] = byte(i % 256)
	}

	// Sign long message
	signer := NewSM2Signer()
	_ = signer.Init(true, nil, privKey)
	signer.Update(message)
	signature, err := signer.GenerateSignature()
	if err != nil {
		t.Fatalf("GenerateSignature failed: %v", err)
	}

	// Verify long message
	verifier := NewSM2Signer()
	_ = verifier.Init(false, pubKey, nil)
	verifier.Update(message)
	valid, _ := verifier.VerifySignature(signature)

	if !valid {
		t.Error("Signature should verify for long message")
	}
}

func TestSM2SignerMultipleUpdates(t *testing.T) {
	privKey := fromHex("128B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C23661D15897263")
	pubKey := sm2.GetG().Multiply(privKey)

	// Sign with multiple updates
	signer := NewSM2Signer()
	_ = signer.Init(true, nil, privKey)
	signer.Update([]byte("hello "))
	signer.Update([]byte("world"))
	signature, _ := signer.GenerateSignature()

	// Verify with single update
	verifier := NewSM2Signer()
	_ = verifier.Init(false, pubKey, nil)
	verifier.Update([]byte("hello world"))
	valid, _ := verifier.VerifySignature(signature)

	if !valid {
		t.Error("Signature should verify with concatenated message")
	}
}

func TestSM2SignerReset(t *testing.T) {
	privKey := fromHex("128B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C23661D15897263")
	pubKey := sm2.GetG().Multiply(privKey)

	message1 := []byte("first message")
	message2 := []byte("second message")

	// Sign message1, reset, then sign message2
	signer := NewSM2Signer()
	_ = signer.Init(true, nil, privKey)

	signer.Update(message1)
	signer.Reset() // Reset should clear the digest

	signer.Update(message2)
	signature, _ := signer.GenerateSignature()

	// Verify with message2
	verifier := NewSM2Signer()
	_ = verifier.Init(false, pubKey, nil)
	verifier.Update(message2)
	valid, _ := verifier.VerifySignature(signature)

	if !valid {
		t.Error("Signature should verify after reset")
	}

	// Should NOT verify with message1
	verifier.Reset()
	verifier.Update(message1)
	valid, _ = verifier.VerifySignature(signature)

	if valid {
		t.Error("Signature should not verify with wrong message after reset")
	}
}

func TestSM2SignerCustomUserID(t *testing.T) {
	privKey := fromHex("128B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C23661D15897263")
	pubKey := sm2.GetG().Multiply(privKey)

	message := []byte("test message")
	customUserID := []byte("alice@example.com")

	// Sign with custom user ID
	signer := NewSM2Signer()
	signer.SetUserID(customUserID)
	_ = signer.Init(true, nil, privKey)
	signer.Update(message)
	signature, _ := signer.GenerateSignature()

	// Verify with same custom user ID
	verifier := NewSM2Signer()
	verifier.SetUserID(customUserID)
	_ = verifier.Init(false, pubKey, nil)
	verifier.Update(message)
	valid, _ := verifier.VerifySignature(signature)

	if !valid {
		t.Error("Signature should verify with matching user ID")
	}

	// Should NOT verify with default user ID
	verifier2 := NewSM2Signer()
	_ = verifier2.Init(false, pubKey, nil)
	verifier2.Update(message)
	valid, _ = verifier2.VerifySignature(signature)

	if valid {
		t.Error("Signature should not verify with different user ID")
	}
}

func TestSM2SignerInvalidPrivateKey(t *testing.T) {
	// Zero private key
	signer := NewSM2Signer()
	err := signer.Init(true, nil, big.NewInt(0))
	if err == nil {
		t.Error("Should fail with zero private key")
	}

	// Private key >= n
	n := sm2.GetN()
	signer2 := NewSM2Signer()
	err = signer2.Init(true, nil, n)
	if err == nil {
		t.Error("Should fail with private key >= n")
	}
}

func TestSM2SignerInvalidPublicKey(t *testing.T) {
	// Point at infinity
	infinity := sm2.GetCurve().GetInfinity()
	verifier := NewSM2Signer()
	err := verifier.Init(false, infinity, nil)
	if err == nil {
		t.Error("Should fail with point at infinity")
	}
}

func TestSM2SignerInvalidSignature(t *testing.T) {
	privKey := fromHex("128B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C23661D15897263")
	pubKey := sm2.GetG().Multiply(privKey)

	message := []byte("test message")

	// Create invalid signature (wrong length)
	invalidSig := make([]byte, 32)

	verifier := NewSM2Signer()
	_ = verifier.Init(false, pubKey, nil)
	verifier.Update(message)
	_, err := verifier.VerifySignature(invalidSig)

	if err == nil {
		t.Error("Should fail with invalid signature length")
	}
}

func fromHex(s string) *big.Int {
	b, _ := hex.DecodeString(s)
	return new(big.Int).SetBytes(b)
}
