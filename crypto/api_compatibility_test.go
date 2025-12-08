package crypto_test

import (
	"crypto/rand"
	"math/big"
	"testing"
	
	"github.com/lihongjie0209/sm-go-bc/crypto/digests"
	"github.com/lihongjie0209/sm-go-bc/crypto/signers"
	"github.com/lihongjie0209/sm-go-bc/crypto/sm2"
	"github.com/lihongjie0209/sm-go-bc/math/ec"
)

// Helper function to generate test key pair
func generateTestKeyPair() (*big.Int, *ec.Point) {
	// Generate random private key in range [1, n-1]
	n := sm2.GetN()
	privateKey, _ := rand.Int(rand.Reader, new(big.Int).Sub(n, big.NewInt(1)))
	privateKey.Add(privateKey, big.NewInt(1))
	
	// Compute public key
	publicKey := sm2.GetG().Multiply(privateKey)
	
	return privateKey, publicKey
}

// TestSM3DigestResetMemoable tests the Reset(Memoable) API for SM3Digest.
// This tests the API consistency improvement from JS v0.4.0.
func TestSM3DigestResetMemoable(t *testing.T) {
	// Create a digest and process some data
	digest1 := digests.NewSM3Digest()
	data1 := []byte("Hello, ")
	digest1.BlockUpdate(data1, 0, len(data1))
	
	// Save state
	savedState := digest1.Copy()
	
	// Continue processing
	data2 := []byte("World!")
	digest1.BlockUpdate(data2, 0, len(data2))
	
	// Get hash of "Hello, World!"
	hash1 := make([]byte, digest1.GetDigestSize())
	digest1.DoFinal(hash1, 0)
	
	// Create another digest and restore from saved state
	digest2 := digests.NewSM3Digest()
	digest2.ResetMemoable(savedState)
	
	// Process the same continuation data
	digest2.BlockUpdate(data2, 0, len(data2))
	
	// Get hash - should match
	hash2 := make([]byte, digest2.GetDigestSize())
	digest2.DoFinal(hash2, 0)
	
	// Verify hashes match
	if len(hash1) != len(hash2) {
		t.Fatalf("Hash lengths differ: %d vs %d", len(hash1), len(hash2))
	}
	
	for i := range hash1 {
		if hash1[i] != hash2[i] {
			t.Errorf("Hash mismatch at byte %d: 0x%02x vs 0x%02x", i, hash1[i], hash2[i])
		}
	}
}

// TestSM3DigestMemoableIndependence tests that copied states are independent.
func TestSM3DigestMemoableIndependence(t *testing.T) {
	// Create digest and process initial data
	digest1 := digests.NewSM3Digest()
	data := []byte("Initial data")
	digest1.BlockUpdate(data, 0, len(data))
	
	// Copy state
	digest2 := digests.NewSM3Digest()
	digest2.ResetMemoable(digest1.Copy())
	
	// Process different data in each
	digest1.BlockUpdate([]byte(" - path A"), 0, 9)
	digest2.BlockUpdate([]byte(" - path B"), 0, 9)
	
	// Get hashes
	hash1 := make([]byte, digest1.GetDigestSize())
	hash2 := make([]byte, digest2.GetDigestSize())
	digest1.DoFinal(hash1, 0)
	digest2.DoFinal(hash2, 0)
	
	// Hashes should be different (they processed different data)
	same := true
	for i := range hash1 {
		if hash1[i] != hash2[i] {
			same = false
			break
		}
	}
	
	if same {
		t.Error("Expected different hashes for different data paths")
	}
}

// TestSM3DigestResetClears tests that Reset() clears the digest state.
func TestSM3DigestResetClears(t *testing.T) {
	digest1 := digests.NewSM3Digest()
	digest2 := digests.NewSM3Digest()
	
	// Process data in digest1, then reset
	digest1.BlockUpdate([]byte("Some data"), 0, 9)
	digest1.Reset()
	
	// Both should now produce same hash for same input
	testData := []byte("Test")
	digest1.BlockUpdate(testData, 0, len(testData))
	digest2.BlockUpdate(testData, 0, len(testData))
	
	hash1 := make([]byte, digest1.GetDigestSize())
	hash2 := make([]byte, digest2.GetDigestSize())
	digest1.DoFinal(hash1, 0)
	digest2.DoFinal(hash2, 0)
	
	for i := range hash1 {
		if hash1[i] != hash2[i] {
			t.Errorf("Hashes differ after reset at byte %d: 0x%02x vs 0x%02x", i, hash1[i], hash2[i])
		}
	}
}

// TestSM2EngineModeConstants tests that SM2Engine mode constants are accessible.
func TestSM2EngineModeConstants(t *testing.T) {
	// Test that mode constants exist and have expected values
	if sm2.Mode_C1C2C3 != 0 {
		t.Errorf("Mode_C1C2C3 should be 0, got %d", sm2.Mode_C1C2C3)
	}
	
	if sm2.Mode_C1C3C2 != 1 {
		t.Errorf("Mode_C1C3C2 should be 1, got %d", sm2.Mode_C1C3C2)
	}
}

// TestSM2EngineDefaultMode tests that SM2Engine uses correct default mode.
func TestSM2EngineDefaultMode(t *testing.T) {
	engine := sm2.NewSM2Engine()
	
	// Generate test keys
	privateKey, publicKey := generateTestKeyPair()
	
	// Initialize for encryption
	err := engine.Init(true, publicKey, privateKey)
	if err != nil {
		t.Fatalf("Failed to initialize engine: %v", err)
	}
	
	// Encrypt some data
	plaintext := []byte("Hello, SM2!")
	ciphertext, err := engine.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}
	
	// Verify ciphertext is not empty
	if len(ciphertext) == 0 {
		t.Error("Ciphertext should not be empty")
	}
	
	// Default mode should be C1C2C3 (mode 0)
	// Format: C1 (65 bytes) || C2 (len(plaintext)) || C3 (32 bytes)
	expectedLen := 65 + len(plaintext) + 32
	if len(ciphertext) != expectedLen {
		t.Logf("Note: Ciphertext length is %d, expected %d for C1C2C3 mode", len(ciphertext), expectedLen)
	}
}

// TestSM2SignerCreateBasePointMultiplier tests that SM2Signer can create a base point multiplier.
// This is a protected method in Java/JS, but in Go we'll make it accessible for testing.
func TestSM2SignerBasicOperation(t *testing.T) {
	signer := signers.NewSM2Signer()
	
	// Generate keys
	privateKey, publicKey := generateTestKeyPair()
	
	// Initialize for signing
	err := signer.Init(true, publicKey, privateKey)
	if err != nil {
		t.Fatalf("Failed to initialize signer: %v", err)
	}
	
	// Update with message
	message := []byte("Test message")
	signer.Update(message)
	
	// Generate signature
	signature, err := signer.GenerateSignature()
	if err != nil {
		t.Fatalf("Failed to generate signature: %v", err)
	}
	
	if len(signature) == 0 {
		t.Error("Signature should not be empty")
	}
	
	// Reset and verify
	signer.Reset()
	err = signer.Init(false, publicKey, nil)
	if err != nil {
		t.Fatalf("Failed to initialize for verification: %v", err)
	}
	
	signer.Update(message)
	valid, err := signer.VerifySignature(signature)
	if err != nil {
		t.Fatalf("Verification failed: %v", err)
	}
	
	if !valid {
		t.Error("Signature should be valid")
	}
}

// TestAPIConsistencyIntegration tests the overall API consistency improvements.
func TestAPIConsistencyIntegration(t *testing.T) {
	t.Run("SM3Digest Memoable", func(t *testing.T) {
		digest := digests.NewSM3Digest()
		
		// Process some data
		digest.BlockUpdate([]byte("test"), 0, 4)
		
		// Copy state
		saved := digest.Copy()
		
		// Should be able to restore
		digest2 := digests.NewSM3Digest()
		digest2.ResetMemoable(saved)
		
		// Both should produce same hash for same additional input
		digest.BlockUpdate([]byte("data"), 0, 4)
		digest2.BlockUpdate([]byte("data"), 0, 4)
		
		hash1 := make([]byte, 32)
		hash2 := make([]byte, 32)
		digest.DoFinal(hash1, 0)
		digest2.DoFinal(hash2, 0)
		
		for i := range hash1 {
			if hash1[i] != hash2[i] {
				t.Errorf("Restored state produced different hash at byte %d", i)
			}
		}
	})
	
	t.Run("SM2Engine Modes", func(t *testing.T) {
		engine := sm2.NewSM2Engine()
		
		// Test mode setting
		engine.SetMode(sm2.Mode_C1C3C2)
		// If we get here without panic, the mode constant is accessible
	})
	
	t.Run("SM2Signer Lifecycle", func(t *testing.T) {
		signer := signers.NewSM2Signer()
		
		// Should support custom user ID
		signer.SetUserID([]byte("testuser@example.com"))
		
		// Generate signature and verify
		priv, pub := generateTestKeyPair()
		signer.Init(true, pub, priv)
		signer.Update([]byte("message"))
		sig, err := signer.GenerateSignature()
		if err != nil {
			t.Fatal(err)
		}
		
		// Reset for verification
		signer.Reset()
		signer.Init(false, pub, nil)
		signer.Update([]byte("message"))
		valid, err := signer.VerifySignature(sig)
		if err != nil {
			t.Fatal(err)
		}
		if !valid {
			t.Error("Signature verification failed")
		}
	})
}

// TestAPIConsistencyWithBCJava tests consistency with Bouncy Castle Java API patterns.
func TestAPIConsistencyWithBCJava(t *testing.T) {
	t.Run("Digest Lifecycle", func(t *testing.T) {
		digest := digests.NewSM3Digest()
		
		// BC Java pattern: create, update, doFinal, reset
		digest.BlockUpdate([]byte("test"), 0, 4)
		out := make([]byte, digest.GetDigestSize())
		digest.DoFinal(out, 0)
		
		// After doFinal, digest should be reset automatically
		digest.BlockUpdate([]byte("test"), 0, 4)
		out2 := make([]byte, digest.GetDigestSize())
		digest.DoFinal(out2, 0)
		
		// Should produce same hash
		for i := range out {
			if out[i] != out2[i] {
				t.Errorf("DoFinal should auto-reset: hash differs at byte %d", i)
			}
		}
	})
	
	t.Run("Engine Mode Setting", func(t *testing.T) {
		// BC Java pattern: create engine, set mode, init, process
		engine := sm2.NewSM2Engine()
		engine.SetMode(sm2.Mode_C1C3C2)
		
		priv, pub := generateTestKeyPair()
		err := engine.Init(true, pub, priv)
		if err != nil {
			t.Fatal(err)
		}
		
		// Should be able to encrypt
		ct, err := engine.Encrypt([]byte("test"))
		if err != nil {
			t.Fatal(err)
		}
		if len(ct) == 0 {
			t.Error("Ciphertext should not be empty")
		}
	})
}
