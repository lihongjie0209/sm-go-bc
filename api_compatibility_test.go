package smgobc

import (
	"testing"

	"github.com/lihongjie0209/sm-go-bc/crypto/digests"
	"github.com/lihongjie0209/sm-go-bc/crypto/engines"
	"github.com/lihongjie0209/sm-go-bc/crypto/modes"
	"github.com/lihongjie0209/sm-go-bc/crypto/paddings"
	"github.com/lihongjie0209/sm-go-bc/crypto/params"
	"github.com/lihongjie0209/sm-go-bc/crypto/signers"
	"github.com/lihongjie0209/sm-go-bc/crypto/sm2"
	"github.com/lihongjie0209/sm-go-bc/math/ec"
)

// TestSM3DigestAPI tests SM3Digest API compatibility with JS version
func TestSM3DigestAPI(t *testing.T) {
	t.Run("Constructor", func(t *testing.T) {
		digest := digests.NewSM3Digest()
		if digest == nil {
			t.Fatal("NewSM3Digest() returned nil")
		}
	})

	t.Run("Reset Method", func(t *testing.T) {
		digest := digests.NewSM3Digest()
		data := []byte("test")
		digest.Update(data, 0, len(data))
		digest.Reset()
		
		// After reset, should produce hash of empty string
		output := make([]byte, 32)
		digest.DoFinal(output, 0)
		
		// Verify it matches empty string hash
		emptyDigest := digests.NewSM3Digest()
		expected := make([]byte, 32)
		emptyDigest.DoFinal(expected, 0)
		
		if string(output) != string(expected) {
			t.Errorf("Reset did not clear digest state")
		}
	})

	t.Run("Update Method Signature", func(t *testing.T) {
		digest := digests.NewSM3Digest()
		data := []byte{0x01, 0x02, 0x03}
		
		// Should accept []byte, int offset, int length
		digest.Update(data, 0, len(data))
		digest.Update(data, 1, 2)
		digest.Update(data, 0, 0) // Empty update
	})

	t.Run("DoFinal Method Signature", func(t *testing.T) {
		digest := digests.NewSM3Digest()
		output := make([]byte, 32)
		
		// Should accept []byte, int offset
		n, err := digest.DoFinal(output, 0)
		if err != nil {
			t.Fatalf("DoFinal failed: %v", err)
		}
		if n != 32 {
			t.Errorf("DoFinal returned %d bytes, expected 32", n)
		}
	})

	t.Run("GetAlgorithmName", func(t *testing.T) {
		digest := digests.NewSM3Digest()
		name := digest.GetAlgorithmName()
		if name != "SM3" {
			t.Errorf("GetAlgorithmName() = %q, want %q", name, "SM3")
		}
	})

	t.Run("GetDigestSize", func(t *testing.T) {
		digest := digests.NewSM3Digest()
		size := digest.GetDigestSize()
		if size != 32 {
			t.Errorf("GetDigestSize() = %d, want 32", size)
		}
	})
}

// TestSM4EngineAPI tests SM4Engine API compatibility
func TestSM4EngineAPI(t *testing.T) {
	t.Run("Constructor", func(t *testing.T) {
		engine := engines.NewSM4Engine()
		if engine == nil {
			t.Fatal("NewSM4Engine() returned nil")
		}
	})

	t.Run("Init Method", func(t *testing.T) {
		engine := engines.NewSM4Engine()
		key := make([]byte, 16)
		
		// Should accept boolean (encrypt) and []byte key
		engine.Init(true, key)
		engine.Init(false, key)
	})

	t.Run("ProcessBlock Method Signature", func(t *testing.T) {
		engine := engines.NewSM4Engine()
		key := make([]byte, 16)
		engine.Init(true, key)
		
		input := make([]byte, 16)
		output := make([]byte, 16)
		
		// Should accept []byte input, int inOff, []byte output, int outOff
		err := engine.ProcessBlock(input, 0, output, 0)
		if err != nil {
			t.Fatalf("ProcessBlock failed: %v", err)
		}
	})

	t.Run("GetAlgorithmName", func(t *testing.T) {
		engine := engines.NewSM4Engine()
		name := engine.GetAlgorithmName()
		if name != "SM4" {
			t.Errorf("GetAlgorithmName() = %q, want %q", name, "SM4")
		}
	})

	t.Run("GetBlockSize", func(t *testing.T) {
		engine := engines.NewSM4Engine()
		size := engine.GetBlockSize()
		if size != 16 {
			t.Errorf("GetBlockSize() = %d, want 16", size)
		}
	})

	t.Run("Reset Method", func(t *testing.T) {
		engine := engines.NewSM4Engine()
		key := make([]byte, 16)
		engine.Init(true, key)
		engine.Reset()
		// After reset, should still be able to init
		engine.Init(false, key)
	})
}

// TestSM2SignerAPI tests SM2Signer API compatibility
func TestSM2SignerAPI(t *testing.T) {
	curve := ec.SM2P256V1()
	privateKey, publicKey := ec.GenerateKeyPair(curve, nil)

	t.Run("Constructor", func(t *testing.T) {
		signer := signers.NewSM2Signer()
		if signer == nil {
			t.Fatal("NewSM2Signer() returned nil")
		}
	})

	t.Run("Init Method for Signing", func(t *testing.T) {
		signer := signers.NewSM2Signer()
		// Should accept forSigning bool, Q point, d big.Int
		signer.Init(true, publicKey, privateKey)
	})

	t.Run("Init Method for Verification", func(t *testing.T) {
		signer := signers.NewSM2Signer()
		// Should accept forSigning bool, Q point, d big.Int (nil for verification)
		signer.Init(false, publicKey, nil)
	})

	t.Run("Update Method", func(t *testing.T) {
		signer := signers.NewSM2Signer()
		signer.Init(true, publicKey, privateKey)
		
		message := []byte("test message")
		// Should accept []byte
		signer.Update(message)
	})

	t.Run("GenerateSignature", func(t *testing.T) {
		signer := signers.NewSM2Signer()
		signer.Init(true, publicKey, privateKey)
		
		message := []byte("test message")
		signer.Update(message)
		
		// Should return []byte signature
		signature, err := signer.GenerateSignature()
		if err != nil {
			t.Fatalf("GenerateSignature failed: %v", err)
		}
		if len(signature) == 0 {
			t.Error("GenerateSignature returned empty signature")
		}
	})

	t.Run("VerifySignature", func(t *testing.T) {
		// Create signature first
		signer := signers.NewSM2Signer()
		signer.Init(true, publicKey, privateKey)
		message := []byte("test message")
		signer.Update(message)
		signature, _ := signer.GenerateSignature()

		// Verify
		verifier := signers.NewSM2Signer()
		verifier.Init(false, publicKey, nil)
		verifier.Update(message)
		
		// Should accept []byte signature and return bool
		valid := verifier.VerifySignature(signature)
		if !valid {
			t.Error("VerifySignature failed for valid signature")
		}
	})

	t.Run("Reset Method", func(t *testing.T) {
		signer := signers.NewSM2Signer()
		signer.Init(true, publicKey, privateKey)
		signer.Update([]byte("some data"))
		signer.Reset()
		
		// After reset, should be able to sign different message
		signer.Update([]byte("new message"))
		_, err := signer.GenerateSignature()
		if err != nil {
			t.Errorf("Failed to sign after reset: %v", err)
		}
	})
}

// TestSM2EngineAPI tests SM2Engine API compatibility  
func TestSM2EngineAPI(t *testing.T) {
	curve := ec.SM2P256V1()
	_, publicKey := ec.GenerateKeyPair(curve, nil)

	t.Run("Constructor", func(t *testing.T) {
		engine := sm2.NewSM2Engine()
		if engine == nil {
			t.Fatal("NewSM2Engine() returned nil")
		}
	})

	t.Run("Mode Constants", func(t *testing.T) {
		// Should have mode constants
		c1c2c3 := sm2.C1C2C3
		c1c3c2 := sm2.C1C3C2
		
		if c1c2c3 == c1c3c2 {
			t.Error("Mode constants should be different")
		}
	})

	t.Run("Init Method for Encryption", func(t *testing.T) {
		engine := sm2.NewSM2Engine()
		// Should accept forEncryption bool, point, and mode
		err := engine.Init(true, publicKey, sm2.C1C2C3)
		if err != nil {
			t.Fatalf("Init for encryption failed: %v", err)
		}
	})

	t.Run("ProcessBlock Method", func(t *testing.T) {
		engine := sm2.NewSM2Engine()
		engine.Init(true, publicKey, sm2.C1C2C3)
		
		plaintext := []byte("test")
		// Should accept []byte input, int offset, int length
		ciphertext, err := engine.ProcessBlock(plaintext, 0, len(plaintext))
		if err != nil {
			t.Fatalf("ProcessBlock failed: %v", err)
		}
		if len(ciphertext) == 0 {
			t.Error("ProcessBlock returned empty ciphertext")
		}
	})
}

// TestBlockCipherModeAPI tests block cipher mode API compatibility
func TestBlockCipherModeAPI(t *testing.T) {
	engine := engines.NewSM4Engine()
	key := make([]byte, 16)
	iv := make([]byte, 16)

	t.Run("CBC Mode", func(t *testing.T) {
		// Constructor
		mode := modes.NewCBCBlockCipher(engine)
		if mode == nil {
			t.Fatal("NewCBCBlockCipher returned nil")
		}

		// Init with IV
		params := params.NewParametersWithIV(key, iv)
		err := mode.Init(true, params)
		if err != nil {
			t.Fatalf("CBC Init failed: %v", err)
		}

		// ProcessBlock
		input := make([]byte, 16)
		output := make([]byte, 16)
		err = mode.ProcessBlock(input, 0, output, 0)
		if err != nil {
			t.Fatalf("CBC ProcessBlock failed: %v", err)
		}
	})

	t.Run("CFB Mode", func(t *testing.T) {
		mode := modes.NewCFBBlockCipher(engine, 128)
		if mode == nil {
			t.Fatal("NewCFBBlockCipher returned nil")
		}

		params := params.NewParametersWithIV(key, iv)
		err := mode.Init(true, params)
		if err != nil {
			t.Fatalf("CFB Init failed: %v", err)
		}
	})

	t.Run("CTR Mode", func(t *testing.T) {
		mode := modes.NewCTRBlockCipher(engine)
		if mode == nil {
			t.Fatal("NewCTRBlockCipher returned nil")
		}

		params := params.NewParametersWithIV(key, iv)
		err := mode.Init(true, params)
		if err != nil {
			t.Fatalf("CTR Init failed: %v", err)
		}
	})

	t.Run("OFB Mode", func(t *testing.T) {
		mode := modes.NewOFBBlockCipher(engine, 128)
		if mode == nil {
			t.Fatal("NewOFBBlockCipher returned nil")
		}

		params := params.NewParametersWithIV(key, iv)
		err := mode.Init(true, params)
		if err != nil {
			t.Fatalf("OFB Init failed: %v", err)
		}
	})

	t.Run("ECB Mode", func(t *testing.T) {
		mode := modes.NewECBBlockCipher(engine)
		if mode == nil {
			t.Fatal("NewECBBlockCipher returned nil")
		}

		err := mode.Init(true, key)
		if err != nil {
			t.Fatalf("ECB Init failed: %v", err)
		}
	})

	t.Run("GCM Mode", func(t *testing.T) {
		mode := modes.NewGCMBlockCipher(engine)
		if mode == nil {
			t.Fatal("NewGCMBlockCipher returned nil")
		}

		aeadParams := params.NewAEADParameters(key, 128, iv, nil)
		err := mode.Init(true, aeadParams)
		if err != nil {
			t.Fatalf("GCM Init failed: %v", err)
		}
	})
}

// TestPaddingAPI tests padding API compatibility
func TestPaddingAPI(t *testing.T) {
	t.Run("PKCS7Padding", func(t *testing.T) {
		padding := paddings.NewPKCS7Padding()
		if padding == nil {
			t.Fatal("NewPKCS7Padding returned nil")
		}

		// AddPadding
		block := make([]byte, 16)
		padded := padding.AddPadding(block, 10)
		if len(padded) != 16 {
			t.Errorf("AddPadding returned wrong length: %d", len(padded))
		}

		// PadCount
		count := padding.PadCount(padded)
		if count != 6 {
			t.Errorf("PadCount = %d, want 6", count)
		}
	})

	t.Run("ZeroBytePadding", func(t *testing.T) {
		padding := paddings.NewZeroBytePadding()
		if padding == nil {
			t.Fatal("NewZeroBytePadding returned nil")
		}

		block := make([]byte, 16)
		padded := padding.AddPadding(block, 10)
		if len(padded) != 16 {
			t.Errorf("AddPadding returned wrong length: %d", len(padded))
		}
	})

	t.Run("ISO7816d4Padding", func(t *testing.T) {
		padding := paddings.NewISO7816d4Padding()
		if padding == nil {
			t.Fatal("NewISO7816d4Padding returned nil")
		}

		block := make([]byte, 16)
		padded := padding.AddPadding(block, 10)
		if len(padded) != 16 {
			t.Errorf("AddPadding returned wrong length: %d", len(padded))
		}
	})

	t.Run("ISO10126Padding", func(t *testing.T) {
		padding := paddings.NewISO10126Padding()
		if padding == nil {
			t.Fatal("NewISO10126Padding returned nil")
		}

		block := make([]byte, 16)
		padded := padding.AddPadding(block, 10)
		if len(padded) != 16 {
			t.Errorf("AddPadding returned wrong length: %d", len(padded))
		}
	})
}

// TestParameterAPI tests parameter classes API compatibility
func TestParameterAPI(t *testing.T) {
	key := make([]byte, 16)
	iv := make([]byte, 16)

	t.Run("ParametersWithIV", func(t *testing.T) {
		params := params.NewParametersWithIV(key, iv)
		if params == nil {
			t.Fatal("NewParametersWithIV returned nil")
		}

		// Should have GetIV method
		returnedIV := params.GetIV()
		if string(returnedIV) != string(iv) {
			t.Error("GetIV returned wrong IV")
		}

		// Should have GetParameters method
		returnedKey := params.GetParameters()
		if string(returnedKey) != string(key) {
			t.Error("GetParameters returned wrong key")
		}
	})

	t.Run("ParametersWithRandom", func(t *testing.T) {
		params := params.NewParametersWithRandom(key, nil)
		if params == nil {
			t.Fatal("NewParametersWithRandom returned nil")
		}

		// Should have GetParameters method
		returnedKey := params.GetParameters()
		if string(returnedKey) != string(key) {
			t.Error("GetParameters returned wrong key")
		}

		// Should have GetRandom method
		random := params.GetRandom()
		if random == nil {
			t.Error("GetRandom returned nil (should use default)")
		}
	})

	t.Run("AEADParameters", func(t *testing.T) {
		nonce := make([]byte, 12)
		ad := []byte("additional data")
		
		params := params.NewAEADParameters(key, 128, nonce, ad)
		if params == nil {
			t.Fatal("NewAEADParameters returned nil")
		}

		// Should have getter methods
		if params.GetMacSize() != 16 {
			t.Errorf("GetMacSize() = %d, want 16", params.GetMacSize())
		}

		returnedKey := params.GetKey()
		if string(returnedKey) != string(key) {
			t.Error("GetKey returned wrong key")
		}

		returnedNonce := params.GetNonce()
		if string(returnedNonce) != string(nonce) {
			t.Error("GetNonce returned wrong nonce")
		}

		returnedAD := params.GetAssociatedText()
		if string(returnedAD) != string(ad) {
			t.Error("GetAssociatedText returned wrong AD")
		}
	})
}

// TestErrorHandling tests error handling consistency
func TestErrorHandling(t *testing.T) {
	t.Run("SM3 Invalid Input", func(t *testing.T) {
		digest := digests.NewSM3Digest()
		output := make([]byte, 10) // Too small
		
		_, err := digest.DoFinal(output, 0)
		if err == nil {
			t.Error("Expected error for too small output buffer")
		}
	})

	t.Run("SM4 Invalid Key", func(t *testing.T) {
		engine := engines.NewSM4Engine()
		invalidKey := make([]byte, 10) // Wrong size
		
		engine.Init(true, invalidKey)
		
		input := make([]byte, 16)
		output := make([]byte, 16)
		err := engine.ProcessBlock(input, 0, output, 0)
		if err == nil {
			t.Error("Expected error for invalid key size")
		}
	})

	t.Run("Block Cipher Invalid Block Size", func(t *testing.T) {
		engine := engines.NewSM4Engine()
		key := make([]byte, 16)
		engine.Init(true, key)
		
		invalidInput := make([]byte, 10) // Wrong size
		output := make([]byte, 16)
		err := engine.ProcessBlock(invalidInput, 0, output, 0)
		if err == nil {
			t.Error("Expected error for invalid input block size")
		}
	})
}

// TestTypeCompatibility tests that Go types match expected JS types
func TestTypeCompatibility(t *testing.T) {
	t.Run("Byte Arrays", func(t *testing.T) {
		// Go []byte should be compatible with JS Uint8Array
		var data []byte = []byte{0x01, 0x02, 0x03}
		if data == nil {
			t.Error("Byte array creation failed")
		}
	})

	t.Run("Error Returns", func(t *testing.T) {
		// Methods should return (result, error) or just error
		engine := engines.NewSM4Engine()
		key := make([]byte, 16)
		engine.Init(true, key)
		
		input := make([]byte, 16)
		output := make([]byte, 16)
		err := engine.ProcessBlock(input, 0, output, 0)
		
		// err should be of type error
		var _ error = err
	})

	t.Run("Boolean Parameters", func(t *testing.T) {
		// Init methods should accept bool for forEncryption/forSigning
		engine := engines.NewSM4Engine()
		key := make([]byte, 16)
		
		engine.Init(true, key)   // encrypt
		engine.Init(false, key)  // decrypt
	})
}
