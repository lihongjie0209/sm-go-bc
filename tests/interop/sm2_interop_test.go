package interop

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"
	
	"github.com/lihongjie0209/sm-go-bc/crypto/signers"
	"github.com/lihongjie0209/sm-go-bc/crypto/sm2"
)

// TestSM2SignVerifyInterop tests SM2 signature interoperability with JavaScript
func TestSM2SignVerifyInterop(t *testing.T) {
	base := NewBaseInteropTest(t)
	
	if !base.IsNodeJsAvailable() {
		t.Skip("Node.js not available")
	}
	
	// Test data
	message := "Hello, SM2 Signature!"
	messageBytes := []byte(message)
	privateKeyHex := "3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8"
	publicKeyXHex := "09f9df311e5421a150dd7d161e4bc5c672179fad1833fc076bb08ff356f35020"
	publicKeyYHex := "ccea490ce26775a52dc6ea718cc1aa600aed05fbf35e084a6632f6072da9ad13"

	privateKey := new(big.Int)
	privateKey.SetString(privateKeyHex, 16)
	publicKeyX := new(big.Int)
	publicKeyX.SetString(publicKeyXHex, 16)
	publicKeyY := new(big.Int)
	publicKeyY.SetString(publicKeyYHex, 16)

	// Test 1: JS signs, Go verifies
	t.Run("JSSign_GoVerify", func(t *testing.T) {
		jsCode := fmt.Sprintf(`
const message = "%s";
const privateKey = 0x%sn;

const signature = smBc.SM2.sign(message, privateKey);
const signatureHex = Buffer.from(signature).toString('hex');

console.log(JSON.stringify({ signature: signatureHex }));
`, message, privateKeyHex)

		result, err := base.ExecuteNodeJs(base.CreateJsScript(jsCode))
		if err != nil {
			t.Fatalf("Failed to execute JS: %v", err)
		}

		signatureHex := result["signature"].(string)
		signatureBytes, err := hex.DecodeString(signatureHex)
		if err != nil {
			t.Fatalf("Failed to decode signature hex: %v", err)
		}

		t.Logf("JS Signature: %s", signatureHex)

		// Verify signature in Go
		curve := sm2.GetCurve()
		publicKey := curve.CreatePoint(publicKeyX, publicKeyY)
		
		signer := signers.NewSM2Signer()
		err = signer.Init(false, publicKey, nil)
		if err != nil {
			t.Fatalf("Failed to initialize signer: %v", err)
		}
		
		signer.Update(messageBytes)
		verified, err := signer.VerifySignature(signatureBytes)
		if err != nil {
			t.Fatalf("Failed to verify signature: %v", err)
		}
		
		if !verified {
			t.Errorf("Go failed to verify JS signature")
		}
	})

	// Test 2: Go signs, JS verifies
	t.Run("GoSign_JSVerify", func(t *testing.T) {
		// Sign in Go
		signer := signers.NewSM2Signer()
		err := signer.Init(true, nil, privateKey)
		if err != nil {
			t.Fatalf("Failed to initialize signer: %v", err)
		}
		
		signer.Update(messageBytes)
		goSignature, err := signer.GenerateSignature()
		if err != nil {
			t.Fatalf("Failed to generate signature: %v", err)
		}
		goSignatureHex := hex.EncodeToString(goSignature)

		t.Logf("Go Signature: %s", goSignatureHex)

		// Verify in JS
		jsCode := fmt.Sprintf(`
const message = "%s";
const signature = Buffer.from("%s", "hex");
const publicKeyX = 0x%sn;
const publicKeyY = 0x%sn;

const verified = smBc.SM2.verify(message, signature, { x: publicKeyX, y: publicKeyY });

console.log(JSON.stringify({ verified: verified }));
`, message, goSignatureHex, publicKeyXHex, publicKeyYHex)

		result, err := base.ExecuteNodeJs(base.CreateJsScript(jsCode))
		if err != nil {
			t.Fatalf("Failed to execute JS verify: %v", err)
		}

		jsVerified := result["verified"].(bool)
		if !jsVerified {
			t.Errorf("JS failed to verify Go signature")
		}
	})
}

// TestSM2EncryptDecryptInterop tests SM2 encryption interoperability with JavaScript
func TestSM2EncryptDecryptInterop(t *testing.T) {
	base := NewBaseInteropTest(t)
	
	if !base.IsNodeJsAvailable() {
		t.Skip("Node.js not available")
	}
	
	// Test data
	message := "Hello, SM2 Encryption!"
	messageBytes := []byte(message)
	privateKeyHex := "3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8"
	publicKeyXHex := "09f9df311e5421a150dd7d161e4bc5c672179fad1833fc076bb08ff356f35020"
	publicKeyYHex := "ccea490ce26775a52dc6ea718cc1aa600aed05fbf35e084a6632f6072da9ad13"

	privateKey := new(big.Int)
	privateKey.SetString(privateKeyHex, 16)
	publicKeyX := new(big.Int)
	publicKeyX.SetString(publicKeyXHex, 16)
	publicKeyY := new(big.Int)
	publicKeyY.SetString(publicKeyYHex, 16)

	// Test 1: Go encrypts, JS decrypts
	t.Run("GoEncrypt_JSDecrypt", func(t *testing.T) {
		// Encrypt in Go
		curve := sm2.GetCurve()
		publicKey := curve.CreatePoint(publicKeyX, publicKeyY)
		
		engine := sm2.NewSM2Engine()
		err := engine.Init(true, publicKey, nil)
		if err != nil {
			t.Fatalf("Failed to initialize engine: %v", err)
		}
		
		ciphertext, err := engine.Encrypt(messageBytes)
		if err != nil {
			t.Fatalf("Failed to encrypt: %v", err)
		}
		ciphertextHex := hex.EncodeToString(ciphertext)

		t.Logf("Go Ciphertext length: %d bytes", len(ciphertext))
		t.Logf("Go Ciphertext (first 64 bytes): %s...", ciphertextHex[:min(128, len(ciphertextHex))])

		// Decrypt in JS
		jsCode := fmt.Sprintf(`
const ciphertext = Buffer.from("%s", "hex");
const privateKey = 0x%sn;

const decrypted = smBc.SM2.decrypt(ciphertext, privateKey);
const message = typeof decrypted === 'string' ? decrypted : new TextDecoder().decode(decrypted);

console.log(JSON.stringify({ decrypted: message }));
`, ciphertextHex, privateKeyHex)

		result, err := base.ExecuteNodeJs(base.CreateJsScript(jsCode))
		if err != nil {
			t.Fatalf("Failed to execute JS decrypt: %v", err)
		}

		decrypted := result["decrypted"].(string)
		if decrypted != message {
			t.Errorf("JS decryption failed: got %q, want %q", decrypted, message)
		}
	})

	// Test 2: JS encrypts, Go decrypts
	t.Run("JSEncrypt_GoDecrypt", func(t *testing.T) {
		// Encrypt in JS
		jsCode := fmt.Sprintf(`
const message = "%s";
const publicKeyX = 0x%sn;
const publicKeyY = 0x%sn;

const ciphertext = smBc.SM2.encrypt(message, publicKeyX, publicKeyY);
const ciphertextHex = Buffer.from(ciphertext).toString('hex');

console.log(JSON.stringify({ ciphertext: ciphertextHex }));
`, message, publicKeyXHex, publicKeyYHex)

		result, err := base.ExecuteNodeJs(base.CreateJsScript(jsCode))
		if err != nil {
			t.Fatalf("Failed to execute JS encrypt: %v", err)
		}

		ciphertextHex := result["ciphertext"].(string)
		ciphertext, err := hex.DecodeString(ciphertextHex)
		if err != nil {
			t.Fatalf("Failed to decode ciphertext hex: %v", err)
		}

		t.Logf("JS Ciphertext length: %d bytes", len(ciphertext))
		t.Logf("JS Ciphertext (first 64 bytes): %s...", ciphertextHex[:min(128, len(ciphertextHex))])

		// Decrypt in Go
		engine := sm2.NewSM2Engine()
		err = engine.Init(false, nil, privateKey)
		if err != nil {
			t.Fatalf("Failed to initialize engine: %v", err)
		}
		
		decrypted, err := engine.Decrypt(ciphertext)
		if err != nil {
			t.Fatalf("Failed to decrypt: %v", err)
		}
		
		if string(decrypted) != message {
			t.Errorf("Go decryption failed: got %q, want %q", string(decrypted), message)
		}
	})
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// TestSM2C1C3C2ModeInterop tests SM2 C1C3C2 mode interoperability
func TestSM2C1C3C2ModeInterop(t *testing.T) {
	base := NewBaseInteropTest(t)
	
	if !base.IsNodeJsAvailable() {
		t.Skip("Node.js not available")
	}
	
	message := "Test C1C3C2 mode"
	messageBytes := []byte(message)
	privateKeyHex := "3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8"
	publicKeyXHex := "09f9df311e5421a150dd7d161e4bc5c672179fad1833fc076bb08ff356f35020"
	publicKeyYHex := "ccea490ce26775a52dc6ea718cc1aa600aed05fbf35e084a6632f6072da9ad13"

	privateKey := new(big.Int)
	privateKey.SetString(privateKeyHex, 16)
	publicKeyX := new(big.Int)
	publicKeyX.SetString(publicKeyXHex, 16)
	publicKeyY := new(big.Int)
	publicKeyY.SetString(publicKeyYHex, 16)

	// Test Go encrypt C1C3C2, JS decrypt C1C3C2
	t.Run("C1C3C2_Mode", func(t *testing.T) {
		// Encrypt in Go with C1C3C2 mode (default)
		curve := sm2.GetCurve()
		publicKey := curve.CreatePoint(publicKeyX, publicKeyY)
		
		engine := sm2.NewSM2Engine()
		engine.SetMode(sm2.Mode_C1C3C2)
		err := engine.Init(true, publicKey, nil)
		if err != nil {
			t.Fatalf("Failed to initialize engine: %v", err)
		}
		
		ciphertext, err := engine.Encrypt(messageBytes)
		if err != nil {
			t.Fatalf("Failed to encrypt: %v", err)
		}
		ciphertextHex := hex.EncodeToString(ciphertext)

		t.Logf("Go C1C3C2 Ciphertext (first 64 bytes): %s...", ciphertextHex[:min(128, len(ciphertextHex))])

		// Decrypt in JS with C1C3C2 mode
		jsCode := fmt.Sprintf(`
const ciphertext = Buffer.from("%s", "hex");
const privateKey = 0x%sn;

// Use low-level API for C1C3C2 mode
const domainParams = smBc.SM2.getParameters();
const privateKeyParam = new smBc.ECPrivateKeyParameters(privateKey, domainParams);

const engine = new smBc.SM2Engine('C1C3C2');
engine.init(false, privateKeyParam);

const decrypted = engine.processBlock(ciphertext, 0, ciphertext.length);
const message = new TextDecoder().decode(decrypted);

console.log(JSON.stringify({ decrypted: message }));
`, ciphertextHex, privateKeyHex)

		result, err := base.ExecuteNodeJs(base.CreateJsScript(jsCode))
		if err != nil {
			t.Fatalf("Failed to execute JS decrypt C1C3C2: %v", err)
		}

		decrypted := result["decrypted"].(string)
		if decrypted != message {
			t.Errorf("JS C1C3C2 decryption failed: got %q, want %q", decrypted, message)
		}
	})
}
