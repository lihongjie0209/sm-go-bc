package interop

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/lihongjie0209/sm-go-bc/crypto/engines"
	"github.com/lihongjie0209/sm-go-bc/crypto/modes"
	"github.com/lihongjie0209/sm-go-bc/crypto/paddings"
	"github.com/lihongjie0209/sm-go-bc/crypto/params"
)

// TestSM4CBCCrossLanguageJS tests SM4-CBC interoperability with JavaScript
func TestSM4CBCCrossLanguageJS(t *testing.T) {
	base := NewBaseInteropTest(t)
	
	if !base.IsNodeJsAvailable() {
		t.Skip("Node.js is not available")
	}
	
	t.Log("=== Testing SM4-CBC Cross-Language with JavaScript ===")
	
	// Fixed key and IV for reproducibility
	keyHex := "0123456789ABCDEFFEDCBA9876543210"
	ivHex := "FEDCBA98765432100123456789ABCDEF"
	
	testMessages := []string{
		"Hello SM4!",
		"Test message for SM4 cipher",
		"SM4密码算法测试",
	}
	
	for _, msg := range testMessages {
		t.Run(fmt.Sprintf("message_%d_bytes", len(msg)), func(t *testing.T) {
			t.Logf("Testing message: %q", msg)
			
			// Encrypt with Go
			goCiphertext, err := encryptGoSM4CBC(msg, keyHex, ivHex)
			if err != nil {
				t.Fatalf("Go encryption failed: %v", err)
			}
			t.Logf("  Go ciphertext: %s...", goCiphertext[:32])
			
			// Decrypt with JavaScript
			jsDecrypted, err := decryptJavaScriptSM4CBC(base, goCiphertext, keyHex, ivHex)
			if err != nil {
				t.Fatalf("JavaScript decryption failed: %v", err)
			}
			
			if msg != jsDecrypted {
				t.Errorf("JS decryption of Go ciphertext failed!\n  Original: %q\n  Decrypted: %q", msg, jsDecrypted)
			}
			t.Log("  ✓ JS successfully decrypted Go ciphertext")
			
			// Encrypt with JavaScript
			jsCiphertext, err := encryptJavaScriptSM4CBC(base, msg, keyHex, ivHex)
			if err != nil {
				t.Fatalf("JavaScript encryption failed: %v", err)
			}
			t.Logf("  JS ciphertext: %s...", jsCiphertext[:32])
			
			// Decrypt with Go
			goDecrypted, err := decryptGoSM4CBC(jsCiphertext, keyHex, ivHex)
			if err != nil {
				t.Fatalf("Go decryption failed: %v", err)
			}
			
			if msg != goDecrypted {
				t.Errorf("Go decryption of JS ciphertext failed!\n  Original: %q\n  Decrypted: %q", msg, goDecrypted)
			}
			t.Log("  ✓ Go successfully decrypted JS ciphertext")
			t.Log("  ✓ Cross-language test passed")
		})
	}
}

// TestSM4CBCCrossLanguagePython tests SM4-CBC interoperability with Python
func TestSM4CBCCrossLanguagePython(t *testing.T) {
	base := NewBaseInteropTest(t)
	
	if !base.IsPythonAvailable() {
		t.Skip("Python is not available")
	}
	
	t.Log("=== Testing SM4-CBC Cross-Language with Python ===")
	
	keyHex := "0123456789ABCDEFFEDCBA9876543210"
	ivHex := "FEDCBA98765432100123456789ABCDEF"
	
	testMessages := []string{
		"Hello SM4!",
		"Test message",
	}
	
	for _, msg := range testMessages {
		t.Run(fmt.Sprintf("message_%d_bytes", len(msg)), func(t *testing.T) {
			t.Logf("Testing message: %q", msg)
			
			// Encrypt with Go
			goCiphertext, err := encryptGoSM4CBC(msg, keyHex, ivHex)
			if err != nil {
				t.Fatalf("Go encryption failed: %v", err)
			}
			
			// Decrypt with Python
			pyDecrypted, err := decryptPythonSM4CBC(base, goCiphertext, keyHex, ivHex)
			if err != nil {
				t.Fatalf("Python decryption failed: %v", err)
			}
			
			if msg != pyDecrypted {
				t.Errorf("Python decryption failed!\n  Original: %q\n  Decrypted: %q", msg, pyDecrypted)
			}
			t.Log("  ✓ Python successfully decrypted Go ciphertext")
			
			// Encrypt with Python
			pyCiphertext, err := encryptPythonSM4CBC(base, msg, keyHex, ivHex)
			if err != nil {
				t.Fatalf("Python encryption failed: %v", err)
			}
			
			// Decrypt with Go
			goDecrypted, err := decryptGoSM4CBC(pyCiphertext, keyHex, ivHex)
			if err != nil {
				t.Fatalf("Go decryption failed: %v", err)
			}
			
			if msg != goDecrypted {
				t.Errorf("Go decryption failed!\n  Original: %q\n  Decrypted: %q", msg, goDecrypted)
			}
			t.Log("  ✓ Go successfully decrypted Python ciphertext")
			t.Log("  ✓ Cross-language test passed")
		})
	}
}

// encryptGoSM4CBC encrypts with Go SM4-CBC
func encryptGoSM4CBC(plaintext, keyHex, ivHex string) (string, error) {
	key, _ := hex.DecodeString(keyHex)
	iv, _ := hex.DecodeString(ivHex)
	
	engine := engines.NewSM4Engine()
	cipher := modes.NewCBCBlockCipher(engine)
	padding := paddings.NewPKCS7Padding()
	paddedCipher := modes.NewPaddedBufferedBlockCipher(cipher, padding)
	
	keyParam := params.NewKeyParameter(key)
	ivParam := params.NewParametersWithIV(keyParam, iv)
	
	paddedCipher.Init(true, ivParam)
	
	input := []byte(plaintext)
	output := make([]byte, len(input)+16)
	
	length, err := paddedCipher.ProcessBytes(input, 0, len(input), output, 0)
	if err != nil {
		return "", err
	}
	finalLen, err := paddedCipher.DoFinal(output, length)
	if err != nil {
		return "", err
	}
	length += finalLen
	
	return hex.EncodeToString(output[:length]), nil
}

// decryptGoSM4CBC decrypts with Go SM4-CBC
func decryptGoSM4CBC(ciphertextHex, keyHex, ivHex string) (string, error) {
	key, _ := hex.DecodeString(keyHex)
	iv, _ := hex.DecodeString(ivHex)
	ciphertext, _ := hex.DecodeString(ciphertextHex)
	
	engine := engines.NewSM4Engine()
	cipher := modes.NewCBCBlockCipher(engine)
	padding := paddings.NewPKCS7Padding()
	paddedCipher := modes.NewPaddedBufferedBlockCipher(cipher, padding)
	
	keyParam := params.NewKeyParameter(key)
	ivParam := params.NewParametersWithIV(keyParam, iv)
	
	paddedCipher.Init(false, ivParam)
	
	output := make([]byte, len(ciphertext)+16)
	
	length, err := paddedCipher.ProcessBytes(ciphertext, 0, len(ciphertext), output, 0)
	if err != nil {
		return "", err
	}
	finalLen, err := paddedCipher.DoFinal(output, length)
	if err != nil {
		return "", err
	}
	length += finalLen
	
	return string(output[:length]), nil
}

// encryptJavaScriptSM4CBC encrypts with JavaScript SM4-CBC
func encryptJavaScriptSM4CBC(base *BaseInteropTest, plaintext, keyHex, ivHex string) (string, error) {
	escaped := fmt.Sprintf("%q", plaintext)
	escaped = escaped[1 : len(escaped)-1]
	
	script := base.CreateJsScript(fmt.Sprintf(`
const hexToBytes = (hex) => {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return bytes;
};

const bytesToHex = (bytes) => {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
};

const plaintext = new TextEncoder().encode("%s");
const key = hexToBytes("%s");
const iv = hexToBytes("%s");

const cipher = new smBc.PaddedBufferedBlockCipher(
    new smBc.CBCBlockCipher(new smBc.SM4Engine()),
    new smBc.PKCS7Padding()
);

const params = new smBc.ParametersWithIV(new smBc.KeyParameter(key), iv);
cipher.init(true, params);

const output = new Uint8Array(plaintext.length + 16);
let len = cipher.processBytes(plaintext, 0, plaintext.length, output, 0);
len += cipher.doFinal(output, len);

const ciphertext = output.slice(0, len);
console.log(JSON.stringify({ ciphertext: bytesToHex(ciphertext) }));
`, escaped, keyHex, ivHex))
	
	result, err := base.ExecuteNodeJs(script)
	if err != nil {
		return "", err
	}
	
	return result["ciphertext"].(string), nil
}

// decryptJavaScriptSM4CBC decrypts with JavaScript SM4-CBC
func decryptJavaScriptSM4CBC(base *BaseInteropTest, ciphertextHex, keyHex, ivHex string) (string, error) {
	script := base.CreateJsScript(fmt.Sprintf(`
const hexToBytes = (hex) => {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return bytes;
};

const ciphertext = hexToBytes("%s");
const key = hexToBytes("%s");
const iv = hexToBytes("%s");

const cipher = new smBc.PaddedBufferedBlockCipher(
    new smBc.CBCBlockCipher(new smBc.SM4Engine()),
    new smBc.PKCS7Padding()
);

const params = new smBc.ParametersWithIV(new smBc.KeyParameter(key), iv);
cipher.init(false, params);

const output = new Uint8Array(ciphertext.length + 16);
let len = cipher.processBytes(ciphertext, 0, ciphertext.length, output, 0);
len += cipher.doFinal(output, len);

const plaintext = output.slice(0, len);
const message = new TextDecoder().decode(plaintext);
console.log(JSON.stringify({ plaintext: message }));
`, ciphertextHex, keyHex, ivHex))
	
	result, err := base.ExecuteNodeJs(script)
	if err != nil {
		return "", err
	}
	
	return result["plaintext"].(string), nil
}

// encryptPythonSM4CBC encrypts with Python SM4-CBC
func encryptPythonSM4CBC(base *BaseInteropTest, plaintext, keyHex, ivHex string) (string, error) {
	escaped := fmt.Sprintf("%q", plaintext)
	
	script := base.CreatePythonScript(fmt.Sprintf(`
from sm_bc.crypto.engines import SM4Engine
from sm_bc.crypto.modes import CBCBlockCipher
from sm_bc.crypto.paddings import PKCS7Padding
from sm_bc.crypto.padded_buffered_block_cipher import PaddedBufferedBlockCipher
from sm_bc.crypto.params import KeyParameter, ParametersWithIV

plaintext = %s.encode('utf-8')
key = bytes.fromhex("%s")
iv = bytes.fromhex("%s")

cipher = PaddedBufferedBlockCipher(
    CBCBlockCipher(SM4Engine()),
    PKCS7Padding()
)

params = ParametersWithIV(KeyParameter(key), iv)
cipher.init(True, params)

output = bytearray(len(plaintext) + 16)
length = cipher.process_bytes(plaintext, 0, len(plaintext), output, 0)
length += cipher.do_final(output, length)

ciphertext = output[:length].hex()
print(json.dumps({"ciphertext": ciphertext}))
`, escaped, keyHex, ivHex))
	
	result, err := base.ExecutePython(script)
	if err != nil {
		return "", err
	}
	
	return result["ciphertext"].(string), nil
}

// decryptPythonSM4CBC decrypts with Python SM4-CBC
func decryptPythonSM4CBC(base *BaseInteropTest, ciphertextHex, keyHex, ivHex string) (string, error) {
	script := base.CreatePythonScript(fmt.Sprintf(`
from sm_bc.crypto.engines import SM4Engine
from sm_bc.crypto.modes import CBCBlockCipher
from sm_bc.crypto.paddings import PKCS7Padding
from sm_bc.crypto.padded_buffered_block_cipher import PaddedBufferedBlockCipher
from sm_bc.crypto.params import KeyParameter, ParametersWithIV

ciphertext = bytes.fromhex("%s")
key = bytes.fromhex("%s")
iv = bytes.fromhex("%s")

cipher = PaddedBufferedBlockCipher(
    CBCBlockCipher(SM4Engine()),
    PKCS7Padding()
)

params = ParametersWithIV(KeyParameter(key), iv)
cipher.init(False, params)

output = bytearray(len(ciphertext) + 16)
length = cipher.process_bytes(ciphertext, 0, len(ciphertext), output, 0)
length += cipher.do_final(output, length)

plaintext = output[:length].decode('utf-8')
print(json.dumps({"plaintext": plaintext}))
`, ciphertextHex, keyHex, ivHex))
	
	result, err := base.ExecutePython(script)
	if err != nil {
		return "", err
	}
	
	return result["plaintext"].(string), nil
}
