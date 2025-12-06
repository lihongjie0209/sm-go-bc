package interop

import (
	"fmt"
	"testing"

	"github.com/lihongjie0209/sm-go-bc/crypto/digests"
)

// TestSM3CrossLanguageJS tests SM3 interoperability with JavaScript implementation
func TestSM3CrossLanguageJS(t *testing.T) {
	base := NewBaseInteropTest(t)
	
	if !base.IsNodeJsAvailable() {
		t.Skip("Node.js is not available")
	}
	
	testVectors := []struct {
		name     string
		message  string
		expected string
	}{
		{
			"empty string",
			"",
			"1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b",
		},
		{
			"single char",
			"a",
			"623476ac18f65a2909e43c7fec61b49c7e764a91a18ccb82f1917a29c86c5e88",
		},
		{
			"abc",
			"abc",
			"66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0",
		},
		{
			"longer message",
			"Test message for SM3 digest",
			"",
		},
	}
	
	t.Log("=== Testing SM3 Cross-Language with JavaScript ===")
	
	for _, tv := range testVectors {
		t.Run(tv.name, func(t *testing.T) {
			t.Logf("Testing message: %q", tv.message)
			
			// Compute with Go
			goHash := computeGoSM3(tv.message)
			t.Logf("  Go hash: %s", goHash)
			
			// Compute with JavaScript
			jsHash, err := computeJavaScriptSM3(base, tv.message)
			if err != nil {
				t.Fatalf("JavaScript SM3 failed: %v", err)
			}
			t.Logf("  JS hash: %s", jsHash)
			
			// Verify they match
			if goHash != jsHash {
				t.Errorf("Go and JavaScript SM3 don't match!\n  Go: %s\n  JS: %s", goHash, jsHash)
			}
			
			// Verify against expected if provided
			if tv.expected != "" && goHash != tv.expected {
				t.Errorf("Hash doesn't match expected!\n  Got:      %s\n  Expected: %s", goHash, tv.expected)
			}
			
			t.Log("  ✓ Both implementations agree")
		})
	}
}

// TestSM3CrossLanguagePython tests SM3 interoperability with Python implementation
func TestSM3CrossLanguagePython(t *testing.T) {
	base := NewBaseInteropTest(t)
	
	if !base.IsPythonAvailable() {
		t.Skip("Python is not available")
	}
	
	testMessages := []string{
		"",
		"a",
		"abc",
		"Hello SM3!",
		"Test message for cross-language verification",
	}
	
	t.Log("=== Testing SM3 Cross-Language with Python ===")
	
	for _, msg := range testMessages {
		t.Run(fmt.Sprintf("message_%d_bytes", len(msg)), func(t *testing.T) {
			t.Logf("Testing message: %q", msg)
			
			// Compute with Go
			goHash := computeGoSM3(msg)
			t.Logf("  Go hash: %s", goHash)
			
			// Compute with Python
			pyHash, err := computePythonSM3(base, msg)
			if err != nil {
				t.Fatalf("Python SM3 failed: %v", err)
			}
			t.Logf("  Python hash: %s", pyHash)
			
			// Verify they match
			if goHash != pyHash {
				t.Errorf("Go and Python SM3 don't match!\n  Go:     %s\n  Python: %s", goHash, pyHash)
			}
			
			t.Log("  ✓ Both implementations agree")
		})
	}
}

// TestSM3CrossLanguagePHP tests SM3 interoperability with PHP implementation
func TestSM3CrossLanguagePHP(t *testing.T) {
	base := NewBaseInteropTest(t)
	
	if !base.IsPHPAvailable() {
		t.Skip("PHP is not available")
	}
	
	testMessages := []string{
		"",
		"a",
		"abc",
		"Hello SM3!",
	}
	
	t.Log("=== Testing SM3 Cross-Language with PHP ===")
	
	for _, msg := range testMessages {
		t.Run(fmt.Sprintf("message_%d_bytes", len(msg)), func(t *testing.T) {
			t.Logf("Testing message: %q", msg)
			
			// Compute with Go
			goHash := computeGoSM3(msg)
			t.Logf("  Go hash: %s", goHash)
			
			// Compute with PHP
			phpHash, err := computePHPSM3(base, msg)
			if err != nil {
				t.Fatalf("PHP SM3 failed: %v", err)
			}
			t.Logf("  PHP hash: %s", phpHash)
			
			// Verify they match
			if goHash != phpHash {
				t.Errorf("Go and PHP SM3 don't match!\n  Go:  %s\n  PHP: %s", goHash, phpHash)
			}
			
			t.Log("  ✓ Both implementations agree")
		})
	}
}

// computeGoSM3 computes SM3 hash using Go implementation
func computeGoSM3(message string) string {
	digest := digests.NewSM3Digest()
	data := []byte(message)
	digest.BlockUpdate(data, 0, len(data))
	
	result := make([]byte, digest.GetDigestSize())
	digest.DoFinal(result, 0)
	
	return fmt.Sprintf("%x", result)
}

// computeJavaScriptSM3 computes SM3 hash using JavaScript implementation
func computeJavaScriptSM3(base *BaseInteropTest, message string) (string, error) {
	// Escape message for JavaScript
	escaped := message
	escaped = fmt.Sprintf("%q", escaped)
	escaped = escaped[1 : len(escaped)-1] // Remove quotes added by %q
	
	script := base.CreateJsScript(fmt.Sprintf(`
const message = new TextEncoder().encode("%s");
const digest = new smBc.SM3Digest();
digest.updateArray(message, 0, message.length);

const result = new Uint8Array(digest.getDigestSize());
digest.doFinal(result, 0);

const hash = Array.from(result)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');

console.log(JSON.stringify({ hash: hash }));
`, escaped))
	
	result, err := base.ExecuteNodeJs(script)
	if err != nil {
		return "", err
	}
	
	return result["hash"].(string), nil
}

// computePythonSM3 computes SM3 hash using Python implementation
func computePythonSM3(base *BaseInteropTest, message string) (string, error) {
	// Escape message for Python
	escaped := fmt.Sprintf("%q", message)
	
	script := base.CreatePythonScript(fmt.Sprintf(`
message = %s.encode('utf-8')
digest = SM3Digest()
digest.update_bytes(message, 0, len(message))

result = bytearray(digest.get_digest_size())
digest.do_final(result, 0)

hash_str = result.hex()
print(json.dumps({"hash": hash_str}))
`, escaped))
	
	result, err := base.ExecutePython(script)
	if err != nil {
		return "", err
	}
	
	return result["hash"].(string), nil
}

// computePHPSM3 computes SM3 hash using PHP implementation
func computePHPSM3(base *BaseInteropTest, message string) (string, error) {
	// Escape message for PHP
	escaped := fmt.Sprintf("%q", message)
	
	script := base.CreatePHPScript(fmt.Sprintf(`
$message = %s;
$digest = new SM3Digest();
$digest->updateBytes($message, 0, strlen($message));

$result = str_repeat("\\0", $digest->getDigestSize());
$digest->doFinal($result, 0);

$hash = bin2hex($result);
echo json_encode(["hash" => $hash]);
`, escaped))
	
	result, err := base.ExecutePHP(script)
	if err != nil {
		return "", err
	}
	
	return result["hash"].(string), nil
}
