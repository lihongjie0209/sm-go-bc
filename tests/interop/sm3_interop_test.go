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


