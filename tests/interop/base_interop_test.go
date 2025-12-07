package interop

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// BaseInteropTest provides common functionality for cross-language tests
type BaseInteropTest struct {
	projectRoot string
	t           *testing.T
}

// NewBaseInteropTest creates a new base test helper
func NewBaseInteropTest(t *testing.T) *BaseInteropTest {
	// Get project root (3 levels up from tests/interop)
	wd, _ := os.Getwd()
	projectRoot := filepath.Join(wd, "..", "..", "..")
	
	return &BaseInteropTest{
		projectRoot: projectRoot,
		t:           t,
	}
}

// ExecuteNodeJs runs a JavaScript script via Node.js and returns JSON result
func (b *BaseInteropTest) ExecuteNodeJs(script string) (map[string]interface{}, error) {
	// Create temp script file in sm-go-bc directory (where node_modules is)
	goRoot := filepath.Join(b.projectRoot, "sm-go-bc")
	tempFile := filepath.Join(goRoot, fmt.Sprintf("temp_test_%d.js", os.Getpid()))
	
	if err := os.WriteFile(tempFile, []byte(script), 0644); err != nil {
		return nil, fmt.Errorf("failed to write temp script: %w", err)
	}
	defer os.Remove(tempFile)
	
	// Execute Node.js
	cmd := exec.Command("node", filepath.Base(tempFile))
	cmd.Dir = goRoot
	
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("node.js execution failed: %w\nOutput: %s", err, string(output))
	}
	
	// Parse JSON output
	var result map[string]interface{}
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w\nOutput: %s", err, string(output))
	}
	
	// Check for JavaScript errors
	if errMsg, ok := result["error"]; ok {
		return nil, fmt.Errorf("JavaScript error: %v", errMsg)
	}
	
	return result, nil
}





// CreateJsScript creates a JavaScript module that uses sm-js-bc
func (b *BaseInteropTest) CreateJsScript(code string) string {
	return fmt.Sprintf(`const smBc = require('sm-js-bc');

try {
    %s
} catch (error) {
    console.log(JSON.stringify({ error: error.message, stack: error.stack }));
    process.exit(1);
}
`, code)
}





// IsNodeJsAvailable checks if Node.js is available
func (b *BaseInteropTest) IsNodeJsAvailable() bool {
	cmd := exec.Command("node", "--version")
	return cmd.Run() == nil
}



// BytesToHex converts bytes to hex string
func (b *BaseInteropTest) BytesToHex(data []byte) string {
	return hex.EncodeToString(data)
}

// HexToBytes converts hex string to bytes
func (b *BaseInteropTest) HexToBytes(hexStr string) ([]byte, error) {
	return hex.DecodeString(strings.TrimSpace(hexStr))
}
