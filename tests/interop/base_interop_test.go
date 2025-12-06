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

// ExecutePython runs a Python script and returns JSON result
func (b *BaseInteropTest) ExecutePython(script string) (map[string]interface{}, error) {
	// Create temp script file
	tempFile := filepath.Join(b.projectRoot, fmt.Sprintf("temp_test_%d.py", os.Getpid()))
	
	if err := os.WriteFile(tempFile, []byte(script), 0644); err != nil {
		return nil, fmt.Errorf("failed to write temp script: %w", err)
	}
	defer os.Remove(tempFile)
	
	// Execute Python
	cmd := exec.Command("python", tempFile)
	cmd.Dir = b.projectRoot
	
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("python execution failed: %w\nOutput: %s", err, string(output))
	}
	
	// Parse JSON output
	var result map[string]interface{}
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w\nOutput: %s", err, string(output))
	}
	
	// Check for Python errors
	if errMsg, ok := result["error"]; ok {
		return nil, fmt.Errorf("Python error: %v", errMsg)
	}
	
	return result, nil
}

// ExecutePHP runs a PHP script and returns JSON result
func (b *BaseInteropTest) ExecutePHP(script string) (map[string]interface{}, error) {
	// Create temp script file
	tempFile := filepath.Join(b.projectRoot, fmt.Sprintf("temp_test_%d.php", os.Getpid()))
	
	if err := os.WriteFile(tempFile, []byte(script), 0644); err != nil {
		return nil, fmt.Errorf("failed to write temp script: %w", err)
	}
	defer os.Remove(tempFile)
	
	// Execute PHP
	cmd := exec.Command("php", tempFile)
	cmd.Dir = b.projectRoot
	
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("php execution failed: %w\nOutput: %s", err, string(output))
	}
	
	// Parse JSON output
	var result map[string]interface{}
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w\nOutput: %s", err, string(output))
	}
	
	// Check for PHP errors
	if errMsg, ok := result["error"]; ok {
		return nil, fmt.Errorf("PHP error: %v", errMsg)
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

// CreatePythonScript creates a Python script that uses sm-py-bc
func (b *BaseInteropTest) CreatePythonScript(code string) string {
	return fmt.Sprintf(`import sys
import json
sys.path.insert(0, 'sm-py-bc/src')

try:
    from sm_bc import *
    %s
except Exception as e:
    print(json.dumps({"error": str(e)}))
    sys.exit(1)
`, code)
}

// CreatePHPScript creates a PHP script that uses sm-php-bc
func (b *BaseInteropTest) CreatePHPScript(code string) string {
	return fmt.Sprintf(`<?php
require_once __DIR__ . '/sm-php-bc/vendor/autoload.php';

use SmBc\Crypto\Digests\SM3Digest;
use SmBc\Crypto\Engines\SM4Engine;
use SmBc\Crypto\Modes\CBCBlockCipher;
use SmBc\Crypto\Paddings\PKCS7Padding;
use SmBc\Crypto\PaddedBufferedBlockCipher;
use SmBc\Crypto\Params\KeyParameter;
use SmBc\Crypto\Params\ParametersWithIV;

try {
    %s
} catch (Exception $e) {
    echo json_encode(["error" => $e->getMessage()]);
    exit(1);
}
`, code)
}

// IsNodeJsAvailable checks if Node.js is available
func (b *BaseInteropTest) IsNodeJsAvailable() bool {
	cmd := exec.Command("node", "--version")
	return cmd.Run() == nil
}

// IsPythonAvailable checks if Python is available
func (b *BaseInteropTest) IsPythonAvailable() bool {
	cmd := exec.Command("python", "--version")
	return cmd.Run() == nil
}

// IsPHPAvailable checks if PHP is available
func (b *BaseInteropTest) IsPHPAvailable() bool {
	cmd := exec.Command("php", "--version")
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
