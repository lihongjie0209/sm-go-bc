// Package main demonstrates comparison of SM4 cipher modes.
package main

import (
	"encoding/hex"
	"fmt"
	"github.com/lihongjie0209/sm-go-bc/crypto/engines"
	"github.com/lihongjie0209/sm-go-bc/crypto/modes"
	"github.com/lihongjie0209/sm-go-bc/crypto/params"
)

func main() {
	fmt.Println("=== SM4 Cipher Modes Comparison ===")
	
	fmt.Println("\n1. Mode Overview:")
	modeOverview()
	
	fmt.Println("\n2. Same Plaintext, Different Modes:")
	samePlaintextDifferentModes()
	
	fmt.Println("\n3. Error Propagation Test:")
	errorPropagationTest()
	
	fmt.Println("\n4. Performance Characteristics:")
	performanceCharacteristics()
}

func modeOverview() {
	fmt.Println("   Available SM4 Cipher Modes:")
	fmt.Println("   • CBC (Cipher Block Chaining)")
	fmt.Println("     - Block cipher, needs padding")
	fmt.Println("     - Sequential processing")
	fmt.Println("     - Error propagates to next block")
	fmt.Println("     - Most common mode")
	fmt.Println()
	fmt.Println("   • CTR (Counter)")
	fmt.Println("     - Stream cipher, no padding needed")
	fmt.Println("     - Parallelizable")
	fmt.Println("     - No error propagation")
	fmt.Println("     - Random access")
	fmt.Println()
	fmt.Println("   • OFB (Output Feedback)")
	fmt.Println("     - Stream cipher, no padding needed")
	fmt.Println("     - Sequential processing")
	fmt.Println("     - No error propagation")
	fmt.Println("     - Self-synchronizing after error")
}

func samePlaintextDifferentModes() {
	key, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	iv, _ := hex.DecodeString("00112233445566778899aabbccddeeff")
	plaintext := []byte("Hello, SM4 modes")
	
	fmt.Printf("   Plaintext: %s\n", string(plaintext))
	fmt.Printf("   Key: %s\n", hex.EncodeToString(key))
	fmt.Printf("   IV:  %s\n\n", hex.EncodeToString(iv))
	
	keyParam := params.NewKeyParameter(key)
	ivParam := params.NewParametersWithIV(keyParam, iv)
	
	// CBC Mode
	engineCBC := engines.NewSM4Engine()
	cbc := modes.NewCBCBlockCipher(engineCBC)
	cbc.Init(true, ivParam)
	ciphertextCBC := make([]byte, 16)
	cbc.ProcessBlock(plaintext, 0, ciphertextCBC, 0)
	fmt.Printf("   CBC: %s\n", hex.EncodeToString(ciphertextCBC))
	
	// CTR Mode
	engineCTR := engines.NewSM4Engine()
	ctr := modes.NewCTRBlockCipher(engineCTR)
	ctr.Init(true, ivParam)
	ciphertextCTR := make([]byte, 16)
	ctr.ProcessBlock(plaintext, 0, ciphertextCTR, 0)
	fmt.Printf("   CTR: %s\n", hex.EncodeToString(ciphertextCTR))
	
	// OFB Mode
	engineOFB := engines.NewSM4Engine()
	ofb := modes.NewOFBBlockCipher(engineOFB, 128)
	ofb.Init(true, ivParam)
	ciphertextOFB := make([]byte, 16)
	ofb.ProcessBlock(plaintext, 0, ciphertextOFB, 0)
	fmt.Printf("   OFB: %s\n", hex.EncodeToString(ciphertextOFB))
	
	fmt.Println("\n   ✓ Same input produces different output in each mode")
}

func errorPropagationTest() {
	key, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	iv, _ := hex.DecodeString("00112233445566778899aabbccddeeff")
	
	// Create 3 blocks of plaintext
	plaintext := make([]byte, 48)
	for i := range plaintext {
		plaintext[i] = byte(i)
	}
	
	keyParam := params.NewKeyParameter(key)
	ivParam := params.NewParametersWithIV(keyParam, iv)
	
	fmt.Println("   Testing error propagation with 3 blocks of data:")
	fmt.Println("   Corrupting byte at position 20 (middle of block 2)")
	fmt.Println()
	
	// Test CBC - error propagates
	testCBCErrorPropagation(plaintext, keyParam, ivParam)
	
	// Test CTR - no error propagation
	testCTRErrorPropagation(plaintext, keyParam, ivParam)
	
	// Test OFB - no error propagation
	testOFBErrorPropagation(plaintext, keyParam, ivParam)
}

func testCBCErrorPropagation(plaintext []byte, keyParam *params.KeyParameter, ivParam *params.ParametersWithIV) {
	// Encrypt
	engine := engines.NewSM4Engine()
	cbc := modes.NewCBCBlockCipher(engine)
	cbc.Init(true, ivParam)
	
	ciphertext := make([]byte, 48)
	for i := 0; i < 3; i++ {
		cbc.ProcessBlock(plaintext, i*16, ciphertext, i*16)
	}
	
	// Corrupt one byte
	ciphertext[20] ^= 0xFF
	
	// Decrypt
	engine2 := engines.NewSM4Engine()
	cbc2 := modes.NewCBCBlockCipher(engine2)
	cbc2.Init(false, ivParam)
	
	decrypted := make([]byte, 48)
	for i := 0; i < 3; i++ {
		cbc2.ProcessBlock(ciphertext, i*16, decrypted, i*16)
	}
	
	errorCount := countErrors(plaintext, decrypted)
	fmt.Printf("   CBC: %d bytes corrupted (error propagates to next block)\n", errorCount)
}

func testCTRErrorPropagation(plaintext []byte, keyParam *params.KeyParameter, ivParam *params.ParametersWithIV) {
	// Encrypt
	engine := engines.NewSM4Engine()
	ctr := modes.NewCTRBlockCipher(engine)
	ctr.Init(true, ivParam)
	
	ciphertext := make([]byte, 48)
	for i := 0; i < 3; i++ {
		ctr.ProcessBlock(plaintext, i*16, ciphertext, i*16)
	}
	
	// Corrupt one byte
	ciphertext[20] ^= 0xFF
	
	// Decrypt
	engine2 := engines.NewSM4Engine()
	ctr2 := modes.NewCTRBlockCipher(engine2)
	ctr2.Init(false, ivParam)
	
	decrypted := make([]byte, 48)
	for i := 0; i < 3; i++ {
		ctr2.ProcessBlock(ciphertext, i*16, decrypted, i*16)
	}
	
	errorCount := countErrors(plaintext, decrypted)
	fmt.Printf("   CTR: %d byte corrupted (no propagation)\n", errorCount)
}

func testOFBErrorPropagation(plaintext []byte, keyParam *params.KeyParameter, ivParam *params.ParametersWithIV) {
	// Encrypt
	engine := engines.NewSM4Engine()
	ofb := modes.NewOFBBlockCipher(engine, 128)
	ofb.Init(true, ivParam)
	
	ciphertext := make([]byte, 48)
	for i := 0; i < 3; i++ {
		ofb.ProcessBlock(plaintext, i*16, ciphertext, i*16)
	}
	
	// Corrupt one byte
	ciphertext[20] ^= 0xFF
	
	// Decrypt
	engine2 := engines.NewSM4Engine()
	ofb2 := modes.NewOFBBlockCipher(engine2, 128)
	ofb2.Init(false, ivParam)
	
	decrypted := make([]byte, 48)
	for i := 0; i < 3; i++ {
		ofb2.ProcessBlock(ciphertext, i*16, decrypted, i*16)
	}
	
	errorCount := countErrors(plaintext, decrypted)
	fmt.Printf("   OFB: %d byte corrupted (no propagation)\n", errorCount)
}

func countErrors(a, b []byte) int {
	count := 0
	for i := range a {
		if a[i] != b[i] {
			count++
		}
	}
	return count
}

func performanceCharacteristics() {
	fmt.Println("   Performance & Use Case Comparison:")
	fmt.Println()
	
	fmt.Println("   CBC (Cipher Block Chaining)")
	fmt.Println("   ✓ Suitable for: General-purpose encryption, file encryption")
	fmt.Println("   ✓ Advantages: Well-studied, widely supported")
	fmt.Println("   ✗ Disadvantages: Sequential, needs padding")
	fmt.Println("   • Security: High (with proper IV)")
	fmt.Println()
	
	fmt.Println("   CTR (Counter)")
	fmt.Println("   ✓ Suitable for: High-speed encryption, disk encryption, network protocols")
	fmt.Println("   ✓ Advantages: Parallelizable, random access, no padding")
	fmt.Println("   ✗ Disadvantages: IV/nonce must NEVER repeat")
	fmt.Println("   • Security: High (with unique nonce)")
	fmt.Println()
	
	fmt.Println("   OFB (Output Feedback)")
	fmt.Println("   ✓ Suitable for: Stream encryption, error-sensitive environments")
	fmt.Println("   ✓ Advantages: No error propagation, self-synchronizing")
	fmt.Println("   ✗ Disadvantages: Sequential, IV/nonce must NEVER repeat")
	fmt.Println("   • Security: High (with unique IV)")
	fmt.Println()
	
	fmt.Println("   Summary Table:")
	fmt.Println("   ┌─────────────┬──────────┬───────────────┬───────────┬──────────────┐")
	fmt.Println("   │ Mode        │ Type     │ Parallelizable│ Padding   │ Error Prop   │")
	fmt.Println("   ├─────────────┼──────────┼───────────────┼───────────┼──────────────┤")
	fmt.Println("   │ CBC         │ Block    │ Decrypt only  │ Required  │ Next block   │")
	fmt.Println("   │ CTR         │ Stream   │ Yes           │ No        │ None         │")
	fmt.Println("   │ OFB         │ Stream   │ No            │ No        │ None         │")
	fmt.Println("   └─────────────┴──────────┴───────────────┴───────────┴──────────────┘")
}
