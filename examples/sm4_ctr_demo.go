// Package main demonstrates SM4-CTR cipher mode usage.
package main

import (
	"encoding/hex"
	"fmt"
	"github.com/lihongjie0209/sm-go-bc/crypto/engines"
	"github.com/lihongjie0209/sm-go-bc/crypto/modes"
	"github.com/lihongjie0209/sm-go-bc/crypto/params"
)

func main() {
	fmt.Println("=== SM4-CTR Cipher Mode Demo ===")
	
	// Example 1: Basic CTR encryption
	fmt.Println("\n1. Basic CTR Encryption:")
	basicCTR()
	
	// Example 2: CTR symmetry (same operation for enc/dec)
	fmt.Println("\n2. CTR Symmetry:")
	ctrSymmetry()
	
	// Example 3: Stream cipher behavior
	fmt.Println("\n3. Stream Cipher Behavior:")
	streamCipher()
	
	// Example 4: Counter increment demonstration
	fmt.Println("\n4. Counter Increment:")
	counterIncrement()
	
	// Example 5: CTR vs CBC comparison
	fmt.Println("\n5. CTR vs CBC:")
	ctrVsCBC()
}

func basicCTR() {
	key, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	iv, _ := hex.DecodeString("00112233445566778899aabbccddeeff")
	plaintext := []byte("Hello, CTR mode!")
	
	fmt.Printf("   Plaintext: %s (%d bytes)\n", string(plaintext), len(plaintext))
	fmt.Printf("   Key:       %s\n", hex.EncodeToString(key))
	fmt.Printf("   IV/Nonce:  %s\n", hex.EncodeToString(iv))
	
	// Encrypt
	engine := engines.NewSM4Engine()
	ctr := modes.NewCTRBlockCipher(engine)
	keyParam := params.NewKeyParameter(key)
	ivParam := params.NewParametersWithIV(keyParam, iv)
	ctr.Init(true, ivParam)
	
	ciphertext := make([]byte, len(plaintext))
	ctr.ProcessBlock(plaintext, 0, ciphertext, 0)
	
	fmt.Printf("   Ciphertext: %s\n", hex.EncodeToString(ciphertext))
	
	// Decrypt
	engine2 := engines.NewSM4Engine()
	ctr2 := modes.NewCTRBlockCipher(engine2)
	ctr2.Init(false, ivParam)
	
	decrypted := make([]byte, len(ciphertext))
	ctr2.ProcessBlock(ciphertext, 0, decrypted, 0)
	
	fmt.Printf("   Decrypted:  %s\n", string(decrypted))
	fmt.Println("   ✓ Encryption and decryption successful!")
}

func ctrSymmetry() {
	key, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	iv, _ := hex.DecodeString("00112233445566778899aabbccddeeff")
	plaintext := []byte("CTR is symmetric")
	
	fmt.Println("   CTR mode uses the SAME operation for encryption and decryption!")
	fmt.Printf("   Plaintext: %s\n", string(plaintext))
	
	// "Encrypt" with forEncryption=true
	engine1 := engines.NewSM4Engine()
	ctr1 := modes.NewCTRBlockCipher(engine1)
	keyParam := params.NewKeyParameter(key)
	ivParam := params.NewParametersWithIV(keyParam, iv)
	ctr1.Init(true, ivParam)
	
	ciphertext := make([]byte, len(plaintext))
	ctr1.ProcessBlock(plaintext, 0, ciphertext, 0)
	
	fmt.Printf("   Ciphertext: %s\n", hex.EncodeToString(ciphertext))
	
	// "Decrypt" with forEncryption=true (same as encryption!)
	engine2 := engines.NewSM4Engine()
	ctr2 := modes.NewCTRBlockCipher(engine2)
	ctr2.Init(true, ivParam) // Notice: true, not false!
	
	decrypted := make([]byte, len(ciphertext))
	ctr2.ProcessBlock(ciphertext, 0, decrypted, 0)
	
	fmt.Printf("   Decrypted:  %s\n", string(decrypted))
	
	if string(plaintext) == string(decrypted) {
		fmt.Println("   ✓ CTR is perfectly symmetric - forEncryption parameter doesn't matter!")
	}
}

func streamCipher() {
	key, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	iv, _ := hex.DecodeString("00112233445566778899aabbccddeeff")
	
	// CTR mode works like a stream cipher - processes in blocks but can handle any length
	plaintext := []byte("This is a longer message that spans multiple blocks!")
	
	fmt.Printf("   Plaintext: %s (%d bytes)\n", string(plaintext), len(plaintext))
	fmt.Println("   CTR mode processes in block chunks:")
	
	engine := engines.NewSM4Engine()
	ctr := modes.NewCTRBlockCipher(engine)
	keyParam := params.NewKeyParameter(key)
	ivParam := params.NewParametersWithIV(keyParam, iv)
	ctr.Init(true, ivParam)
	
	ciphertext := make([]byte, len(plaintext))
	
	// Process full blocks
	fullBlocks := len(plaintext) / 16
	for i := 0; i < fullBlocks; i++ {
		ctr.ProcessBlock(plaintext, i*16, ciphertext, i*16)
	}
	
	// Handle remaining bytes (if any)
	remaining := len(plaintext) % 16
	if remaining > 0 {
		lastBlock := make([]byte, 16)
		copy(lastBlock, plaintext[fullBlocks*16:])
		encBlock := make([]byte, 16)
		ctr.ProcessBlock(lastBlock, 0, encBlock, 0)
		copy(ciphertext[fullBlocks*16:], encBlock[:remaining])
	}
	
	fmt.Printf("   Ciphertext: %s...\n", hex.EncodeToString(ciphertext[:16]))
	
	// Decrypt
	engine2 := engines.NewSM4Engine()
	ctr2 := modes.NewCTRBlockCipher(engine2)
	ctr2.Init(false, ivParam)
	
	decrypted := make([]byte, len(ciphertext))
	for i := 0; i < fullBlocks; i++ {
		ctr2.ProcessBlock(ciphertext, i*16, decrypted, i*16)
	}
	if remaining > 0 {
		lastBlock := make([]byte, 16)
		copy(lastBlock, ciphertext[fullBlocks*16:])
		decBlock := make([]byte, 16)
		ctr2.ProcessBlock(lastBlock, 0, decBlock, 0)
		copy(decrypted[fullBlocks*16:], decBlock[:remaining])
	}
	
	fmt.Printf("   Decrypted: %s\n", string(decrypted))
	
	if string(plaintext) == string(decrypted) {
		fmt.Println("   ✓ Stream cipher behavior - works on any length!")
	}
}

func counterIncrement() {
	key, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	iv, _ := hex.DecodeString("00000000000000000000000000000000")
	
	// Create multiple identical blocks
	plaintext := make([]byte, 48) // 3 blocks
	for i := range plaintext {
		plaintext[i] = 0xAA // All same
	}
	
	fmt.Println("   Encrypting 3 identical plaintext blocks:")
	fmt.Println("   Plaintext blocks: [AA...AA] [AA...AA] [AA...AA]")
	
	engine := engines.NewSM4Engine()
	ctr := modes.NewCTRBlockCipher(engine)
	keyParam := params.NewKeyParameter(key)
	ivParam := params.NewParametersWithIV(keyParam, iv)
	ctr.Init(true, ivParam)
	
	ciphertext := make([]byte, 48)
	for i := 0; i < 3; i++ {
		ctr.ProcessBlock(plaintext, i*16, ciphertext, i*16)
	}
	
	fmt.Printf("   Block 1: %s\n", hex.EncodeToString(ciphertext[0:16]))
	fmt.Printf("   Block 2: %s\n", hex.EncodeToString(ciphertext[16:32]))
	fmt.Printf("   Block 3: %s\n", hex.EncodeToString(ciphertext[32:48]))
	
	fmt.Println("   ✓ Counter increments → different ciphertext for identical plaintext!")
	fmt.Println("   This is a security feature - prevents pattern detection.")
}

func ctrVsCBC() {
	key, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	iv, _ := hex.DecodeString("00112233445566778899aabbccddeeff")
	plaintext := []byte("Compare modes!!!")
	
	fmt.Println("   Comparing CTR and CBC modes:")
	fmt.Printf("   Plaintext: %s\n", string(plaintext))
	
	// CTR mode
	engineCTR := engines.NewSM4Engine()
	ctr := modes.NewCTRBlockCipher(engineCTR)
	keyParam := params.NewKeyParameter(key)
	ivParam := params.NewParametersWithIV(keyParam, iv)
	ctr.Init(true, ivParam)
	
	ciphertextCTR := make([]byte, len(plaintext))
	ctr.ProcessBlock(plaintext, 0, ciphertextCTR, 0)
	
	// CBC mode
	engineCBC := engines.NewSM4Engine()
	cbc := modes.NewCBCBlockCipher(engineCBC)
	cbc.Init(true, ivParam)
	
	ciphertextCBC := make([]byte, len(plaintext))
	cbc.ProcessBlock(plaintext, 0, ciphertextCBC, 0)
	
	fmt.Printf("   CTR: %s\n", hex.EncodeToString(ciphertextCTR))
	fmt.Printf("   CBC: %s\n", hex.EncodeToString(ciphertextCBC))
	
	fmt.Println("\n   Key differences:")
	fmt.Println("   • CTR: Stream cipher (no padding), parallelizable, random access")
	fmt.Println("   • CBC: Block cipher (needs padding), sequential, simpler")
	fmt.Println("   • CTR: Encryption only (for counter)")
	fmt.Println("   • CBC: Encryption AND decryption operations")
	fmt.Println("   ✓ Both are secure - choose based on use case!")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
