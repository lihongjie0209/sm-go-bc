// Package main demonstrates SM4-CBC cipher mode usage.
package main

import (
	"encoding/hex"
	"fmt"
	"github.com/lihongjie0209/sm-go-bc/crypto/engines"
	"github.com/lihongjie0209/sm-go-bc/crypto/modes"
	"github.com/lihongjie0209/sm-go-bc/crypto/paddings"
	"github.com/lihongjie0209/sm-go-bc/crypto/params"
)

func main() {
	fmt.Println("=== SM4-CBC Cipher Mode Demo ===")
	
	// Example 1: Basic CBC encryption
	fmt.Println("\n1. Basic CBC Encryption:")
	basicCBC()
	
	// Example 2: CBC with PKCS7 padding
	fmt.Println("\n2. CBC with PKCS7 Padding:")
	cbcWithPadding()
	
	// Example 3: Encrypting longer messages
	fmt.Println("\n3. Longer Messages:")
	longerMessages()
	
	// Example 4: IV importance
	fmt.Println("\n4. Importance of IV:")
	ivImportance()
}

func basicCBC() {
	key, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	iv, _ := hex.DecodeString("00112233445566778899aabbccddeeff")
	plaintext := []byte("1234567890123456") // Exactly 16 bytes
	
	fmt.Printf("   Plaintext: %s\n", string(plaintext))
	fmt.Printf("   Key:       %s\n", hex.EncodeToString(key))
	fmt.Printf("   IV:        %s\n", hex.EncodeToString(iv))
	
	// Encrypt
	engine := engines.NewSM4Engine()
	cbc := modes.NewCBCBlockCipher(engine)
	keyParam := params.NewKeyParameter(key)
	ivParam := params.NewParametersWithIV(keyParam, iv)
	cbc.Init(true, ivParam)
	
	ciphertext := make([]byte, 16)
	cbc.ProcessBlock(plaintext, 0, ciphertext, 0)
	
	fmt.Printf("   Ciphertext: %s\n", hex.EncodeToString(ciphertext))
	
	// Decrypt
	engine2 := engines.NewSM4Engine()
	cbc2 := modes.NewCBCBlockCipher(engine2)
	cbc2.Init(false, ivParam)
	
	decrypted := make([]byte, 16)
	cbc2.ProcessBlock(ciphertext, 0, decrypted, 0)
	
	fmt.Printf("   Decrypted:  %s\n", string(decrypted))
	fmt.Println("   ✓ Encryption and decryption successful!")
}

func cbcWithPadding() {
	key, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	iv, _ := hex.DecodeString("00112233445566778899aabbccddeeff")
	plaintext := []byte("Hello, SM4-CBC!") // Not a multiple of 16 bytes
	
	fmt.Printf("   Plaintext: %s (%d bytes)\n", string(plaintext), len(plaintext))
	
	// Encrypt
	engine := engines.NewSM4Engine()
	cbc := modes.NewCBCBlockCipher(engine)
	padding := paddings.NewPKCS7Padding()
	cipher := modes.NewPaddedBufferedBlockCipher(cbc, padding)
	
	keyParam := params.NewKeyParameter(key)
	ivParam := params.NewParametersWithIV(keyParam, iv)
	cipher.Init(true, ivParam)
	
	outSize := cipher.GetOutputSize(len(plaintext))
	ciphertext := make([]byte, outSize)
	
	outLen, _ := cipher.ProcessBytes(plaintext, 0, len(plaintext), ciphertext, 0)
	outLen2, _ := cipher.DoFinal(ciphertext, outLen)
	totalOut := outLen + outLen2
	ciphertext = ciphertext[:totalOut]
	
	fmt.Printf("   Ciphertext: %s (%d bytes)\n", hex.EncodeToString(ciphertext), len(ciphertext))
	
	// Decrypt
	engine2 := engines.NewSM4Engine()
	cbc2 := modes.NewCBCBlockCipher(engine2)
	cipher2 := modes.NewPaddedBufferedBlockCipher(cbc2, padding)
	cipher2.Init(false, ivParam)
	
	decrypted := make([]byte, len(ciphertext))
	outLen, _ = cipher2.ProcessBytes(ciphertext, 0, len(ciphertext), decrypted, 0)
	outLen2, _ = cipher2.DoFinal(decrypted, outLen)
	totalOut = outLen + outLen2
	decrypted = decrypted[:totalOut]
	
	fmt.Printf("   Decrypted:  %s (%d bytes)\n", string(decrypted), len(decrypted))
	
	if string(plaintext) == string(decrypted) {
		fmt.Println("   ✓ Padding handled correctly!")
	}
}

func longerMessages() {
	key, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	iv, _ := hex.DecodeString("00112233445566778899aabbccddeeff")
	plaintext := []byte("This is a longer message that spans multiple blocks. " +
		"SM4-CBC can handle messages of any length with proper padding!")
	
	fmt.Printf("   Plaintext length: %d bytes\n", len(plaintext))
	fmt.Printf("   Plaintext: %s\n", string(plaintext))
	
	// Encrypt
	engine := engines.NewSM4Engine()
	cbc := modes.NewCBCBlockCipher(engine)
	padding := paddings.NewPKCS7Padding()
	cipher := modes.NewPaddedBufferedBlockCipher(cbc, padding)
	
	keyParam := params.NewKeyParameter(key)
	ivParam := params.NewParametersWithIV(keyParam, iv)
	cipher.Init(true, ivParam)
	
	outSize := cipher.GetOutputSize(len(plaintext))
	ciphertext := make([]byte, outSize)
	
	outLen, _ := cipher.ProcessBytes(plaintext, 0, len(plaintext), ciphertext, 0)
	outLen2, _ := cipher.DoFinal(ciphertext, outLen)
	totalOut := outLen + outLen2
	ciphertext = ciphertext[:totalOut]
	
	fmt.Printf("   Ciphertext length: %d bytes\n", len(ciphertext))
	fmt.Printf("   Ciphertext: %s...\n", hex.EncodeToString(ciphertext[:32]))
	
	// Decrypt
	engine2 := engines.NewSM4Engine()
	cbc2 := modes.NewCBCBlockCipher(engine2)
	cipher2 := modes.NewPaddedBufferedBlockCipher(cbc2, padding)
	cipher2.Init(false, ivParam)
	
	decrypted := make([]byte, len(ciphertext))
	outLen, _ = cipher2.ProcessBytes(ciphertext, 0, len(ciphertext), decrypted, 0)
	outLen2, _ = cipher2.DoFinal(decrypted, outLen)
	totalOut = outLen + outLen2
	decrypted = decrypted[:totalOut]
	
	fmt.Printf("   Decrypted: %s\n", string(decrypted))
	
	if string(plaintext) == string(decrypted) {
		fmt.Println("   ✓ Long message encrypted and decrypted successfully!")
	}
}

func ivImportance() {
	key, _ := hex.DecodeString("0123456789abcdeffedcba9876543210")
	plaintext := []byte("Same plaintext!!")
	
	// Encrypt with IV1
	iv1, _ := hex.DecodeString("00000000000000000000000000000000")
	engine1 := engines.NewSM4Engine()
	cbc1 := modes.NewCBCBlockCipher(engine1)
	keyParam := params.NewKeyParameter(key)
	ivParam1 := params.NewParametersWithIV(keyParam, iv1)
	cbc1.Init(true, ivParam1)
	
	ciphertext1 := make([]byte, 16)
	cbc1.ProcessBlock(plaintext, 0, ciphertext1, 0)
	
	// Encrypt with IV2
	iv2, _ := hex.DecodeString("11111111111111111111111111111111")
	engine2 := engines.NewSM4Engine()
	cbc2 := modes.NewCBCBlockCipher(engine2)
	ivParam2 := params.NewParametersWithIV(keyParam, iv2)
	cbc2.Init(true, ivParam2)
	
	ciphertext2 := make([]byte, 16)
	cbc2.ProcessBlock(plaintext, 0, ciphertext2, 0)
	
	fmt.Printf("   Plaintext: %s\n", string(plaintext))
	fmt.Printf("   IV 1:      %s\n", hex.EncodeToString(iv1))
	fmt.Printf("   Cipher 1:  %s\n", hex.EncodeToString(ciphertext1))
	fmt.Printf("   IV 2:      %s\n", hex.EncodeToString(iv2))
	fmt.Printf("   Cipher 2:  %s\n", hex.EncodeToString(ciphertext2))
	
	if hex.EncodeToString(ciphertext1) != hex.EncodeToString(ciphertext2) {
		fmt.Println("   ✓ Different IVs produce different ciphertexts!")
		fmt.Println("   This is important for security - always use a unique IV!")
	}
}
