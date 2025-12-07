package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/lihongjie0209/sm-go-bc/crypto"
	"github.com/lihongjie0209/sm-go-bc/crypto/engines"
	"github.com/lihongjie0209/sm-go-bc/crypto/modes"
	"github.com/lihongjie0209/sm-go-bc/crypto/paddings"
	"github.com/lihongjie0209/sm-go-bc/crypto/params"
)

func main() {
	fmt.Println("========================================")
	fmt.Println("SM4 Padding Schemes Demo")
	fmt.Println("========================================\n")

	// Generate random key and IV
	key := make([]byte, 16)
	iv := make([]byte, 16)
	rand.Read(key)
	rand.Read(iv)

	plaintext := []byte("Hello, SM4 Padding!")
	fmt.Printf("Plaintext: %s (%d bytes)\n\n", plaintext, len(plaintext))

	// Demonstrate all padding schemes
	demonstratePadding("PKCS7", paddings.NewPKCS7Padding(), key, iv, plaintext)
	demonstratePadding("ZeroByte", paddings.NewZeroBytePadding(), key, iv, plaintext)
	demonstratePadding("ISO7816-4", paddings.NewISO7816d4Padding(), key, iv, plaintext)
	demonstratePadding("ISO10126", paddings.NewISO10126Padding(), key, iv, plaintext)

	// Compare padding schemes
	fmt.Println("\n========================================")
	fmt.Println("Padding Comparison")
	fmt.Println("========================================")
	comparePaddings()
}

func demonstratePadding(name string, padding crypto.BlockCipherPadding, key, iv, plaintext []byte) {
	// Create cipher with specified padding
	engine := engines.NewSM4Engine()
	cbc := modes.NewCBCBlockCipher(engine)
	cipher := modes.NewPaddedBufferedBlockCipher(cbc, padding)

	// Encrypt
	keyParam := params.NewKeyParameter(key)
	ivParam := params.NewParametersWithIV(keyParam, iv)
	cipher.Init(true, ivParam)

	out := make([]byte, cipher.GetOutputSize(len(plaintext)))
	outLen, _ := cipher.ProcessBytes(plaintext, 0, len(plaintext), out, 0)
	outLen2, _ := cipher.DoFinal(out, outLen)
	ciphertext := out[:outLen+outLen2]

	// Decrypt
	cipher.Init(false, ivParam)
	out2 := make([]byte, len(ciphertext))
	outLen3, _ := cipher.ProcessBytes(ciphertext, 0, len(ciphertext), out2, 0)
	outLen4, _ := cipher.DoFinal(out2, outLen3)
	decrypted := out2[:outLen3+outLen4]

	// Display results
	fmt.Printf("%s Padding:\n", name)
	fmt.Printf("  Encrypted: %s\n", hex.EncodeToString(ciphertext))
	fmt.Printf("  Length:    %d bytes (from %d bytes)\n", len(ciphertext), len(plaintext))
	fmt.Printf("  Decrypted: %s\n", decrypted)
	fmt.Println()
}

func comparePaddings() {
	fmt.Println("\nPadding Scheme Comparison:")
	fmt.Println("\n┌─────────────┬────────────┬───────────┬──────────────┬─────────────┐")
	fmt.Println("│ Scheme      │ Ambiguous? │ Secure?   │ Performance  │ Recommended │")
	fmt.Println("├─────────────┼────────────┼───────────┼──────────────┼─────────────┤")
	fmt.Println("│ PKCS7       │ No         │ Yes       │ Fast         │ ✅ Yes      │")
	fmt.Println("│ ZeroByte    │ Yes        │ Depends   │ Fastest      │ ⚠️  Careful │")
	fmt.Println("│ ISO7816-4   │ No         │ Yes       │ Fast         │ ✅ Yes      │")
	fmt.Println("│ ISO10126    │ No         │ Yes       │ Medium       │ ✅ Yes      │")
	fmt.Println("└─────────────┴────────────┴───────────┴──────────────┴─────────────┘")

	fmt.Println("\nPadding Formats:")
	fmt.Println("  • PKCS7:      [data][0x04 0x04 0x04 0x04] - padding length repeated")
	fmt.Println("  • ZeroByte:   [data][0x00 0x00 0x00 0x00] - all zeros")
	fmt.Println("  • ISO7816-4:  [data][0x80 0x00 0x00 0x00] - 0x80 followed by zeros")
	fmt.Println("  • ISO10126:   [data][0xXX 0xXX 0xXX 0x04] - random, last byte is length")

	fmt.Println("\nUse Cases:")
	fmt.Println("  • PKCS7:      General purpose (most common)")
	fmt.Println("  • ZeroByte:   Legacy systems (use with caution)")
	fmt.Println("  • ISO7816-4:  Smart cards, embedded systems")
	fmt.Println("  • ISO10126:   When extra randomness is desired")

	fmt.Println("\nSecurity Notes:")
	fmt.Println("  ⚠️  ZeroByte padding is ambiguous if data ends with zeros")
	fmt.Println("  ✅ PKCS7, ISO7816-4, and ISO10126 are unambiguous")
	fmt.Println("  ✅ All padding schemes are secure when used correctly")
	fmt.Println("  💡 For new applications, use PKCS7 (most widely supported)")
}
