// Package main demonstrates SM3 hash function usage.
package main

import (
	"encoding/hex"
	"fmt"
	"github.com/lihongjie0209/sm-go-bc/crypto/digests"
)

func main() {
	fmt.Println("=== SM3 Hash Function Demo ===")
	
	// Example 1: Simple hash
	fmt.Println("1. Simple Hash:")
	simpleHash()
	
	// Example 2: Incremental hashing
	fmt.Println("\n2. Incremental Hashing:")
	incrementalHash()
	
	// Example 3: Hash comparison
	fmt.Println("\n3. Hash Comparison:")
	hashComparison()
	
	// Example 4: Using Memoable (copy state)
	fmt.Println("\n4. Using Memoable (State Copy):")
	memoableDemo()
}

func simpleHash() {
	digest := digests.NewSM3Digest()
	data := []byte("Hello, SM3!")
	
	digest.BlockUpdate(data, 0, len(data))
	
	output := make([]byte, 32)
	digest.DoFinal(output, 0)
	
	fmt.Printf("   Input: %s\n", string(data))
	fmt.Printf("   Hash:  %s\n", hex.EncodeToString(output))
}

func incrementalHash() {
	digest := digests.NewSM3Digest()
	
	// Hash data in multiple chunks
	parts := []string{"Hello", ", ", "SM3", "!"}
	for _, part := range parts {
		digest.BlockUpdate([]byte(part), 0, len(part))
	}
	
	output := make([]byte, 32)
	digest.DoFinal(output, 0)
	
	fmt.Printf("   Input parts: %v\n", parts)
	fmt.Printf("   Hash:        %s\n", hex.EncodeToString(output))
	
	// Verify it matches single-chunk hash
	digest2 := digests.NewSM3Digest()
	data := []byte("Hello, SM3!")
	digest2.BlockUpdate(data, 0, len(data))
	output2 := make([]byte, 32)
	digest2.DoFinal(output2, 0)
	
	if hex.EncodeToString(output) == hex.EncodeToString(output2) {
		fmt.Println("   ✓ Incremental hash matches single-chunk hash")
	} else {
		fmt.Println("   ✗ Hash mismatch!")
	}
}

func hashComparison() {
	digest1 := digests.NewSM3Digest()
	digest2 := digests.NewSM3Digest()
	
	data1 := []byte("abc")
	data2 := []byte("abc")
	
	digest1.BlockUpdate(data1, 0, len(data1))
	digest2.BlockUpdate(data2, 0, len(data2))
	
	output1 := make([]byte, 32)
	output2 := make([]byte, 32)
	
	digest1.DoFinal(output1, 0)
	digest2.DoFinal(output2, 0)
	
	fmt.Printf("   Data 1: %s -> Hash: %s\n", string(data1), hex.EncodeToString(output1))
	fmt.Printf("   Data 2: %s -> Hash: %s\n", string(data2), hex.EncodeToString(output2))
	
	if hex.EncodeToString(output1) == hex.EncodeToString(output2) {
		fmt.Println("   ✓ Hashes match (same input)")
	}
	
	// Different input
	digest3 := digests.NewSM3Digest()
	data3 := []byte("abd")
	digest3.BlockUpdate(data3, 0, len(data3))
	output3 := make([]byte, 32)
	digest3.DoFinal(output3, 0)
	
	fmt.Printf("   Data 3: %s -> Hash: %s\n", string(data3), hex.EncodeToString(output3))
	
	if hex.EncodeToString(output1) != hex.EncodeToString(output3) {
		fmt.Println("   ✓ Hashes differ (different input)")
	}
}

func memoableDemo() {
	// Create initial digest and hash some data
	digest1 := digests.NewSM3Digest()
	digest1.BlockUpdate([]byte("Prefix: "), 0, 8)
	
	// Save state by copying
	digest2 := digests.NewSM3DigestFromCopy(digest1)
	
	// Continue with different suffixes
	digest1.BlockUpdate([]byte("Message A"), 0, 9)
	output1 := make([]byte, 32)
	digest1.DoFinal(output1, 0)
	
	digest2.BlockUpdate([]byte("Message B"), 0, 9)
	output2 := make([]byte, 32)
	digest2.DoFinal(output2, 0)
	
	fmt.Printf("   Common prefix: 'Prefix: '\n")
	fmt.Printf("   Branch A: 'Message A' -> %s\n", hex.EncodeToString(output1)[:32]+"...")
	fmt.Printf("   Branch B: 'Message B' -> %s\n", hex.EncodeToString(output2)[:32]+"...")
	fmt.Println("   ✓ State cloning allows efficient branching")
}
