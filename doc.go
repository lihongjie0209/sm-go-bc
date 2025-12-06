// Package smgobc provides a pure Go implementation of Chinese National Cryptographic Standards.
//
// This package implements SM2 (public key cryptography), SM3 (cryptographic hash),
// and SM4 (block cipher) algorithms according to Chinese national standards.
//
// # Installation
//
//	go get github.com/lihongjie0209/sm-go-bc
//
// # SM4 Symmetric Encryption Example
//
//	import (
//	    "github.com/lihongjie0209/sm-go-bc/crypto/engines"
//	    "github.com/lihongjie0209/sm-go-bc/crypto/modes"
//	    "github.com/lihongjie0209/sm-go-bc/crypto/paddings"
//	)
//
//	// Create SM4 cipher with CBC mode
//	engine := engines.NewSM4Engine()
//	mode := modes.NewCBC(engine, iv)
//	padding := paddings.NewPKCS7Padding()
//	cipher := modes.NewPaddedBlockCipher(mode, padding)
//
//	// Encrypt
//	cipher.Init(true, key)
//	ciphertext := cipher.DoFinal(plaintext)
//
// # SM3 Hash Example
//
//	import "github.com/lihongjie0209/sm-go-bc/crypto/digests"
//
//	digest := digests.NewSM3Digest()
//	digest.Update(data, 0, len(data))
//	hashOutput := make([]byte, 32)
//	digest.DoFinal(hashOutput, 0)
//
// # SM2 Digital Signature Example
//
//	import (
//	    "github.com/lihongjie0209/sm-go-bc/crypto/signers"
//	    "github.com/lihongjie0209/sm-go-bc/math/ec"
//	)
//
//	// Generate key pair
//	curve := ec.SM2P256V1()
//	// ... key generation logic
//
//	// Sign and verify
//	signer := signers.NewSM2Signer()
//	signer.Init(true, privParams)
//	signature := signer.GenerateSignature(message)
//
// For more examples, see the examples/ directory in the repository.
package smgobc
