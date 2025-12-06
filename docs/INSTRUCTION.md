# SM2/SM3/SM4 Go Implementation Instructions

## Project Overview
This project aims to provide a pure Go implementation of the Chinese National Standard (SM) cryptographic algorithms (SM2, SM3, SM4), strictly following the architecture and logic of the Bouncy Castle Java (`bc-java`) library and reference implementations (`sm-js-bc`, `sm-py-bc`, `sm-php-bc`).

## Core Requirements

1.  **Reference Implementation**:
    *   Primary Reference: `sm-js-bc` (TypeScript implementation)
    *   Secondary Reference: `sm-py-bc` (Python implementation), `sm-php-bc` (PHP implementation)
    *   Tertiary Reference: `bc-java` (Bouncy Castle Java)
    *   The goal is a one-to-one port of the logic and structure

2.  **Tech Stack**:
    *   Language: Go 1.21+ (with generics support)
    *   Package Manager: Go modules
    *   Testing Framework: Go testing package
    *   Documentation: godoc format

3.  **Design Principles**:
    *   **Structure**: Mirror the package structure of `bc-java` / `sm-js-bc` (e.g., `crypto/digests`, `crypto/engines`, `math/ec`)
    *   **Logic**: Port internal logic exactly to ensure identical behavior
    *   **Dependencies**: Zero external dependencies for cryptographic operations (pure Go implementation)
    *   **Package naming**: Use lowercase package names following Go conventions (e.g., `crypto`, `math`, `util`)
    *   **Type safety**: Leverage Go's strong typing and interfaces

4.  **Code Style**:
    *   Follow official Go style guidelines and `gofmt`
    *   Naming conventions:
        *   Types/Structs: `PascalCase` (e.g., `SM3Digest`)
        *   Functions/Methods: `PascalCase` for exported, `camelCase` for unexported (e.g., `GetDigestSize`, `updateState`)
        *   Variables: `camelCase` (e.g., `digestSize`)
        *   Constants: `PascalCase` or `SCREAMING_SNAKE_CASE` for public constants
    *   Must include detailed godoc comments for all exported types and functions
    *   Comment should note corresponding Java/TS/Python implementation for reference

5.  **Testing Strategy**:
    *   **Test-Driven Development (TDD)**: Write tests before implementation
    *   **Test Vectors**: Reuse test vectors from `sm-js-bc` and other implementations
    *   **Consistency**: Ensure outputs match exactly with reference implementations
    *   **Benchmarks**: Include performance benchmarks for critical operations

## Algorithm Scope

### SM3 (Hash Algorithm)
*   `SM3Digest`: Implementation of the SM3 digest algorithm
*   Block size: 512 bits
*   Digest size: 256 bits
*   Support for incremental hashing
*   Memoable interface for state cloning

### SM2 (Elliptic Curve)
*   **Infrastructure**: Point arithmetic, Field elements, Curve definitions
*   **Signer**: `SM2Signer` (Signature generation/verification)
*   **Engine**: `SM2Engine` (Public key encryption/decryption)
*   **KeyExchange**: `SM2KeyExchange` (Key agreement)
*   **Key Generation**: `ECKeyPairGenerator`

### SM4 (Block Cipher)
*   **Engine**: `SM4Engine` (Basic block cipher)
*   **Modes**: ECB, CBC, CTR, OFB, CFB, GCM
*   **Padding**: PKCS7, ISO7816-4, ISO10126-2, ZeroByte

## Development Workflow

1.  **Phase 1: Foundation (Utilities & Math)**
    *   Implement utility functions (Pack, Arrays, encoding/decoding)
    *   Implement big integer wrapper (if needed)
    *   Implement elliptic curve math primitives

2.  **Phase 2: SM3 Implementation**
    *   Create SM3Digest structure
    *   Port hash logic from reference implementations
    *   Write comprehensive tests with known test vectors
    *   Verify cross-language compatibility

3.  **Phase 3: SM4 Implementation**
    *   Create SM4Engine structure
    *   Implement core block cipher operations
    *   Implement block cipher modes (CBC, CTR, etc.)
    *   Implement padding schemes
    *   Write comprehensive tests

4.  **Phase 4: SM2 Implementation**
    *   Implement elliptic curve operations
    *   Create SM2Signer for digital signatures
    *   Create SM2Engine for encryption/decryption
    *   Implement SM2KeyExchange
    *   Write comprehensive tests

5.  **Phase 5: Integration & Documentation**
    *   Cross-language compatibility tests
    *   Performance benchmarks
    *   Complete API documentation
    *   Usage examples
    *   README with quick start guide

## File Structure Convention

```
sm-go-bc/
├── crypto/
│   ├── digests/
│   │   ├── sm3.go
│   │   └── digest.go (interface)
│   ├── engines/
│   │   ├── sm2_engine.go
│   │   ├── sm4_engine.go
│   │   └── block_cipher.go (interface)
│   ├── signers/
│   │   ├── sm2_signer.go
│   │   └── signer.go (interface)
│   ├── modes/
│   │   ├── cbc.go
│   │   ├── ctr.go
│   │   ├── ofb.go
│   │   ├── cfb.go
│   │   └── gcm.go
│   ├── paddings/
│   │   ├── pkcs7.go
│   │   ├── iso7816.go
│   │   ├── iso10126.go
│   │   └── padding.go (interface)
│   ├── params/
│   │   ├── ec_key_parameters.go
│   │   ├── key_parameter.go
│   │   └── parameters_with_iv.go
│   └── generators/
│       └── ec_key_pair_generator.go
├── math/
│   ├── ec/
│   │   ├── ec_point.go
│   │   ├── ec_curve.go
│   │   ├── ec_field_element.go
│   │   └── custom_named_curves.go
│   └── bigint/
│       └── nat.go (if needed)
├── util/
│   ├── pack.go
│   ├── arrays.go
│   └── encoding.go
├── test/
│   ├── sm2_test.go
│   ├── sm3_test.go
│   ├── sm4_test.go
│   └── test_vectors/
│       └── vectors.json
├── examples/
│   ├── sm2_demo.go
│   ├── sm3_demo.go
│   └── sm4_demo.go
├── docs/
│   ├── INSTRUCTION.md (this file)
│   ├── API.md
│   ├── IMPLEMENTATION.md
│   └── PROGRESS.md
├── go.mod
├── go.sum
├── README.md
└── LICENSE
```

## Verification Standards

*   All unit tests must pass
*   Output results must match exactly with test vectors from reference implementations
*   Cross-language compatibility verified (Go output = JS/Python/PHP output)
*   Benchmarks show reasonable performance
*   Code passes `go vet` and `golint` checks
*   100% godoc coverage for exported APIs

## Development Rules for AI Agents

1.  **Self-Documenting**: 
    *   Update `PROGRESS.md` after completing each module
    *   Document any deviations from reference implementations
    *   Note performance considerations

2.  **Test-First Approach**:
    *   Always write tests before implementation
    *   Port test cases from reference implementations
    *   Add edge case tests specific to Go

3.  **Incremental Development**:
    *   Complete one module at a time
    *   Verify each module independently before moving forward
    *   Keep commits atomic and well-described

4.  **Cross-Reference**:
    *   Always reference the corresponding file in reference implementations
    *   Note line numbers or function names for complex logic
    *   Document any Go-specific adaptations

5.  **Knowledge Base Updates**:
    *   Update documentation immediately after implementation
    *   Create summary documents for other agents
    *   Maintain compatibility matrix

## Next Steps

1.  Initialize Go module with `go mod init`
2.  Create basic project structure
3.  Implement utility functions
4.  Start with SM3 (simplest algorithm)
5.  Progress to SM4, then SM2
6.  Write comprehensive documentation
7.  Create usage examples
8.  Publish to GitHub

## Success Criteria

✅ All algorithms implemented and tested
✅ Cross-language compatibility verified
✅ Documentation complete
✅ Examples working
✅ Performance benchmarks available
✅ Ready for production use
