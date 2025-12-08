# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2025-12-08

### Added
- **HMAC-SM3 Implementation**
  - Mac interface matching org.bouncycastle.crypto.Mac
  - RFC 2104 compliant HMAC with SM3 digest
  - Support for any digest algorithm (not just SM3)
  - Handles keys of arbitrary length
  - Supports incremental updates and auto-reset
  - 30+ comprehensive tests
  - Cross-verified with JavaScript implementation
  
- **ZUC Stream Cipher Family**
  - **ZUC-128 Engine**: Complete stream cipher implementation (GM/T 0001-2012, 3GPP TS 35.221)
    - LFSR with 16 cells of 31 bits
    - Bit reorganization and nonlinear function F
    - S-boxes (S0 and S1) with L1/L2 transformations
    - 40+ comprehensive tests
  - **ZUC-256 Engine**: Enhanced security with 256-bit keys
    - 184-bit and 200-bit IV support
    - 20+ comprehensive tests
  - **ZUC-128 MAC (128-EIA3)**: 3GPP LTE/5G integrity protection
    - 32-bit MAC output (configurable)
    - 3GPP TS 35.223 compliant
    - 30+ comprehensive tests
  - **ZUC-256 MAC**: Flexible MAC lengths (32/64/128-bit)
    - Enhanced security for 5G and beyond
    - 30+ comprehensive tests

- **API Improvements**
  - StreamCipher interface matching org.bouncycastle.crypto.StreamCipher
  - API compatibility tests (14+ tests)
  - Verified consistency with Bouncy Castle Java patterns

- **Examples and Documentation**
  - HMAC-SM3 examples (authentication, key derivation, streaming)
  - ZUC examples (ZUC-128/256 encryption, MAC generation)
  - Comprehensive TASK_RECORD.md tracking document
  - Updated README with new features

### Enhanced
- Test coverage increased to 200+ tests (all passing)
- Standards compliance: RFC 2104, GM/T 0001-2012, 3GPP TS 35.221/223
- Production-ready implementations with extensive error handling

## [0.1.0] - 2025-12-07

### Added
- Initial release of SM-GO-BC (Chinese SM Cryptography Go Implementation)
- **SM3 Hash Algorithm**
  - Complete SM3 digest implementation
  - Cross-language interoperability with JavaScript
  - Comprehensive test coverage
  
- **SM4 Block Cipher**
  - Core SM4 encryption/decryption
  - Multiple cipher modes:
    - CBC (Cipher Block Chaining)
    - ECB (Electronic Codebook)
    - CFB (Cipher Feedback) - CFB8 and CFB128
    - CTR (Counter Mode)
    - OFB (Output Feedback)
    - GCM (Galois/Counter Mode) with authentication
  - PKCS#7 padding support
  - High-level `Cipher` API for simplified usage
  - Cross-language testing with JavaScript implementation
  
- **SM2 Elliptic Curve Cryptography**
  - SM2 key pair generation
  - Digital signature (sign/verify)
  - Encryption/decryption
  - Key exchange protocol
  - Support for C1C2C3 and C1C3C2 ciphertext formats
  - EC parameter classes and domain parameters
  - Comprehensive elliptic curve operations
  - Cross-language interoperability tests
  
- **Documentation**
  - Complete API documentation
  - Usage examples for all algorithms
  - Cross-language interoperability guides
  - Chinese and English README files
  
- **Testing**
  - 100+ unit tests
  - Cross-language interoperability tests with JavaScript
  - Known test vectors validation
  - Edge case coverage

### Features
- Pure Go implementation with no external crypto dependencies for SM algorithms
- Thread-safe implementations
- Comprehensive error handling
- Compatible with JavaScript sm-js-bc library
- Well-documented APIs with examples

### Compatibility
- Go 1.21+
- Cross-language tested with sm-js-bc v1.0.0+
