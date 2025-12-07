# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
