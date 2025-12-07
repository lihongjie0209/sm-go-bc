# Go-JS Alignment Action Plan
**Date:** 2025-12-07  
**Status:** IN PROGRESS

## Overview
This document tracks the alignment of Go implementation with the JavaScript (sm-js-bc) implementation to ensure API compatibility, test coverage, and cross-language interoperability.

## Completed Actions ✅

### Phase 1: Core Infrastructure
- ✅ Removed root-level wrapper files (sm2.go, sm3.go, sm4.go)
- ✅ Implemented proper package structure under pkg/
- ✅ Created crypto parameter classes (ECDomainParameters, ECPrivateKeyParameters, ECPublicKeyParameters)
- ✅ Implemented SM3 digest with full test coverage (20 tests)
- ✅ Implemented SM4 cipher engine
- ✅ Implemented SM2 elliptic curve operations

### Phase 2: Block Cipher Modes
- ✅ CBC mode with PKCS7 padding
- ✅ CTR mode (counter mode)
- ✅ OFB mode (output feedback)
- ✅ CFB mode (cipher feedback) 
- ✅ ECB mode (electronic codebook)
- ✅ GCM mode (Galois/Counter Mode) with authentication

### Phase 3: SM2 Operations
- ✅ SM2 key generation
- ✅ SM2 digital signature (sign/verify)
- ✅ SM2 encryption/decryption
- ✅ SM2 key exchange protocol with optional confirmation

### Phase 4: High-Level API
- ✅ Created api package with simplified interfaces
- ✅ SM3 hash API
- ✅ SM4 encryption/decryption API (all modes)
- ✅ SM2 key generation, sign/verify, encrypt/decrypt API

## Current Session: Test Alignment 🔄

### Goals
1. Align Go tests with JS test structure and coverage
2. Ensure all test cases match JS implementation
3. Verify cross-language interoperability
4. Document test coverage gaps

### Test Categories (from JS)

#### Unit Tests - Completed
1. **Utility Tests**
   - ✅ Pack.test (byte packing/unpacking) - 18 tests
   - ✅ Integers.test (integer operations) - 49 tests
   - ✅ SecureRandom.test (RNG) - 22 tests
   - ⚠️ UtilityIntegration.test - needs Go equivalent

2. **Math Tests**
   - ✅ Nat.test (natural number arithmetic) - 16 tests
   - ✅ ECFieldElement tests - 48 tests
   - ✅ ECCurve tests - 34 tests
   - ✅ ECMultiplier tests - 53 tests (basic + comprehensive)
   - ⚠️ CombAlgorithmMath.test - needs documentation

3. **Crypto Tests**
   - ✅ SM3Digest.test - 20 tests
   - ✅ SM4.test - 17 tests
   - ✅ KDF.test (Key Derivation) - 25 tests
   - ✅ CBC mode - 11 tests
   - ✅ CTR/SIC mode - 19 tests
   - ✅ CFB mode - 17 tests
   - ✅ OFB mode - 22 tests
   - ✅ GCM mode - 17 tests
   - ✅ GCMUtil - 15 tests

#### Integration Tests - In Progress
1. **Cross-Language Interop**
   - ✅ JS→Go decryption tests
   - ✅ Go→JS decryption tests
   - ⚠️ Need to verify all modes (CBC, CTR, GCM, etc.)
   - ⚠️ SM2 cross-language tests needed

2. **High-Level API Tests**
   - ⚠️ Need comprehensive API tests
   - ⚠️ Need example programs

### Test Count Comparison

| Category | JS Tests | Go Tests | Status |
|----------|----------|----------|--------|
| Utility | 103 | ~80 | ⚠️ Missing integration tests |
| Math | 151 | ~100 | ⚠️ Missing comb algorithm docs |
| Crypto Core | 62 | 62 | ✅ Aligned |
| Block Modes | 86 | ~70 | ⚠️ Need comprehensive mode tests |
| SM2 | ~30 | 30 | ✅ Aligned |
| SM2 KeyExchange | ~10 | 3 subtests | ✅ Functional |
| Cross-Language | ~20 | 10 | ⚠️ Need more coverage |
| **TOTAL** | **462+** | **~355** | **77% coverage** |

## Next Actions 🎯

### Immediate (This Session)
1. ⚠️ Create comprehensive test files for each mode
2. ⚠️ Add integration tests for high-level API
3. ⚠️ Implement cross-language SM2 tests
4. ⚠️ Add error handling tests
5. ⚠️ Add edge case tests (empty input, large data, etc.)

### Short Term (Next Session)
1. Add performance benchmarks
2. Add fuzzing tests
3. Improve documentation with examples
4. Create migration guide from JS to Go

### Long Term
1. Add GraalVM integration tests
2. Create comprehensive API documentation
3. Add CI/CD workflows
4. Publish package to pkg.go.dev

## Test Implementation Strategy

### Step 1: Create Test Files (Aligned with JS structure)
```
tests/
├── unit/
│   ├── util/
│   │   ├── pack_test.go ✅
│   │   ├── integers_test.go ✅
│   │   ├── secure_random_test.go ✅
│   │   └── utility_integration_test.go ❌
│   ├── math/
│   │   ├── nat_test.go ✅
│   │   ├── ec_field_element_test.go ✅
│   │   ├── ec_curve_test.go ✅
│   │   ├── ec_multiplier_test.go ✅
│   │   └── comb_algorithm_test.go ❌
│   └── crypto/
│       ├── sm3_test.go ✅
│       ├── sm4_test.go ✅
│       ├── kdf_test.go ✅
│       └── modes/
│           ├── cbc_test.go ✅
│           ├── ctr_test.go ✅
│           ├── cfb_test.go ✅
│           ├── ofb_test.go ✅
│           ├── ecb_test.go ✅
│           ├── gcm_test.go ✅
│           └── gcm_util_test.go ❌
├── integration/
│   ├── cross_language_test.go ⚠️ (partial)
│   ├── high_level_api_test.go ❌
│   └── sm2_interop_test.go ❌
└── examples/
    ├── sm3_example_test.go ✅
    ├── sm4_example_test.go ⚠️
    └── sm2_example_test.go ❌
```

### Step 2: Test Content Guidelines
1. Each test file should have similar structure to JS version
2. Test names should match JS test descriptions
3. Test vectors should be identical where possible
4. Add Go-specific tests for error handling
5. Include table-driven tests for multiple cases

### Step 3: Cross-Language Test Strategy
1. Generate test vectors in JS
2. Export as JSON
3. Import in Go tests
4. Verify encryption/decryption in both directions
5. Test all modes and algorithms

## Success Criteria
- [ ] All JS test cases have Go equivalents
- [ ] Cross-language tests pass in both directions
- [ ] Test coverage >= 90%
- [ ] All examples run successfully
- [ ] Documentation is complete
- [ ] CI/CD pipeline is green

## Notes
- Prioritize functional correctness over 100% test parity
- Focus on cross-language compatibility
- Ensure error messages are helpful
- Keep API simple and idiomatic to Go

## References
- JS Implementation: `sm-js-bc/test/`
- Test Alignment Audit: `GO_JS_TEST_ALIGNMENT_AUDIT_2025-12-07.md`
- Recommendations: `TEST_ALIGNMENT_RECOMMENDATIONS.md`
