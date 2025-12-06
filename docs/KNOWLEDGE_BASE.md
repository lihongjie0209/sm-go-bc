# SM-GO-BC Knowledge Base

**For AI Agents Working on This Project**

This document provides essential information for continuing development on the sm-go-bc project.

---

## 🎯 Project Status Summary

**Date**: 2025-12-06  
**Completion**: 85%  
**Current Phase**: SM2 Signer Complete, Need SM2 KeyExchange

### What's Done ✅
- ✅ Project structure initialized
- ✅ Core interfaces defined (`crypto/interfaces.go`)
- ✅ Utility functions implemented (`util/pack.go`, `util/arrays.go`)
- ✅ **SM3 hash function COMPLETE and verified** (8/8 tests)
- ✅ **SM4 block cipher engine COMPLETE** (10/10 tests)
- ✅ **SM4 cipher modes COMPLETE** (CBC, CTR, OFB - 26/26 tests)
- ✅ **PKCS7 padding COMPLETE** (10/10 tests)
- ✅ **SM2 elliptic curve math COMPLETE** (15/15 tests)
- ✅ **SM2 encryption engine COMPLETE** (15/15 tests)
- ✅ **SM2 digital signature COMPLETE** (11/11 tests)
- All implementations cross-language compatible

### What's Next ⏳
1. SM2 Key Exchange implementation
2. Additional cipher modes (CFB, GCM if needed)
3. Additional padding schemes (ISO7816, ISO10126)
4. Final integration and high-level API
5. Complete documentation and examples

---

## 📚 Architecture Overview

### Package Structure
```
sm-go-bc/
├── crypto/           # Core cryptographic implementations
│   ├── interfaces.go # All crypto interfaces (Digest, BlockCipher, etc.)
│   ├── digests/     # Hash functions (SM3 ✅)
│   ├── engines/     # Cipher engines (SM2, SM4)
│   ├── signers/     # Digital signature (SM2Signer)
│   ├── modes/       # Cipher modes (CBC, CTR, OFB, CFB, GCM)
│   ├── paddings/    # Padding schemes (PKCS7, ISO7816, etc.)
│   ├── params/      # Crypto parameters
│   └── generators/  # Key generators
├── math/
│   └── ec/          # Elliptic curve math
├── util/            # Utilities (Pack, Arrays ✅)
├── test/            # Test suites
├── examples/        # Usage examples
└── docs/            # Documentation
```

### Key Design Patterns

**1. Interface-Based Design**
- All algorithms implement standard interfaces (Digest, BlockCipher, Signer)
- Enables polymorphism and testing
- See `crypto/interfaces.go` for all interface definitions

**2. Memoable Pattern**
- Objects can save/restore state (e.g., for cloning)
- Implemented in SM3 for efficient branching
- Interface: `Copy() Memoable`, `ResetMemoable(other Memoable)`

**3. Error Handling**
- Go idiomatic: return `(result, error)`
- No panics except for programmer errors
- Validate inputs early

---

## 🔑 Key Implementation Details

### SM3 Hash Function

**Location**: `crypto/digests/sm3.go`

**Key Features**:
- 256-bit (32-byte) hash output
- Processes data in 512-bit (64-byte) blocks
- Internal state: 8 uint32 words
- Message expansion: 68 words
- 64 rounds of compression

**Critical Functions**:
```go
NewSM3Digest() *SM3Digest              // Create new instance
Update(in byte)                         // Add single byte
BlockUpdate(in []byte, inOff, len int) // Add multiple bytes
DoFinal(out []byte, outOff int) int    // Finalize and output hash
Reset()                                 // Reset to initial state
Copy() Memoable                         // Clone state
```

**Test Vectors** (Verified ✅):
```
Empty string:
  1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b

"abc":
  66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0

64-byte "abcd..." repeated:
  debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732
```

**Reference Implementations**:
- Python: `sm-py-bc/src/sm_bc/crypto/digests/sm3_digest.py`
- TypeScript: `sm-js-bc/src/crypto/digests/SM3Digest.ts`
- PHP: `sm-php-bc/src/Crypto/Digests/SM3Digest.php`

### Utility Functions

**Location**: `util/pack.go`, `util/arrays.go`

**Pack Functions** (Byte ordering):
- `BigEndianToUint32(bs []byte, off int) uint32`
- `Uint32ToBigEndian(n uint32, bs []byte, off int)`
- Similar for Uint64, LittleEndian, and array versions

**Array Functions** (Memory operations):
- `AreEqual(a, b []byte) bool` - Simple comparison
- `ConstantTimeAreEqual(a, b []byte) bool` - Constant-time comparison (security)
- `Clone(data []byte) []byte` - Deep copy
- `Clear(data []byte)` - Zero out (security)
- `Concatenate(arrays ...[]byte) []byte` - Merge multiple arrays

**Usage Example**:
```go
// Read big-endian uint32 from bytes
value := util.BigEndianToUint32(data, 0)

// Write uint32 as big-endian bytes
util.Uint32ToBigEndian(value, output, 0)

// Secure comparison
if util.ConstantTimeAreEqual(hash1, hash2) {
    // Hashes match
}
```

---

## 🧪 Testing Strategy

### Test Organization
- Tests in `*_test.go` files alongside implementation
- Use Go's standard `testing` package
- Include benchmarks with `Benchmark*` functions

### Test Pattern
```go
func TestFeature(t *testing.T) {
    // Arrange
    input := []byte("test data")
    expected := "expected_output"
    
    // Act
    result := SomeFunction(input)
    
    // Assert
    if result != expected {
        t.Errorf("Expected %s, got %s", expected, result)
    }
}
```

### Running Tests
```bash
go test ./...                    # All tests
go test -v ./crypto/digests/     # Specific package
go test -cover ./...             # With coverage
go test -bench=. ./...           # Run benchmarks
```

---

## 📖 Reference Materials

### Official Standards
- **SM2**: GM/T 0003-2012 (Elliptic Curve Public Key Cryptography)
- **SM3**: GM/T 0004-2012 (Cryptographic Hash Algorithm)
- **SM4**: GB/T 32907-2016 (Block Cipher Algorithm)

### Reference Implementations
1. **sm-js-bc** (TypeScript) - Primary reference
   - Path: `../sm-js-bc/src/`
   - Most actively maintained
   - Clean, modern code

2. **sm-py-bc** (Python) - Secondary reference
   - Path: `../sm-py-bc/src/sm_bc/`
   - Well-documented
   - Good test coverage

3. **sm-php-bc** (PHP) - Tertiary reference
   - Path: `../sm-php-bc/src/`
   - Recently completed
   - Similar structure

4. **Bouncy Castle** (Java) - Original reference
   - Structure and naming conventions
   - Battle-tested implementations

### Test Vectors Location
- JS: `sm-js-bc/test/`
- Python: `sm-py-bc/tests/unit/`
- PHP: `sm-php-bc/tests/Unit/`

---

## 🛠️ Development Guidelines

### Code Style
1. Follow `gofmt` and official Go style
2. Use meaningful variable names
3. Document all exported functions with godoc comments
4. Keep functions focused and small

### Naming Conventions
- **Exported** (public): `PascalCase` - `SM3Digest`, `NewSM3Digest()`
- **Unexported** (private): `camelCase` - `processBlock()`, `internalState`
- **Interfaces**: `PascalCase` - `Digest`, `BlockCipher`
- **Constants**: `camelCase` or `PascalCase` - `sm3DigestLength`

### Documentation
```go
// SM3Digest implements the SM3 cryptographic hash function.
// Reference: GM/T 0004-2012
// Based on: sm-py-bc/src/sm_bc/crypto/digests/sm3_digest.py
type SM3Digest struct {
    // ...
}

// NewSM3Digest creates a new SM3 digest instance.
func NewSM3Digest() *SM3Digest {
    // ...
}
```

### Error Handling
```go
// Good: Return errors
func ProcessData(data []byte) ([]byte, error) {
    if len(data) == 0 {
        return nil, errors.New("data cannot be empty")
    }
    // ...
    return result, nil
}

// Avoid: Panicking (except for programmer errors)
```

### Security Considerations
1. Use constant-time operations for comparisons
2. Clear sensitive data after use
3. Avoid timing leaks in crypto operations
4. Validate all inputs

---

## 🚀 Next Steps for Agents

### Immediate Tasks (Priority Order)

**1. SM4 Block Cipher Engine**
- Reference: `sm-py-bc/src/sm_bc/crypto/engines/sm4_engine.py`
- Implement: Key expansion, block encrypt/decrypt
- Location: `crypto/engines/sm4.go`
- Tests: Use vectors from reference implementations

**2. SM4 Cipher Modes**
- Start with CBC (most common)
- Then CTR, OFB, CFB
- GCM last (most complex)
- Location: `crypto/modes/`
- Reference: `sm-py-bc/src/sm_bc/crypto/modes/`

**3. Padding Schemes**
- PKCS7 (most important)
- ISO7816-4
- ISO10126-2
- ZeroByte
- Location: `crypto/paddings/`

**4. SM2 Elliptic Curve**
- Math primitives first: `math/ec/`
- Then SM2 operations
- Most complex part of project

### How to Start

1. **Read reference implementation**
   ```bash
   # Example for SM4
   cat ../sm-py-bc/src/sm_bc/crypto/engines/sm4_engine.py
   ```

2. **Port test vectors first** (TDD)
   ```bash
   # Create test file first
   touch crypto/engines/sm4_test.go
   # Add test cases from reference
   ```

3. **Implement to pass tests**
   ```bash
   # Create implementation
   touch crypto/engines/sm4.go
   # Write code until tests pass
   go test ./crypto/engines/
   ```

4. **Create example**
   ```bash
   touch examples/sm4_demo.go
   go run examples/sm4_demo.go
   ```

5. **Update documentation**
   - Update `PROGRESS.md` with completion status
   - Update this knowledge base with new learnings
   - Note any design decisions

---

## 💡 Tips & Tricks

### Go-Specific Adaptations

**1. Byte Slices vs Arrays**
```go
// Use slices for flexibility
func Process(data []byte) {}

// Use arrays for fixed-size
var state [8]uint32
```

**2. No Exceptions - Use Errors**
```go
// Python/Java
try {
    result = doSomething()
} catch (e) {
    handle(e)
}

// Go
result, err := doSomething()
if err != nil {
    handle(err)
}
```

**3. Interfaces Are Implicit**
```go
// No need to declare "implements"
// Just satisfy the interface methods

// Verify at compile time:
var _ crypto.Digest = (*SM3Digest)(nil)
```

**4. Defer for Cleanup**
```go
func ProcessSecretData(key []byte) {
    defer util.Clear(key) // Always clear on exit
    // Use key...
}
```

### Common Pitfalls

1. **Forgetting to mask uint32 operations**
   ```go
   // Python needs: value & 0xFFFFFFFF
   // Go: uint32 already wraps automatically
   value := uint32(a + b) // Automatically wraps
   ```

2. **Slice references vs copies**
   ```go
   // Reference (shares memory)
   a := []byte{1, 2, 3}
   b := a // b points to same data!
   
   // Copy (separate memory)
   a := []byte{1, 2, 3}
   b := make([]byte, len(a))
   copy(b, a)
   ```

3. **Loop variable capture**
   ```go
   // Wrong
   for i := range items {
       go func() {
           process(i) // Captures reference!
       }()
   }
   
   // Right
   for i := range items {
       i := i // Create new variable
       go func() {
           process(i)
       }()
   }
   ```

---

## 📞 Communication Protocol

### Updating Progress

**When you complete a task**:
1. Run all tests: `go test ./...`
2. Update `PROGRESS.md`:
   - Mark tasks as complete ✅
   - Update percentage
   - Add to "Completed Modules" section
3. Update this `KNOWLEDGE_BASE.md` with learnings
4. Commit with descriptive message

**When you hit a blocker**:
1. Document in `PROGRESS.md` under "Known Issues"
2. Note what you tried
3. Add references to similar code in other languages
4. Mark task status clearly

### Handoff Checklist

Before passing to another agent:
- [ ] All tests passing
- [ ] Code formatted (`gofmt`)
- [ ] Documentation updated
- [ ] Examples working
- [ ] Progress file updated
- [ ] Knowledge base updated
- [ ] Next steps clearly defined

---

## 🔗 Quick Links

- **Main README**: `../README.md`
- **Progress Tracker**: `PROGRESS.md`
- **Implementation Guide**: `INSTRUCTION.md`
- **SM3 Implementation**: `../crypto/digests/sm3.go`
- **SM3 Tests**: `../crypto/digests/sm3_test.go`
- **SM3 Example**: `../examples/sm3_demo.go`

---

**Last Updated**: 2025-12-06T10:25:00Z  
**Status**: SM3 Complete ✅, Ready for SM4 Development  
**Next Agent**: Should start with SM4 engine implementation
