# Good First Issues Program

Welcome to Arcanum! We've designed a pathway for new contributors to make meaningful contributions without needing deep cryptography or Rust expertise.

## How It Works

1. **Pick an issue** labeled `good first issue` from our [issues page](../../issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22)
2. **Follow the template** - each issue has step-by-step instructions
3. **Open a PR** - we'll review and merge quickly
4. **Get credited** - you're now an Arcanum contributor!

Most good first issues take **5-15 minutes** to complete.

---

## Issue Types

### 1. Add Test Vectors (No Rust Required)

**Difficulty**: Beginner
**Time**: 5-10 minutes
**Skills**: Copy/paste, basic file editing

NIST publishes thousands of Known Answer Test (KAT) vectors for cryptographic algorithms. Each vector tests that our implementation produces the correct output for a given input.

**How to contribute:**
1. Find a test vector from [NIST CAVP](https://csrc.nist.gov/Projects/cryptographic-algorithm-validation-program) or [Wycheproof](https://github.com/google/wycheproof)
2. Open the appropriate test file (listed in the issue)
3. Add the vector in the existing format
4. Open a PR

**Example:**
```rust
// In crates/arcanum-pqc/src/ml_kem/tests.rs

#[test]
fn test_ml_kem_768_kat_47() {
    // NIST FIPS 203 KAT #47
    let dk = hex!("...");  // Decapsulation key
    let ek = hex!("...");  // Encapsulation key
    let ct = hex!("...");  // Ciphertext
    let ss = hex!("...");  // Shared secret

    let decapsulated = MlKem768::decapsulate(&dk, &ct);
    assert_eq!(decapsulated, ss);
}
```

---

### 2. Add Usage Examples (Basic Rust)

**Difficulty**: Beginner
**Time**: 10-15 minutes
**Skills**: Basic Rust syntax

Our documentation needs more examples showing how to use each algorithm.

**How to contribute:**
1. Pick an algorithm that needs examples
2. Write a simple, working code snippet
3. Add it to the appropriate doc comment or examples/ directory

**Example:**
```rust
/// Encrypt a message with AES-256-GCM
///
/// ```rust
/// use arcanum_symmetric::{Aes256Gcm, Cipher};
///
/// let key = Aes256Gcm::generate_key();
/// let nonce = Aes256Gcm::generate_nonce();
/// let ciphertext = Aes256Gcm::encrypt(&key, &nonce, b"secret", None)?;
/// ```
```

---

### 3. Add Benchmark Scenarios (Basic Rust)

**Difficulty**: Beginner
**Time**: 10-15 minutes
**Skills**: Basic Rust, copy existing patterns

Help us document performance across different scenarios.

**How to contribute:**
1. Find an algorithm without benchmarks for a specific size/scenario
2. Copy an existing benchmark as a template
3. Adjust parameters and add to the benchmark file

---

### 4. Improve Error Messages (Basic Rust)

**Difficulty**: Beginner
**Time**: 5-10 minutes
**Skills**: English writing, basic Rust

Better error messages help users debug issues faster.

**How to contribute:**
1. Find an error message that could be clearer
2. Improve the message text
3. Optionally add suggestions for how to fix the error

---

## Available Test Vector Sources

### Post-Quantum (FIPS 203/204/205)
- [ML-KEM Test Vectors](https://csrc.nist.gov/Projects/post-quantum-cryptography/selected-algorithms-2022)
- [ML-DSA Test Vectors](https://csrc.nist.gov/Projects/post-quantum-cryptography/selected-algorithms-2022)
- [SLH-DSA Test Vectors](https://csrc.nist.gov/Projects/post-quantum-cryptography/selected-algorithms-2022)

### Symmetric Encryption
- [AES-GCM (NIST)](https://csrc.nist.gov/Projects/cryptographic-algorithm-validation-program/CAVP-TESTING-BLOCK-CIPHER-MODES)
- [AES-GCM (Wycheproof)](https://github.com/google/wycheproof/blob/master/testvectors/aes_gcm_test.json)
- [ChaCha20-Poly1305 (Wycheproof)](https://github.com/google/wycheproof/blob/master/testvectors/chacha20_poly1305_test.json)

### Signatures
- [Ed25519 (Wycheproof)](https://github.com/google/wycheproof/blob/master/testvectors/ed25519_test.json)
- [ECDSA (Wycheproof)](https://github.com/google/wycheproof/blob/master/testvectors/ecdsa_secp256r1_sha256_test.json)

### Key Exchange
- [X25519 (Wycheproof)](https://github.com/google/wycheproof/blob/master/testvectors/x25519_test.json)
- [ECDH (Wycheproof)](https://github.com/google/wycheproof/blob/master/testvectors/ecdh_secp256r1_test.json)

---

## Issue Backlog

These issues are pre-approved and ready to be claimed. Just comment "I'll take this!" on any issue.

### ML-KEM-768 Test Vectors (FIPS 203)
- [ ] KAT #1-10 (Basic encapsulation)
- [ ] KAT #11-20 (Decapsulation)
- [ ] KAT #21-30 (Edge cases)

### ML-DSA-65 Test Vectors (FIPS 204)
- [ ] KAT #1-10 (Signing)
- [ ] KAT #11-20 (Verification)
- [ ] KAT #21-30 (Invalid signatures)

### Wycheproof Edge Cases
- [ ] AES-GCM: tcId 1-20
- [ ] ChaCha20-Poly1305: tcId 1-20
- [ ] Ed25519: tcId 1-20
- [ ] X25519: tcId 1-20 (including low-order points)

### Documentation Examples
- [ ] ML-KEM key exchange example
- [ ] Hybrid X25519+ML-KEM example
- [ ] Threshold signature example
- [ ] HoloCrypt selective disclosure example

---

## Recognition

All contributors are:
- Listed in our [CONTRIBUTORS.md](../CONTRIBUTORS.md)
- Credited in release notes for their contributions
- Welcomed to take on more complex issues as they learn the codebase

Thank you for helping make cryptography more accessible!
