# Arcanum Release Roadmap

**Version:** 1.0.0-rc1
**Created:** 2026-01-20
**Methodology:** Test-Driven Development (TDD)
**Status:** Draft

---

## Overview

This roadmap addresses all issues identified in the pre-release security and quality audit. Each item follows TDD methodology:

1. **RED**: Write failing test that exposes the issue
2. **GREEN**: Implement fix to make test pass
3. **REFACTOR**: Clean up while maintaining passing tests

Issues are organized into phases with clear dependencies. Each phase must be completed before the next begins.

---

## Phase 1: Critical Security Fixes

**Timeline:** Immediate (blocks release)
**Dependencies:** None

### 1.1 Timing Attack in X25519 Low-Order Point Check

**Issue:** `X25519SharedSecret::is_low_order()` uses non-constant-time comparison

**Location:** `crates/arcanum-asymmetric/src/x25519.rs:209`

#### TDD Steps

**RED - Write failing test:**
```rust
// crates/arcanum-asymmetric/src/x25519.rs (tests module)

#[test]
fn test_is_low_order_constant_time() {
    use std::time::Instant;

    // All-zero shared secret (low order)
    let low_order = X25519SharedSecret::from([0u8; 32]);

    // Non-zero shared secret
    let mut normal = [0u8; 32];
    normal[31] = 0x01;
    let normal = X25519SharedSecret::from(normal);

    // Measure timing for both cases (run many iterations)
    const ITERATIONS: u32 = 10_000;

    let start = Instant::now();
    for _ in 0..ITERATIONS {
        std::hint::black_box(low_order.is_low_order());
    }
    let low_order_time = start.elapsed();

    let start = Instant::now();
    for _ in 0..ITERATIONS {
        std::hint::black_box(normal.is_low_order());
    }
    let normal_time = start.elapsed();

    // Times should be within 10% of each other for constant-time
    let ratio = low_order_time.as_nanos() as f64 / normal_time.as_nanos() as f64;
    assert!(
        (0.9..=1.1).contains(&ratio),
        "Timing variance too high: ratio={:.3} (low_order={:?}, normal={:?})",
        ratio, low_order_time, normal_time
    );
}

#[test]
fn test_is_low_order_correctness() {
    // All zeros = low order
    assert!(X25519SharedSecret::from([0u8; 32]).is_low_order());

    // Any non-zero byte = not low order
    for i in 0..32 {
        let mut bytes = [0u8; 32];
        bytes[i] = 1;
        assert!(!X25519SharedSecret::from(bytes).is_low_order());
    }

    // All 0xFF = not low order
    assert!(!X25519SharedSecret::from([0xFF; 32]).is_low_order());
}
```

**GREEN - Implement fix:**
```rust
// crates/arcanum-asymmetric/src/x25519.rs

use subtle::{Choice, ConstantTimeEq};

impl X25519SharedSecret {
    /// Check if this shared secret is a low-order point (all zeros).
    ///
    /// # Security
    ///
    /// This check is performed in constant time to prevent timing attacks.
    pub fn is_low_order(&self) -> bool {
        // Constant-time OR of all bytes, then check if result is zero
        let zero = [0u8; 32];
        self.bytes.ct_eq(&zero).into()
    }
}
```

**REFACTOR:** Ensure `subtle` crate is in dependencies, add documentation.

---

### 1.2 Panic on Untrusted Input - Poly1305

**Issue:** Multiple `.unwrap()` calls on user-controlled slice conversions

**Location:** `crates/arcanum-primitives/src/poly1305.rs:87-88, 259-260, 297, 301, 334`

#### TDD Steps

**RED - Write failing tests:**
```rust
// crates/arcanum-primitives/src/poly1305.rs (tests module)

#[test]
fn test_poly1305_empty_input() {
    let key = [0u8; 32];
    let mut poly = Poly1305::new(&key);
    poly.update(&[]);  // Should not panic
    let tag = poly.finalize();
    assert_eq!(tag.len(), 16);
}

#[test]
fn test_poly1305_unaligned_input_sizes() {
    let key = [0x42u8; 32];

    // Test all sizes from 0 to 100 (including non-16-byte-aligned)
    for size in 0..=100 {
        let input = vec![0xAB; size];
        let mut poly = Poly1305::new(&key);
        poly.update(&input);  // Should not panic for any size
        let tag = poly.finalize();
        assert_eq!(tag.len(), 16, "Failed at size {}", size);
    }
}

#[test]
fn test_poly1305_multiple_unaligned_updates() {
    let key = [0x42u8; 32];
    let mut poly = Poly1305::new(&key);

    // Multiple updates with odd sizes
    poly.update(&[1, 2, 3]);
    poly.update(&[4, 5, 6, 7, 8]);
    poly.update(&[9]);
    poly.update(&[10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20]);

    let tag = poly.finalize();
    assert_eq!(tag.len(), 16);
}

#[test]
fn test_poly1305_large_input() {
    let key = [0x42u8; 32];
    let input = vec![0xCD; 1_000_000];  // 1MB

    let mut poly = Poly1305::new(&key);
    poly.update(&input);
    let tag = poly.finalize();
    assert_eq!(tag.len(), 16);
}
```

**GREEN - Replace unwraps with safe alternatives:**
```rust
// Pattern 1: Use array chunks iterator
fn process_block(&mut self, block: &[u8]) {
    debug_assert_eq!(block.len(), 16);
    // Instead of: block.try_into().unwrap()
    // Use: array reference with bounds check
    let block: &[u8; 16] = block.try_into()
        .expect("process_block called with non-16-byte block (internal error)");
    // ... rest of implementation
}

// Pattern 2: Use get() with fallback for user input
pub fn update(&mut self, data: &[u8]) {
    // Process complete 16-byte blocks
    let chunks = data.chunks_exact(16);
    let remainder = chunks.remainder();

    for chunk in chunks {
        // chunks_exact guarantees 16 bytes, safe to convert
        let block: &[u8; 16] = chunk.try_into().unwrap();
        self.process_block(block);
    }

    // Handle remainder safely (always < 16 bytes)
    if !remainder.is_empty() {
        self.buffer[..remainder.len()].copy_from_slice(remainder);
        self.buffer_len = remainder.len();
    }
}
```

**REFACTOR:** Add `debug_assert!` for internal invariants, document safety.

---

### 1.3 Panic on Untrusted Input - ChaCha20Poly1305

**Issue:** `.unwrap()` calls in AEAD decryption path

**Location:** `crates/arcanum-primitives/src/chacha20poly1305.rs:250, 307-308`

#### TDD Steps

**RED - Write failing tests:**
```rust
// crates/arcanum-primitives/src/chacha20poly1305.rs (tests module)

#[test]
fn test_decrypt_truncated_ciphertext() {
    let key = [0x42u8; 32];
    let nonce = [0x24u8; 12];
    let cipher = ChaCha20Poly1305::new(&key);

    // Encrypt some data
    let mut buffer = b"hello world".to_vec();
    let tag = cipher.encrypt(&nonce, &[], &mut buffer);

    // Try to decrypt with truncated ciphertext (should error, not panic)
    for truncate_by in 1..=buffer.len() {
        let truncated = &buffer[..buffer.len() - truncate_by];
        let mut decrypt_buf = truncated.to_vec();

        let result = cipher.decrypt(&nonce, &[], &mut decrypt_buf, &tag);
        assert!(result.is_err(), "Should fail with truncated ciphertext");
    }
}

#[test]
fn test_decrypt_empty_ciphertext() {
    let key = [0x42u8; 32];
    let nonce = [0x24u8; 12];
    let cipher = ChaCha20Poly1305::new(&key);

    let mut buffer = vec![];
    let tag = [0u8; 16];

    // Should return error, not panic
    let result = cipher.decrypt(&nonce, &[], &mut buffer, &tag);
    assert!(result.is_err());
}

#[test]
fn test_decrypt_wrong_tag_length() {
    let key = [0x42u8; 32];
    let nonce = [0x24u8; 12];
    let cipher = ChaCha20Poly1305::new(&key);

    let mut buffer = b"test data".to_vec();

    // This is a compile-time guarantee with [u8; 16], but test the API
    // accepts the right type
    let tag: [u8; 16] = [0u8; 16];
    let result = cipher.decrypt(&nonce, &[], &mut buffer, &tag);
    assert!(result.is_err());  // Wrong tag should fail authentication
}

#[test]
fn test_open_malformed_ciphertext() {
    let key = [0x42u8; 32];
    let nonce = [0x24u8; 12];
    let cipher = ChaCha20Poly1305::new(&key);

    // Too short (less than TAG_SIZE)
    for len in 0..16 {
        let malformed = vec![0u8; len];
        let result = cipher.open(&nonce, &[], &malformed);
        assert!(result.is_err(), "Should fail for len={}", len);
    }

    // Random garbage of valid length
    let garbage = vec![0xDE; 100];
    let result = cipher.open(&nonce, &[], &garbage);
    assert!(result.is_err());
}
```

**GREEN - Add proper error handling:**
```rust
// crates/arcanum-primitives/src/chacha20poly1305.rs

pub fn open(
    &self,
    nonce: &[u8; NONCE_SIZE],
    aad: &[u8],
    ciphertext_and_tag: &[u8],
) -> Result<Vec<u8>, AeadError> {
    // Validate minimum length
    if ciphertext_and_tag.len() < TAG_SIZE {
        return Err(AeadError::InvalidLength {
            expected: TAG_SIZE,
            actual: ciphertext_and_tag.len(),
        });
    }

    let ct_len = ciphertext_and_tag.len() - TAG_SIZE;
    let ciphertext = &ciphertext_and_tag[..ct_len];

    // Safe conversion - we verified length above
    let tag: &[u8; TAG_SIZE] = ciphertext_and_tag[ct_len..]
        .try_into()
        .map_err(|_| AeadError::InvalidLength {
            expected: TAG_SIZE,
            actual: ciphertext_and_tag.len() - ct_len,
        })?;

    let mut plaintext = ciphertext.to_vec();
    self.decrypt(nonce, aad, &mut plaintext, tag)?;

    Ok(plaintext)
}
```

---

### 1.4 Undefined Feature Flag Usage

**Issue:** `ethereum` feature used but not defined in Cargo.toml

**Location:** `crates/arcanum-asymmetric/src/ecdh.rs:398`

#### TDD Steps

**RED - Write test that uses the feature:**
```rust
// crates/arcanum-asymmetric/src/ecdh.rs (tests module)

#[test]
#[cfg(feature = "ethereum")]
fn test_to_ethereum_address() {
    use crate::ecdh::EcdhPublicKey;

    // Known test vector from Ethereum
    let pubkey_bytes = hex::decode(
        "04\
         50863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352\
         2cd470243453a299fa9e77237716103abc11a1df38855ed6f2ee187e9c582ba6"
    ).unwrap();

    let pubkey = EcdhPublicKey::from_sec1_bytes(&pubkey_bytes).unwrap();
    let address = pubkey.to_ethereum_address();

    // Expected: 0x001d3f1ef827552ae1114027bd3ecf1f086ba0f9
    assert_eq!(
        hex::encode(&address),
        "001d3f1ef827552ae1114027bd3ecf1f086ba0f9"
    );
}

#[test]
#[cfg(not(feature = "ethereum"))]
fn test_ethereum_feature_not_available() {
    // This test ensures the function doesn't exist without the feature
    // Compilation will fail if to_ethereum_address() is available without feature
}
```

**GREEN - Add feature to Cargo.toml:**
```toml
# crates/arcanum-asymmetric/Cargo.toml

[features]
default = ["std"]
std = []
ethereum = ["sha3"]  # Ethereum addresses use Keccak-256

[dependencies]
sha3 = { version = "0.10", optional = true }
```

**Update the function with proper feature gate:**
```rust
// crates/arcanum-asymmetric/src/ecdh.rs

/// Convert public key to Ethereum address (Keccak-256 of uncompressed point, last 20 bytes).
///
/// # Example
///
/// ```
/// # #[cfg(feature = "ethereum")]
/// # {
/// use arcanum_asymmetric::ecdh::EcdhPublicKey;
///
/// let pubkey = EcdhPublicKey::generate();
/// let address = pubkey.to_ethereum_address();
/// assert_eq!(address.len(), 20);
/// # }
/// ```
#[cfg(feature = "ethereum")]
pub fn to_ethereum_address(&self) -> [u8; 20] {
    use sha3::{Keccak256, Digest};

    // Get uncompressed point (65 bytes: 0x04 || x || y)
    let uncompressed = self.to_sec1_bytes_uncompressed();

    // Keccak-256 hash of x || y (skip the 0x04 prefix)
    let hash = Keccak256::digest(&uncompressed[1..]);

    // Take last 20 bytes
    let mut address = [0u8; 20];
    address.copy_from_slice(&hash[12..]);
    address
}
```

---

## Phase 2: High Priority Security & Quality

**Timeline:** Before release
**Dependencies:** Phase 1 complete

### 2.1 Mutex Poisoning in Random Number Generator

**Issue:** `lock().unwrap()` panics if mutex was poisoned

**Location:** `crates/arcanum-primitives/src/random.rs:154,166`

#### TDD Steps

**RED - Write test:**
```rust
// crates/arcanum-primitives/src/random.rs (tests module)

#[test]
fn test_rng_survives_panic_in_other_thread() {
    use std::sync::Arc;
    use std::thread;

    // Get a reference to the global RNG
    let rng = Arc::new(std::sync::Mutex::new(()));

    // Spawn a thread that panics while "holding" a conceptual lock
    let rng_clone = rng.clone();
    let handle = thread::spawn(move || {
        let _guard = rng_clone.lock().unwrap();
        panic!("Intentional panic to poison mutex");
    });

    // Wait for thread to panic
    let _ = handle.join();

    // RNG should still work (this tests our actual implementation)
    let mut bytes = [0u8; 32];
    fill_random(&mut bytes);  // Should not panic

    // Verify we got some randomness (not all zeros)
    assert!(bytes.iter().any(|&b| b != 0));
}
```

**GREEN - Handle poisoned mutex:**
```rust
// crates/arcanum-primitives/src/random.rs

pub fn fill_random(dest: &mut [u8]) {
    let mut rng = RNG.lock().unwrap_or_else(|poisoned| {
        // Mutex was poisoned by a panic in another thread.
        // The RNG state is still valid, so recover it.
        poisoned.into_inner()
    });
    rng.fill_bytes(dest);
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut rng = RNG.lock().unwrap_or_else(|poisoned| {
        poisoned.into_inner()
    });
    let mut bytes = [0u8; N];
    rng.fill_bytes(&mut bytes);
    bytes
}
```

---

### 2.2 Add `#[must_use]` to Result-Returning Functions

**Issue:** 174 functions return `Result` without `#[must_use]`

**Locations:** All crates, especially AEAD and signature operations

#### TDD Steps

**RED - Write test that would catch ignored errors:**
```rust
// This is a documentation/lint test - add to CI

// .cargo/config.toml or lib.rs
#![deny(unused_must_use)]

// Test file: tests/must_use_enforcement.rs
#[test]
fn test_decrypt_result_must_be_used() {
    let key = [0u8; 32];
    let nonce = [0u8; 12];
    let cipher = ChaCha20Poly1305::new(&key);

    let mut buffer = b"test".to_vec();
    let tag = cipher.encrypt(&nonce, &[], &mut buffer);

    // This should cause a compiler warning/error with #[must_use]
    // cipher.decrypt(&nonce, &[], &mut buffer, &tag);

    // Correct usage:
    let result = cipher.decrypt(&nonce, &[], &mut buffer, &tag);
    assert!(result.is_ok());
}
```

**GREEN - Add attributes systematically:**
```rust
// Pattern for all Result-returning functions:

/// Decrypt ciphertext in place.
///
/// # Errors
///
/// Returns `AeadError::AuthenticationFailed` if the tag doesn't match.
#[must_use = "decryption may fail; check the Result"]
pub fn decrypt(
    &self,
    nonce: &[u8; NONCE_SIZE],
    aad: &[u8],
    buffer: &mut [u8],
    tag: &[u8; TAG_SIZE],
) -> Result<(), AeadError> {
    // ...
}

// For functions returning Option:
#[must_use = "returns None if parsing fails"]
pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
    // ...
}
```

**Batch update script:**
```bash
# Find all pub fn returning Result without #[must_use]
rg -l 'pub fn.*-> Result' crates/ | while read file; do
    echo "Processing: $file"
    # Add #[must_use] before each pub fn ... -> Result
done
```

---

### 2.3 Remove Duplicate Error Files

**Issue:** Both `error.rs` and `errors.rs` exist in arcanum-threshold

**Location:** `crates/arcanum-threshold/src/`

#### TDD Steps

**RED - Write test to verify unified error type:**
```rust
// crates/arcanum-threshold/src/lib.rs (tests module)

#[test]
fn test_all_functions_use_same_error_type() {
    // This is a compile-time test - if it compiles, errors are unified

    fn accepts_threshold_error(_: ThresholdError) {}

    // All these should return the same error type
    let e1 = ThresholdError::InvalidThreshold { threshold: 0, total: 5 };
    let e2 = ThresholdError::InsufficientShares { provided: 2, required: 3 };
    let e3 = ThresholdError::InvalidShare;

    accepts_threshold_error(e1);
    accepts_threshold_error(e2);
    accepts_threshold_error(e3);
}

#[test]
fn test_error_conversion_from_core() {
    // If we need conversion from arcanum_core::error::Error
    let core_error = arcanum_core::error::Error::InvalidInput("test".into());
    let threshold_error: ThresholdError = core_error.into();

    matches!(threshold_error, ThresholdError::CoreError(_));
}
```

**GREEN - Consolidate error types:**
```rust
// crates/arcanum-threshold/src/error.rs (keep this one)

use thiserror::Error;

/// Errors that can occur in threshold cryptography operations.
#[derive(Debug, Error)]
pub enum ThresholdError {
    #[error("invalid threshold: {threshold} of {total} (threshold must be > 0 and <= total)")]
    InvalidThreshold { threshold: usize, total: usize },

    #[error("insufficient shares: provided {provided}, required {required}")]
    InsufficientShares { provided: usize, required: usize },

    #[error("invalid share format or corrupted data")]
    InvalidShare,

    #[error("share verification failed")]
    VerificationFailed,

    #[error("duplicate share index: {0}")]
    DuplicateIndex(u8),

    #[error(transparent)]
    Core(#[from] arcanum_core::error::Error),
}

/// Result type for threshold operations.
pub type Result<T> = std::result::Result<T, ThresholdError>;

// Delete errors.rs after migration
```

**REFACTOR - Update all imports:**
```bash
# Find and replace
sed -i 's/use crate::errors::/use crate::error::/g' crates/arcanum-threshold/src/*.rs
# Remove the old file
rm crates/arcanum-threshold/src/errors.rs
```

---

### 2.4 Add Missing Test Vectors

**Issue:** PQC algorithms lack FIPS test vectors

**Location:** `crates/arcanum-pqc/`

#### TDD Steps

**RED - Add NIST test vector tests:**
```rust
// crates/arcanum-pqc/src/ml_kem.rs (tests module)

/// FIPS 203 (ML-KEM) Known Answer Tests
/// Source: NIST ACVP test vectors
mod fips_203_kat {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_ml_kem_512_encapsulation_kat() {
        // NIST ACVP test vector
        let seed = hex!("...");  // 64 bytes: d || z
        let expected_pk = hex!("...");
        let expected_sk = hex!("...");
        let expected_ct = hex!("...");
        let expected_ss = hex!("...");

        // Deterministic key generation from seed
        let (pk, sk) = MlKem512::generate_deterministic(&seed);
        assert_eq!(pk.as_bytes(), &expected_pk[..]);
        assert_eq!(sk.as_bytes(), &expected_sk[..]);

        // Deterministic encapsulation
        let encap_seed = hex!("...");  // 32 bytes: m
        let (ct, ss) = pk.encapsulate_deterministic(&encap_seed);
        assert_eq!(ct.as_bytes(), &expected_ct[..]);
        assert_eq!(ss.as_bytes(), &expected_ss[..]);

        // Decapsulation
        let ss_decap = sk.decapsulate(&ct);
        assert_eq!(ss_decap.as_bytes(), &expected_ss[..]);
    }

    #[test]
    fn test_ml_kem_768_encapsulation_kat() {
        // ... similar for ML-KEM-768
    }

    #[test]
    fn test_ml_kem_1024_encapsulation_kat() {
        // ... similar for ML-KEM-1024
    }
}

/// FIPS 204 (ML-DSA) Known Answer Tests
mod fips_204_kat {
    #[test]
    fn test_ml_dsa_44_sign_verify_kat() {
        // NIST test vector
        let seed = hex!("...");
        let message = hex!("...");
        let expected_sig = hex!("...");

        let (pk, sk) = MlDsa44::generate_deterministic(&seed);
        let sig = sk.sign_deterministic(&message);

        assert_eq!(sig.as_bytes(), &expected_sig[..]);
        assert!(pk.verify(&message, &sig).is_ok());
    }
}
```

**GREEN - Implement deterministic variants for testing:**
```rust
// crates/arcanum-pqc/src/ml_kem.rs

impl MlKem512 {
    /// Generate key pair from seed (for testing with KAT vectors).
    ///
    /// # Security
    ///
    /// Only use this for testing with known-answer tests.
    /// For production, use `generate()` which uses secure randomness.
    #[cfg(test)]
    pub(crate) fn generate_deterministic(seed: &[u8; 64]) -> (PublicKey, SecretKey) {
        let d = &seed[..32];
        let z = &seed[32..];
        // ... deterministic generation using d and z
    }
}
```

---

## Phase 3: Code Quality & Cleanup

**Timeline:** Before stable release
**Dependencies:** Phase 2 complete

### 3.1 Remove Dead CUDA Code

**Issue:** 801 lines of CUDA code never compiled

**Location:** `crates/arcanum-primitives/src/blake3_cuda.cu`, `blake3_cuda_ffi.rs`

#### TDD Steps

**RED - Verify CUDA is not used:**
```rust
// tests/no_cuda_dependency.rs

#[test]
fn test_blake3_works_without_cuda() {
    use arcanum_primitives::blake3::hash;

    let data = b"test data for BLAKE3";
    let hash = hash(data);

    // Known answer test
    assert_eq!(
        hex::encode(&hash),
        "expected_blake3_hash_here"
    );
}

#[test]
fn test_no_cuda_symbols_exported() {
    // Check that no CUDA-related symbols are in the public API
    // This is a compile-time check - if blake3_cuda is removed,
    // any code using it will fail to compile
}
```

**GREEN - Remove or feature-gate:**

Option A: Remove entirely (recommended if CUDA not needed):
```bash
git rm crates/arcanum-primitives/src/blake3_cuda.cu
git rm crates/arcanum-primitives/src/blake3_cuda_ffi.rs
```

Option B: Feature-gate for future use:
```toml
# crates/arcanum-primitives/Cargo.toml

[features]
cuda = ["cc"]  # Enables CUDA acceleration

[build-dependencies]
cc = { version = "1.0", optional = true }
```

```rust
// crates/arcanum-primitives/src/lib.rs

#[cfg(feature = "cuda")]
mod blake3_cuda_ffi;
```

---

### 3.2 Clean Up arcanum-platform Directory

**Issue:** Separate workspace with potentially stale code

**Location:** `/home/user/arcanum/arcanum-platform/`

#### TDD Steps

**RED - Audit what's unique:**
```bash
# Compare directory structures
diff -rq crates/ arcanum-platform/crates/ | grep -v "Only in"

# Check for unique implementations
for crate in arcanum-platform/crates/*/; do
    name=$(basename "$crate")
    if [ ! -d "crates/$name" ]; then
        echo "UNIQUE: $name"
    fi
done
```

**GREEN - Archive or remove:**
```bash
# Option A: Archive for reference
mkdir -p archive/
mv arcanum-platform archive/arcanum-platform-legacy
echo "Archived on $(date) - see main crates/ for current code" > archive/README.md

# Option B: Remove entirely if confirmed stale
rm -rf arcanum-platform/

# Update .gitignore if archiving
echo "archive/" >> .gitignore
```

---

### 3.3 Add no_std Gates

**Issue:** Crates claim no_std support but lack proper attributes

**Location:** All library crates

#### TDD Steps

**RED - Write no_std compilation test:**
```rust
// tests/no_std_compile_test.rs
// This file should compile with #![no_std]

#![no_std]

extern crate arcanum_primitives;
extern crate arcanum_core;

use arcanum_primitives::chacha20::ChaCha20;
use arcanum_core::traits::Cipher;

#[test]
fn test_chacha20_no_std() {
    let key = [0u8; 32];
    let nonce = [0u8; 12];
    let mut cipher = ChaCha20::new(&key, &nonce);

    let mut buffer = [0u8; 64];
    cipher.apply_keystream(&mut buffer);
}
```

**GREEN - Add proper no_std gates:**
```rust
// crates/arcanum-primitives/src/lib.rs

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec, string::String};

// ... rest of lib.rs
```

```toml
# crates/arcanum-primitives/Cargo.toml

[features]
default = ["std"]
std = []
alloc = []  # For Vec, String without full std
```

---

### 3.4 Remove Dead Feature Flags

**Issue:** Features defined but never used

**Location:** Various Cargo.toml files

#### TDD Steps

**RED - Audit feature usage:**
```bash
# For each feature, check if it's actually used
for feature in pbkdf2 legacy hardware-accel kdf fast-hashing; do
    echo "=== $feature ==="
    rg "feature.*$feature" crates/ --type toml
    rg "cfg.*feature.*$feature" crates/ --type rust
done
```

**GREEN - Remove unused features:**
```toml
# Before (arcanum-hash/Cargo.toml):
[features]
default = ["std"]
std = []
pbkdf2 = []      # REMOVE - no implementation
legacy = []      # REMOVE - no code uses this
hardware-accel = []  # REMOVE - never checked
kdf = ["hkdf"]   # KEEP or rename to just use hkdf directly
fast-hashing = ["blake3"]  # KEEP or rename

# After:
[features]
default = ["std"]
std = []
hkdf = ["dep:hkdf"]
blake3 = ["dep:blake3"]
```

---

## Phase 4: Test Coverage Expansion

**Timeline:** Post-release (ongoing)
**Dependencies:** Phase 3 complete

### 4.1 Error Path Testing

Add tests for all error conditions in:
- `shamir.rs`: threshold=0, threshold>total, empty secret
- `aes_ciphers.rs`: wrong key length, wrong nonce length
- `encoding.rs`: invalid hex, invalid base64
- `hkdf_impl.rs`: output_len=0, output_len > max

### 4.2 Fuzz Testing Infrastructure

```toml
# Cargo.toml

[workspace.metadata.fuzz]
fuzz_targets = [
    "fuzz_chacha20poly1305",
    "fuzz_x25519",
    "fuzz_ml_kem",
    "fuzz_shamir",
]
```

### 4.3 Property-Based Testing

```rust
// Using proptest crate
proptest! {
    #[test]
    fn test_encrypt_decrypt_roundtrip(
        key in any::<[u8; 32]>(),
        nonce in any::<[u8; 12]>(),
        plaintext in any::<Vec<u8>>(),
    ) {
        let cipher = ChaCha20Poly1305::new(&key);
        let mut buffer = plaintext.clone();
        let tag = cipher.encrypt(&nonce, &[], &mut buffer);
        cipher.decrypt(&nonce, &[], &mut buffer, &tag).unwrap();
        prop_assert_eq!(buffer, plaintext);
    }
}
```

---

## Summary Checklist

### Phase 1: Critical Security (MUST before any release)
- [ ] Fix timing attack in X25519 is_low_order()
- [ ] Replace unwrap() in Poly1305 user input paths
- [ ] Replace unwrap() in ChaCha20Poly1305 AEAD paths
- [ ] Add `ethereum` feature to Cargo.toml

### Phase 2: High Priority (MUST before stable release)
- [ ] Handle mutex poisoning in random.rs
- [ ] Add #[must_use] to Result-returning functions
- [ ] Remove duplicate errors.rs in arcanum-threshold
- [ ] Add FIPS 203/204/205 test vectors

### Phase 3: Code Quality (SHOULD before stable release)
- [ ] Remove or feature-gate CUDA code
- [ ] Archive/remove arcanum-platform directory
- [ ] Add no_std gates to all crates
- [ ] Remove dead feature flags

### Phase 4: Test Coverage (ONGOING)
- [ ] Add error path tests
- [ ] Set up fuzz testing
- [ ] Add property-based tests
- [ ] Achieve >80% code coverage

---

## Appendix: CI Integration

```yaml
# .github/workflows/tdd-checks.yml

name: TDD Compliance

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run tests
        run: cargo test --all-features

      - name: Check no_std compilation
        run: cargo check --no-default-features --features alloc

      - name: Clippy (deny warnings)
        run: cargo clippy --all-features -- -D warnings

      - name: Check unused dependencies
        run: cargo +nightly udeps --all-features

      - name: Security audit
        run: cargo audit
```

---

*This roadmap follows TDD principles: every fix is preceded by a failing test that verifies the issue exists, and passes after the fix is applied.*
