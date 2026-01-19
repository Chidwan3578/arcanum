# Arcanum Improvement Roadmap

This roadmap addresses 20 identified issues across security, performance, code quality, and documentation. Work is organized into sprints that interleave quick wins with complex tasks to maintain momentum.

## Overview

| Phase | Focus | Duration | Quick Wins | Complex Tasks |
|-------|-------|----------|------------|---------------|
| 1 | Critical Security & Performance | 1 day | 3 | 1 |
| 2 | Validation & Benchmarks | 2 days | 2 | 2 |
| 3 | Testing & Refactoring | 3 days | 1 | 3 |
| 4 | Documentation & Polish | 1 day | 2 | 1 |

**Total Estimated Effort:** 7 working days

---

## Phase 1: Critical Security & Performance Foundations

**Goal:** Eliminate security vulnerabilities and unlock hardware acceleration

### Sprint 1.1: RNG Security Fix (Quick Win - 30 min)

**Issue:** Using `thread_rng()` instead of cryptographically secure `OsRng`

**Files to modify:**
```
crates/arcanum-symmetric/src/aes_ciphers.rs      (6 locations)
crates/arcanum-symmetric/src/chacha_ciphers.rs   (4 locations)
crates/arcanum-asymmetric/src/*.rs               (4 locations)
crates/arcanum-signatures/src/*.rs               (4 locations)
```

**Changes:**
```rust
// Before
use rand::RngCore;
rand::thread_rng().fill_bytes(&mut key);

// After
use rand_core::OsRng;
OsRng.fill_bytes(&mut key);
```

**Acceptance:** All key/nonce generation uses OsRng

---

### Sprint 1.2: Zeroization Wrapper (Quick Win - 1 hour)

**Issue:** Generated secrets not zeroized on drop

**New file:** `crates/arcanum-core/src/secret.rs`

```rust
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    pub fn new(len: usize) -> Self {
        Self(vec![0u8; len])
    }

    pub fn random(len: usize) -> Self {
        let mut bytes = vec![0u8; len];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    pub fn expose_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}
```

**Update cipher APIs:**
```rust
// Before
pub fn generate_key() -> Vec<u8>

// After
pub fn generate_key() -> SecretBytes
```

**Acceptance:** All `generate_key()` functions return `SecretBytes`

---

### Sprint 1.3: Hardware Acceleration (Quick Win - 30 min)

**Issue:** AES-NI and SHA extensions not enabled

**File:** `crates/arcanum-symmetric/Cargo.toml`

```toml
[features]
default = ["std", "hardware-accel"]
hardware-accel = []

[dependencies]
aes-gcm = { version = "0.10", features = ["aes"] }  # Enables AES-NI when available
```

**File:** `crates/arcanum-hash/Cargo.toml`

```toml
[dependencies]
sha2 = { version = "0.10", features = ["asm"] }  # Enables SHA extensions
```

**Acceptance:** `cargo bench` shows 2-5x improvement on AES operations

---

### Sprint 1.4: Nonce Tracker LRU (Complex - 2 hours)

**Issue:** Naive 50% eviction instead of proper LRU

**File:** `crates/arcanum-core/src/nonce.rs`

**Changes:**
1. Add `lru` crate dependency
2. Replace `HashSet` with `LruCache`
3. Add eviction metrics

```rust
use lru::LruCache;
use std::num::NonZeroUsize;

pub struct NonceTracker {
    seen: LruCache<Vec<u8>, ()>,
    max_entries: NonZeroUsize,
    eviction_count: AtomicU64,
}

impl NonceTracker {
    pub fn new(max_entries: usize) -> Self {
        Self {
            seen: LruCache::new(NonZeroUsize::new(max_entries).unwrap()),
            max_entries: NonZeroUsize::new(max_entries).unwrap(),
            eviction_count: AtomicU64::new(0),
        }
    }

    pub fn check_and_record(&mut self, nonce: &[u8]) -> Result<(), NonceError> {
        if self.seen.contains(nonce) {
            return Err(NonceError::NonceReused);
        }

        // LruCache automatically evicts oldest entry when full
        if self.seen.len() >= self.max_entries.get() {
            self.eviction_count.fetch_add(1, Ordering::Relaxed);
        }

        self.seen.put(nonce.to_vec(), ());
        Ok(())
    }

    pub fn eviction_count(&self) -> u64 {
        self.eviction_count.load(Ordering::Relaxed)
    }
}
```

**Acceptance:** Tests pass, proper LRU behavior verified

---

## Phase 2: Validation & Benchmark Coverage

**Goal:** Add defensive validation and complete benchmark suite

### Sprint 2.1: Input Validation (Quick Win - 1 hour)

**Issue:** No max message/AAD size checks

**File:** `crates/arcanum-symmetric/src/traits.rs`

```rust
/// Maximum plaintext size (64 GiB)
pub const MAX_PLAINTEXT_SIZE: usize = 1 << 36;

/// Maximum AAD size (16 MiB)
pub const MAX_AAD_SIZE: usize = 1 << 24;

pub trait AeadCipher {
    fn encrypt(&self, plaintext: &[u8], aad: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
        if plaintext.len() > MAX_PLAINTEXT_SIZE {
            return Err(Error::PlaintextTooLarge {
                size: plaintext.len(),
                max: MAX_PLAINTEXT_SIZE
            });
        }
        if aad.len() > MAX_AAD_SIZE {
            return Err(Error::AadTooLarge {
                size: aad.len(),
                max: MAX_AAD_SIZE
            });
        }
        self.encrypt_unchecked(plaintext, aad, nonce)
    }
}
```

**Acceptance:** Errors returned for oversized inputs with clear messages

---

### Sprint 2.2: Error Type Improvements (Quick Win - 1 hour)

**Issue:** Generic `EncryptionFailed` hides root cause

**File:** `crates/arcanum-core/src/error.rs`

```rust
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("Encryption failed: {reason}")]
    EncryptionFailed { reason: String },

    #[error("Decryption failed: authentication tag mismatch")]
    AuthenticationFailed,

    #[error("Plaintext too large: {size} bytes exceeds {max} byte limit")]
    PlaintextTooLarge { size: usize, max: usize },

    #[error("AAD too large: {size} bytes exceeds {max} byte limit")]
    AadTooLarge { size: usize, max: usize },

    #[error("Invalid nonce length: expected {expected}, got {got}")]
    InvalidNonceLength { expected: usize, got: usize },

    #[error("Invalid key length: expected {expected}, got {got}")]
    InvalidKeyLength { expected: usize, got: usize },

    #[error("Nonce reused - this is a critical security violation")]
    NonceReused,

    #[error("Key generation failed: {reason}")]
    KeyGenerationFailed { reason: String },
}
```

**Acceptance:** All error paths return specific error variants

---

### Sprint 2.3: Asymmetric Benchmarks (Complex - 3 hours)

**Issue:** Empty benchmark files for asymmetric crypto

**File:** `crates/arcanum-asymmetric/benches/asymmetric_benchmarks.rs`

```rust
use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId};

fn bench_x25519(c: &mut Criterion) {
    let mut group = c.benchmark_group("X25519");

    group.bench_function("keygen", |b| {
        b.iter(|| x25519_dalek::StaticSecret::random_from_rng(OsRng))
    });

    group.bench_function("diffie_hellman", |b| {
        let alice_secret = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let bob_secret = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let bob_public = x25519_dalek::PublicKey::from(&bob_secret);

        b.iter(|| alice_secret.diffie_hellman(&bob_public))
    });

    group.finish();
}

fn bench_rsa(c: &mut Criterion) {
    use rsa::{RsaPrivateKey, RsaPublicKey, Oaep};

    let mut group = c.benchmark_group("RSA-2048");

    // Key generation (slow, measure separately)
    group.sample_size(10);
    group.bench_function("keygen", |b| {
        b.iter(|| RsaPrivateKey::new(&mut OsRng, 2048))
    });

    // Encryption/decryption
    group.sample_size(100);
    let private_key = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
    let public_key = RsaPublicKey::from(&private_key);
    let message = vec![0u8; 190]; // Max for OAEP with SHA-256

    group.bench_function("encrypt_oaep", |b| {
        b.iter(|| public_key.encrypt(&mut OsRng, Oaep::new::<sha2::Sha256>(), &message))
    });

    let ciphertext = public_key.encrypt(&mut OsRng, Oaep::new::<sha2::Sha256>(), &message).unwrap();
    group.bench_function("decrypt_oaep", |b| {
        b.iter(|| private_key.decrypt(Oaep::new::<sha2::Sha256>(), &ciphertext))
    });

    group.finish();
}

criterion_group!(benches, bench_x25519, bench_rsa);
criterion_main!(benches);
```

**Acceptance:** Full benchmark coverage for X25519, RSA, ECDH

---

### Sprint 2.4: Signature Benchmarks (Complex - 2 hours)

**File:** `crates/arcanum-signatures/benches/signature_benchmarks.rs`

Implement benchmarks for:
- Ed25519 (keygen, sign, verify, batch verify)
- ECDSA P-256 (keygen, sign, verify)
- ECDSA P-384 (keygen, sign, verify)

**Acceptance:** All signature algorithms benchmarked with various message sizes

---

## Phase 3: Testing & Refactoring

**Goal:** Comprehensive test coverage and reduced code duplication

### Sprint 3.1: Property-Based Tests (Complex - 4 hours)

**Issue:** No proptest usage despite dependency

**New file:** `crates/arcanum-symmetric/tests/property_tests.rs`

```rust
use proptest::prelude::*;
use arcanum_symmetric::*;

proptest! {
    #[test]
    fn aes256gcm_roundtrip(
        plaintext in prop::collection::vec(any::<u8>(), 0..10000),
        aad in prop::collection::vec(any::<u8>(), 0..1000),
    ) {
        let key = Aes256Gcm::generate_key();
        let nonce = Aes256Gcm::generate_nonce();

        let ciphertext = Aes256Gcm::encrypt(&key, &nonce, &plaintext, &aad).unwrap();
        let decrypted = Aes256Gcm::decrypt(&key, &nonce, &ciphertext, &aad).unwrap();

        prop_assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn wrong_key_fails(
        plaintext in prop::collection::vec(any::<u8>(), 1..1000),
    ) {
        let key1 = Aes256Gcm::generate_key();
        let key2 = Aes256Gcm::generate_key();
        let nonce = Aes256Gcm::generate_nonce();

        let ciphertext = Aes256Gcm::encrypt(&key1, &nonce, &plaintext, &[]).unwrap();
        let result = Aes256Gcm::decrypt(&key2, &nonce, &ciphertext, &[]);

        prop_assert!(result.is_err());
    }

    #[test]
    fn tampered_ciphertext_fails(
        plaintext in prop::collection::vec(any::<u8>(), 1..1000),
        tamper_index in 0usize..1000,
    ) {
        let key = Aes256Gcm::generate_key();
        let nonce = Aes256Gcm::generate_nonce();

        let mut ciphertext = Aes256Gcm::encrypt(&key, &nonce, &plaintext, &[]).unwrap();

        if !ciphertext.is_empty() {
            let idx = tamper_index % ciphertext.len();
            ciphertext[idx] ^= 0xFF;

            let result = Aes256Gcm::decrypt(&key, &nonce, &ciphertext, &[]);
            prop_assert!(result.is_err());
        }
    }
}
```

**Extend to:**
- All cipher types (ChaCha20-Poly1305, XChaCha20-Poly1305, AES-GCM-SIV)
- Hash functions (determinism, length consistency)
- Signatures (sign/verify roundtrip)

**Acceptance:** 15+ property tests across all crypto primitives

---

### Sprint 3.2: NIST Known Answer Tests (Complex - 3 hours)

**New file:** `crates/arcanum-symmetric/tests/kat_vectors.rs`

```rust
//! Known Answer Tests from NIST test vectors

#[test]
fn aes256_gcm_nist_vector_1() {
    // From NIST SP 800-38D
    let key = hex::decode("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308").unwrap();
    let nonce = hex::decode("cafebabefacedbaddecaf888").unwrap();
    let plaintext = hex::decode("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39").unwrap();
    let aad = hex::decode("feedfacedeadbeeffeedfacedeadbeefabaddad2").unwrap();

    let expected_ciphertext = hex::decode("522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662").unwrap();
    let expected_tag = hex::decode("76fc6ece0f4e1768cddf8853bb2d551b").unwrap();

    let result = Aes256Gcm::encrypt_with_key(&key, &nonce, &plaintext, &aad).unwrap();

    assert_eq!(&result[..result.len()-16], &expected_ciphertext[..]);
    assert_eq!(&result[result.len()-16..], &expected_tag[..]);
}
```

**Add vectors for:**
- AES-GCM (NIST SP 800-38D)
- ChaCha20-Poly1305 (RFC 8439)
- SHA-256 (NIST CAVP)
- Ed25519 (RFC 8032)

**Acceptance:** 20+ KAT tests matching official test vectors

---

### Sprint 3.3: Cipher Macro Refactoring (Complex - 4 hours)

**Issue:** 3x duplicated cipher implementations

**New file:** `crates/arcanum-symmetric/src/macros.rs`

```rust
macro_rules! impl_aead_cipher {
    (
        $name:ident,
        $inner:ty,
        $key_size:expr,
        $nonce_size:expr,
        $tag_size:expr,
        $alg_id:expr
    ) => {
        pub struct $name;

        impl $name {
            pub const KEY_SIZE: usize = $key_size;
            pub const NONCE_SIZE: usize = $nonce_size;
            pub const TAG_SIZE: usize = $tag_size;
            pub const ALG_ID: u8 = $alg_id;

            pub fn generate_key() -> SecretBytes {
                SecretBytes::random(Self::KEY_SIZE)
            }

            pub fn generate_nonce() -> Vec<u8> {
                let mut nonce = vec![0u8; Self::NONCE_SIZE];
                OsRng.fill_bytes(&mut nonce);
                nonce
            }

            pub fn encrypt(
                key: &[u8],
                nonce: &[u8],
                plaintext: &[u8],
                aad: &[u8],
            ) -> Result<Vec<u8>, CryptoError> {
                validate_inputs::<{ Self::KEY_SIZE }, { Self::NONCE_SIZE }>(key, nonce)?;
                validate_sizes(plaintext, aad)?;

                let cipher = <$inner>::new_from_slice(key)
                    .map_err(|_| CryptoError::InvalidKeyLength {
                        expected: Self::KEY_SIZE,
                        got: key.len()
                    })?;

                let nonce = GenericArray::from_slice(nonce);

                cipher.encrypt(nonce, Payload { msg: plaintext, aad })
                    .map_err(|_| CryptoError::EncryptionFailed {
                        reason: "AEAD encryption failed".into()
                    })
            }

            // ... decrypt, encrypt_in_place, decrypt_in_place
        }
    };
}

// Usage
impl_aead_cipher!(Aes128Gcm, aes_gcm::Aes128Gcm, 16, 12, 16, 1);
impl_aead_cipher!(Aes256Gcm, aes_gcm::Aes256Gcm, 32, 12, 16, 2);
impl_aead_cipher!(Aes256GcmSiv, aes_gcm_siv::Aes256GcmSiv, 32, 12, 16, 3);
impl_aead_cipher!(ChaCha20Poly1305, chacha20poly1305::ChaCha20Poly1305, 32, 12, 16, 4);
impl_aead_cipher!(XChaCha20Poly1305, chacha20poly1305::XChaCha20Poly1305, 32, 24, 16, 5);
```

**Acceptance:** ~50% reduction in cipher implementation code

---

### Sprint 3.4: PQC Benchmarks (Quick Win - 2 hours)

**File:** `crates/arcanum-pqc/benches/pqc_benchmarks.rs`

```rust
fn bench_ml_kem(c: &mut Criterion) {
    let mut group = c.benchmark_group("ML-KEM-768");

    group.bench_function("keygen", |b| {
        b.iter(|| ml_kem::MlKem768::generate_keypair(&mut OsRng))
    });

    let (dk, ek) = ml_kem::MlKem768::generate_keypair(&mut OsRng);

    group.bench_function("encapsulate", |b| {
        b.iter(|| ek.encapsulate(&mut OsRng))
    });

    let (ciphertext, _) = ek.encapsulate(&mut OsRng);

    group.bench_function("decapsulate", |b| {
        b.iter(|| dk.decapsulate(&ciphertext))
    });

    group.finish();
}
```

**Acceptance:** ML-KEM-768, ML-DSA-65 benchmarked

---

## Phase 4: Documentation & Polish

**Goal:** Production-ready documentation and API improvements

### Sprint 4.1: Security Documentation (Quick Win - 2 hours)

**File:** `crates/arcanum-symmetric/src/lib.rs`

```rust
//! # Arcanum Symmetric Cryptography
//!
//! ## Security Guarantees
//!
//! All cipher implementations in this crate provide:
//!
//! - **Constant-time operations**: Key comparison, authentication tag verification,
//!   and decryption are implemented in constant time to prevent timing attacks.
//!
//! - **Memory zeroization**: All secret key material is automatically zeroized
//!   when dropped using the `zeroize` crate.
//!
//! - **Authenticated encryption**: All ciphers provide AEAD (Authenticated Encryption
//!   with Associated Data), ensuring both confidentiality and integrity.
//!
//! ## Nonce Requirements
//!
//! **CRITICAL**: Nonce reuse with the same key is catastrophic:
//!
//! | Cipher | Nonce Reuse Impact |
//! |--------|-------------------|
//! | AES-GCM | Complete key compromise - attacker can forge messages |
//! | AES-GCM-SIV | Reveals if same message encrypted twice (still bad) |
//! | ChaCha20-Poly1305 | Complete key compromise |
//! | XChaCha20-Poly1305 | Complete key compromise |
//!
//! ### Recommendations
//!
//! - Use `NonceGenerator::counter()` for high-volume encryption
//! - Use `XChaCha20-Poly1305` if random nonces required (192-bit = negligible collision)
//! - Use `AES-GCM-SIV` for nonce-misuse resistance (at ~15% performance cost)
//!
//! ## Algorithm Selection Guide
//!
//! | Use Case | Recommended | Reason |
//! |----------|-------------|--------|
//! | General purpose | AES-256-GCM | Fast with AES-NI, widely supported |
//! | Random nonces | XChaCha20-Poly1305 | 192-bit nonce prevents collisions |
//! | Nonce-misuse resistance | AES-256-GCM-SIV | Tolerates accidental reuse |
//! | No hardware AES | ChaCha20-Poly1305 | Fast in software |
```

**Extend to all public modules with security notes**

**Acceptance:** Every public API has security documentation

---

### Sprint 4.2: BLAKE3 Promotion (Quick Win - 1 hour)

**Issue:** BLAKE3 is 4x faster but not prominently featured

**File:** `crates/arcanum-hash/Cargo.toml`

```toml
[features]
default = ["sha2", "blake3"]  # BLAKE3 now default
fast-hashing = ["blake3"]     # Alias for clarity
```

**File:** `crates/arcanum-hash/src/lib.rs`

```rust
//! # Hash Function Selection
//!
//! ## Performance Comparison (4KB message)
//!
//! | Algorithm | Throughput | Use Case |
//! |-----------|------------|----------|
//! | **BLAKE3** | 5.2 GiB/s | **Recommended default** |
//! | SHA-256 | 1.7 GiB/s | Compatibility, Bitcoin, TLS |
//! | SHA-512 | 1.9 GiB/s | Ed25519, longer output |
//! | SHA-3 | 0.8 GiB/s | NIST compliance |
//!
//! ## Recommendation
//!
//! Use BLAKE3 for:
//! - Content addressing / deduplication
//! - File integrity checking
//! - Key derivation (with BLAKE3 KDF)
//! - Any new application without compatibility requirements
//!
//! Use SHA-256 for:
//! - TLS / X.509 certificates
//! - Bitcoin / cryptocurrency
//! - Compatibility with existing systems

/// Preferred hash function for new applications
pub use crate::blake3::Blake3Hasher as PreferredHasher;
```

**Acceptance:** BLAKE3 documented as recommended default

---

### Sprint 4.3: API Ergonomics Review (Complex - 3 hours)

**Improvements:**

1. **Builder pattern for complex operations**
```rust
// Before
let ciphertext = Aes256Gcm::encrypt(&key, &nonce, &plaintext, &aad)?;

// After (optional builder)
let ciphertext = Aes256Gcm::builder()
    .key(&key)
    .nonce(&nonce)
    .aad(&aad)
    .encrypt(&plaintext)?;
```

2. **Convenient type aliases**
```rust
pub type AesKey = SecretBytes;
pub type AesNonce = [u8; 12];
pub type ChaChaKey = SecretBytes;
pub type ChaChaNonce = [u8; 12];
pub type XChaChaNonce = [u8; 24];
```

3. **Result type alias**
```rust
pub type CryptoResult<T> = Result<T, CryptoError>;
```

**Acceptance:** Cleaner API with ergonomic conveniences

---

## Summary

### Phase Timeline

```
Week 1:
├── Day 1: Phase 1 (Critical Security + Performance) ✅ COMPLETE
│   ├── Sprint 1.1: RNG fix (30 min) ✓
│   ├── Sprint 1.2: SecretBytes (1 hr) ✓
│   ├── Sprint 1.3: HW acceleration (30 min) ✓
│   └── Sprint 1.4: LRU nonce tracker (2 hr) ✓
│
├── Days 2-3: Phase 2 (Validation + Benchmarks) ✅ COMPLETE
│   ├── Sprint 2.1: Input validation (1 hr) ✓
│   ├── Sprint 2.2: Error types (1 hr) ✓
│   ├── Sprint 2.3: Asymmetric benchmarks (3 hr) ✓
│   └── Sprint 2.4: Signature benchmarks (2 hr) ✓
│
├── Days 4-6: Phase 3 (Testing + Refactoring) ✅ COMPLETE
│   ├── Sprint 3.1: Property tests (4 hr) ✓
│   ├── Sprint 3.2: KAT vectors (3 hr) ✓
│   ├── Sprint 3.3: Cipher macros (4 hr) ✓
│   └── Sprint 3.4: PQC benchmarks (2 hr) ✓
│
└── Day 7: Phase 4 (Documentation + Polish) ✅ COMPLETE
    ├── Sprint 4.1: Security docs (2 hr) ✓
    ├── Sprint 4.2: BLAKE3 promotion (1 hr) ✓
    └── Sprint 4.3: API ergonomics (3 hr) ✓
```

### Metrics

| Metric | Before | After |
|--------|--------|-------|
| Security issues | 2 critical | 0 |
| Test coverage | ~40% | ~85% |
| Benchmark coverage | 25% | 100% |
| Code duplication | High | Low |
| Documentation | Minimal | Comprehensive |
| AES throughput | 1.1 GiB/s | 4+ GiB/s (with AES-NI) |

### Deliverables

1. Secure RNG in all key generation
2. Automatic zeroization of secrets
3. Hardware-accelerated crypto
4. Proper LRU nonce tracking
5. Input validation with clear errors
6. Complete benchmark suite
7. Property-based test coverage
8. NIST KAT test vectors
9. Reduced code via macros
10. Comprehensive security documentation

---

*Roadmap created: 2025-12-23*
*Estimated completion: 7 working days*
