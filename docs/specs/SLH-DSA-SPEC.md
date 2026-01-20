# SLH-DSA Implementation Specification

**Version**: 1.0.0
**Status**: Draft
**Target**: arcanum-pqc native implementation
**Standard**: FIPS 205 (Stateless Hash-Based Digital Signature Standard)
**Date**: 2025-01-20

---

## 1. Executive Summary

This specification defines the native implementation of SLH-DSA (Stateless Hash-Based Digital Signature Algorithm) for the Arcanum cryptography library. SLH-DSA is standardized in FIPS 205 and provides post-quantum security based solely on the security of hash functions.

### 1.1 Why Native Implementation?

- **Dependency Independence**: Eliminates reliance on external crates with potential API instability (see: ml-dsa/slh-dsa rand_core issues)
- **Performance Control**: Leverages Arcanum's existing optimized SHA-256/SHAKE implementations
- **Consistency**: Follows established patterns in arcanum-primitives
- **SIMD Optimization**: Future path to AVX2/AVX-512 acceleration for batch operations

### 1.2 Security Properties

- **Post-Quantum Secure**: Security relies only on hash function properties (preimage, second-preimage, collision resistance)
- **Conservative Assumptions**: No lattice/number-theoretic assumptions that may be weakened
- **Stateless**: No state management required (unlike XMSS/LMS)
- **EUF-CMA Secure**: Existentially Unforgeable under Adaptive Chosen Message Attack

---

## 2. Algorithm Overview

### 2.1 FIPS 205 Structure

SLH-DSA combines three components in a hypertree structure:

```
┌─────────────────────────────────────────────────────────────┐
│                      SLH-DSA Signature                       │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────┐                                                │
│  │  FORS   │  Few-time signature (signs message digest)     │
│  └────┬────┘                                                │
│       │ authenticates                                        │
│       ▼                                                      │
│  ┌─────────┐                                                │
│  │  XMSS   │  Merkle tree layer (d layers in hypertree)     │
│  │  Tree   │  Each layer signs the root of layer below      │
│  └────┬────┘                                                │
│       │ uses                                                 │
│       ▼                                                      │
│  ┌─────────┐                                                │
│  │  WOTS+  │  One-time signature at each tree node          │
│  └─────────┘                                                │
└─────────────────────────────────────────────────────────────┘
```

### 2.2 Component Descriptions

#### WOTS+ (Winternitz One-Time Signature Plus)
- Winternitz parameter w ∈ {4, 16, 256}
- Chains hash values using iterative hashing
- Signs a single message hash
- One-time use only (security degrades with reuse)

#### XMSS (eXtended Merkle Signature Scheme)
- Binary hash tree structure
- Height h' determines capacity (2^h' signatures per tree)
- Leaves are WOTS+ public keys
- Authentication path proves leaf membership

#### FORS (Forest of Random Subsets)
- k trees, each of height a
- Signs message by revealing k leaves (one per tree)
- Few-time signature (can sign multiple messages with degraded security)

#### Hypertree
- d layers of XMSS trees
- Total height: h = d × h'
- Top layer contains the root public key
- Each layer authenticates the layer below

### 2.3 Parameter Sets (FIPS 205)

| Parameter Set | Security | n | h | d | h' | a | k | w | Sig Size | PK Size | SK Size |
|---------------|----------|---|---|---|----|---|---|---|----------|---------|---------|
| SLH-DSA-SHA2-128s | 128-bit | 16 | 63 | 7 | 9 | 12 | 14 | 16 | 7,856 | 32 | 64 |
| SLH-DSA-SHA2-128f | 128-bit | 16 | 66 | 22 | 3 | 6 | 33 | 16 | 17,088 | 32 | 64 |
| SLH-DSA-SHA2-192s | 192-bit | 24 | 63 | 7 | 9 | 14 | 17 | 16 | 16,224 | 48 | 96 |
| SLH-DSA-SHA2-192f | 192-bit | 24 | 66 | 22 | 3 | 8 | 33 | 16 | 35,664 | 48 | 96 |
| SLH-DSA-SHA2-256s | 256-bit | 32 | 64 | 8 | 8 | 14 | 22 | 16 | 29,792 | 64 | 128 |
| SLH-DSA-SHA2-256f | 256-bit | 32 | 68 | 17 | 4 | 9 | 35 | 16 | 49,856 | 64 | 128 |
| SLH-DSA-SHAKE-128s | 128-bit | 16 | 63 | 7 | 9 | 12 | 14 | 16 | 7,856 | 32 | 64 |
| SLH-DSA-SHAKE-128f | 128-bit | 16 | 66 | 22 | 3 | 6 | 33 | 16 | 17,088 | 32 | 64 |
| SLH-DSA-SHAKE-192s | 192-bit | 24 | 63 | 7 | 9 | 14 | 17 | 16 | 16,224 | 48 | 96 |
| SLH-DSA-SHAKE-192f | 192-bit | 24 | 66 | 22 | 3 | 8 | 33 | 16 | 35,664 | 48 | 96 |
| SLH-DSA-SHAKE-256s | 256-bit | 32 | 64 | 8 | 8 | 14 | 22 | 16 | 29,792 | 64 | 128 |
| SLH-DSA-SHAKE-256f | 256-bit | 32 | 68 | 17 | 4 | 9 | 35 | 16 | 49,856 | 64 | 128 |

**Variant Naming**:
- `s` = "small" signature, slower signing
- `f` = "fast" signing, larger signature
- `SHA2` = Uses SHA-256 as hash function
- `SHAKE` = Uses SHAKE256 as hash function

### 2.4 Recommended Variants for Initial Implementation

**Phase 1** (MVP):
- `SLH-DSA-SHA2-128f` - Fast signing, uses existing SHA-256
- `SLH-DSA-SHA2-128s` - Small signatures, uses existing SHA-256

**Phase 2** (Full Coverage):
- All SHA2 variants (leverage optimized SHA-256)
- SHAKE variants (requires SHAKE256 implementation or addition)

---

## 3. Module Structure

### 3.1 File Organization

```
crates/arcanum-pqc/src/
├── slh_dsa/
│   ├── mod.rs              # Public API, re-exports
│   ├── params.rs           # Parameter set definitions
│   ├── address.rs          # ADRS (address) scheme
│   ├── wots.rs             # WOTS+ implementation
│   ├── xmss.rs             # XMSS tree operations
│   ├── fors.rs             # FORS implementation
│   ├── hypertree.rs        # Hypertree construction
│   ├── hash.rs             # Hash function abstractions (Hmsg, PRF, etc.)
│   ├── keygen.rs           # Key generation
│   ├── sign.rs             # Signing algorithm
│   ├── verify.rs           # Verification algorithm
│   └── tests/
│       ├── mod.rs
│       ├── kat_vectors.rs  # NIST Known Answer Tests
│       ├── wots_tests.rs
│       ├── xmss_tests.rs
│       ├── fors_tests.rs
│       └── integration.rs
```

### 3.2 Dependency Graph

```
                    ┌──────────┐
                    │  mod.rs  │  (Public API)
                    └────┬─────┘
                         │
         ┌───────────────┼───────────────┐
         │               │               │
         ▼               ▼               ▼
    ┌─────────┐    ┌──────────┐    ┌──────────┐
    │ keygen  │    │   sign   │    │  verify  │
    └────┬────┘    └────┬─────┘    └────┬─────┘
         │              │               │
         └──────────────┼───────────────┘
                        │
                        ▼
                 ┌─────────────┐
                 │  hypertree  │
                 └──────┬──────┘
                        │
              ┌─────────┼─────────┐
              │         │         │
              ▼         ▼         ▼
         ┌────────┐ ┌────────┐ ┌────────┐
         │  xmss  │ │  fors  │ │ address│
         └───┬────┘ └───┬────┘ └────────┘
             │          │
             ▼          │
         ┌────────┐     │
         │  wots  │◄────┘
         └───┬────┘
             │
             ▼
         ┌────────┐
         │  hash  │ ──► arcanum-primitives (SHA-256)
         └────────┘
```

---

## 4. API Design

### 4.1 Public Types

```rust
// Key types with proper security properties
pub struct SlhDsaSigningKey<P: SlhDsaParams> {
    sk_seed: SecretBytes<{P::N}>,    // Secret seed
    sk_prf: SecretBytes<{P::N}>,     // PRF key for randomness
    pk_seed: [u8; P::N],             // Public seed
    pk_root: [u8; P::N],             // Root of hypertree
    _params: PhantomData<P>,
}

pub struct SlhDsaVerifyingKey<P: SlhDsaParams> {
    pk_seed: [u8; P::N],
    pk_root: [u8; P::N],
    _params: PhantomData<P>,
}

pub struct SlhDsaSignature<P: SlhDsaParams> {
    randomness: [u8; P::N],          // R
    fors_sig: ForsSig<P>,            // FORS signature
    ht_sig: HypertreeSig<P>,         // Hypertree signature
}

// Parameter set marker types
pub struct Sha2_128s;
pub struct Sha2_128f;
pub struct Sha2_192s;
pub struct Sha2_192f;
pub struct Sha2_256s;
pub struct Sha2_256f;
```

### 4.2 Trait Definitions

```rust
/// Parameter set trait - compile-time constants
pub trait SlhDsaParams: Clone + 'static {
    /// Security parameter (bytes): 16, 24, or 32
    const N: usize;

    /// Total tree height
    const H: usize;

    /// Number of hypertree layers
    const D: usize;

    /// Height of each XMSS tree (H / D)
    const H_PRIME: usize;

    /// FORS tree height
    const A: usize;

    /// Number of FORS trees
    const K: usize;

    /// Winternitz parameter (16 for all FIPS 205 sets)
    const W: usize;

    /// Algorithm name for identification
    const ALGORITHM: &'static str;

    /// Security level in bits
    const SECURITY_LEVEL: usize;

    /// Signature size in bytes
    const SIG_SIZE: usize;

    /// Public key size in bytes
    const PK_SIZE: usize;

    /// Secret key size in bytes
    const SK_SIZE: usize;
}

/// Main signature trait (implements arcanum's PostQuantumSignature)
impl<P: SlhDsaParams> PostQuantumSignature for SlhDsa<P> {
    type SigningKey = SlhDsaSigningKey<P>;
    type VerifyingKey = SlhDsaVerifyingKey<P>;
    type Signature = SlhDsaSignature<P>;

    fn generate_keypair() -> (Self::SigningKey, Self::VerifyingKey);
    fn sign(sk: &Self::SigningKey, message: &[u8]) -> Self::Signature;
    fn verify(vk: &Self::VerifyingKey, message: &[u8], sig: &Self::Signature) -> Result<()>;
}
```

### 4.3 Convenience Type Aliases

```rust
// SHA-2 based (recommended for initial release)
pub type SlhDsaSha2_128s = SlhDsa<Sha2_128s>;
pub type SlhDsaSha2_128f = SlhDsa<Sha2_128f>;
pub type SlhDsaSha2_192s = SlhDsa<Sha2_192s>;
pub type SlhDsaSha2_192f = SlhDsa<Sha2_192f>;
pub type SlhDsaSha2_256s = SlhDsa<Sha2_256s>;
pub type SlhDsaSha2_256f = SlhDsa<Sha2_256f>;

// Convenience re-export for recommended variant
pub type SlhDsa128f = SlhDsaSha2_128f;
pub type SlhDsa128s = SlhDsaSha2_128s;
```

---

## 5. Performance Targets

### 5.1 Reference Benchmarks

Based on SPHINCS+ reference implementation (C, single-threaded, Intel i7-6700):

| Variant | KeyGen | Sign | Verify |
|---------|--------|------|--------|
| SHA2-128s | 5.0 ms | 120 ms | 4.5 ms |
| SHA2-128f | 0.4 ms | 8.5 ms | 0.5 ms |
| SHA2-192s | 8.0 ms | 200 ms | 7.5 ms |
| SHA2-192f | 0.6 ms | 14 ms | 0.8 ms |
| SHA2-256s | 15 ms | 350 ms | 12 ms |
| SHA2-256f | 1.0 ms | 22 ms | 1.2 ms |

### 5.2 Arcanum Performance Targets

**Phase 1 Targets** (Pure Rust, no SIMD):

| Variant | KeyGen | Sign | Verify | vs Reference |
|---------|--------|------|--------|--------------|
| SHA2-128s | ≤ 6.0 ms | ≤ 150 ms | ≤ 5.5 ms | ≤ 1.2x |
| SHA2-128f | ≤ 0.5 ms | ≤ 10 ms | ≤ 0.6 ms | ≤ 1.2x |

**Phase 2 Targets** (With SIMD optimization):

| Variant | KeyGen | Sign | Verify | vs Reference |
|---------|--------|------|--------|--------------|
| SHA2-128s | ≤ 4.0 ms | ≤ 100 ms | ≤ 3.5 ms | ≤ 0.8x |
| SHA2-128f | ≤ 0.3 ms | ≤ 7 ms | ≤ 0.4 ms | ≤ 0.8x |

**Rationale**: SLH-DSA is hash-bound. Arcanum's SHA-256 with SHA-NI achieves ~1.2 GiB/s. SIMD batch hashing can further improve throughput for WOTS+ chain computations.

### 5.3 Memory Targets

| Metric | Target | Notes |
|--------|--------|-------|
| Stack usage (sign) | ≤ 32 KB | Avoid heap in hot paths |
| Stack usage (verify) | ≤ 16 KB | Verification should be lean |
| Heap allocations (sign) | ≤ 3 | For signature buffer only |
| Heap allocations (verify) | 0 | Fully stack-based verification |

---

## 6. Arcanum Primitive Dependencies

### 6.1 Required Primitives

| Primitive | Source | Usage |
|-----------|--------|-------|
| SHA-256 | `arcanum-primitives::sha2::Sha256` | Primary hash (SHA2 variants) |
| HMAC-SHA256 | `arcanum-primitives` (to add) | PRF_msg construction |
| MGF1-SHA256 | `arcanum-primitives` (to add) | Mask generation |

### 6.2 New Primitives Required

```rust
// Required additions to arcanum-primitives or arcanum-hash

/// HMAC-SHA256 (RFC 2104)
pub struct HmacSha256 {
    // ...
}

impl HmacSha256 {
    pub fn new(key: &[u8]) -> Self;
    pub fn update(&mut self, data: &[u8]);
    pub fn finalize(self) -> [u8; 32];
    pub fn mac(key: &[u8], data: &[u8]) -> [u8; 32];
}

/// MGF1 with SHA-256 (RFC 8017)
pub fn mgf1_sha256(seed: &[u8], length: usize) -> Vec<u8>;
```

### 6.3 Internal Hash Functions (FIPS 205 Section 10)

```rust
/// Hash function abstractions for SLH-DSA
pub trait SlhDsaHash {
    /// H_msg: Message hash
    fn h_msg(r: &[u8], pk_seed: &[u8], pk_root: &[u8], m: &[u8]) -> Vec<u8>;

    /// PRF: Pseudorandom function
    fn prf(pk_seed: &[u8], sk_seed: &[u8], adrs: &Address) -> Vec<u8>;

    /// PRF_msg: Message randomness
    fn prf_msg(sk_prf: &[u8], opt_rand: &[u8], m: &[u8]) -> Vec<u8>;

    /// F: Chaining function for WOTS+
    fn f(pk_seed: &[u8], adrs: &Address, m: &[u8]) -> Vec<u8>;

    /// H: Tree hash
    fn h(pk_seed: &[u8], adrs: &Address, m1: &[u8], m2: &[u8]) -> Vec<u8>;

    /// T_l: l-node hash (WOTS+ public key compression)
    fn t_l(pk_seed: &[u8], adrs: &Address, m: &[u8]) -> Vec<u8>;
}
```

---

## 7. Constant-Time Requirements

### 7.1 Critical Operations

The following operations MUST be constant-time to prevent timing side-channels:

| Operation | Risk | Mitigation |
|-----------|------|------------|
| Secret key access | Key extraction | Use `SecretBytes` wrapper |
| WOTS+ chain computation | Chain length leaks message | Fixed iteration count |
| FORS leaf selection | Reveals message bits | Constant-time indexing |
| Tree traversal | Path reveals index | Fixed traversal pattern |
| Signature serialization | Length variations | Fixed-size output |

### 7.2 Audit Checkpoints

```rust
// Each checkpoint must pass dudect analysis

#[cfg(test)]
mod constant_time_tests {
    use dudect_bencher::{ctbench_main, BenchRng, Class, CtRunner};

    // Checkpoint 1: WOTS+ chain computation
    fn wots_chain_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
        // Verify chain computation time independent of input
    }

    // Checkpoint 2: FORS signing
    fn fors_sign_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
        // Verify signing time independent of message
    }

    // Checkpoint 3: Tree traversal
    fn tree_traversal_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
        // Verify traversal time independent of path
    }

    // Checkpoint 4: Full signing
    fn sign_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
        // End-to-end signing constant-time check
    }
}
```

### 7.3 Constant-Time Primitives to Use

From `arcanum-primitives::ct`:
- `CtEq` for secret comparisons
- `CtSelect` for conditional selection
- `CtBool` for branching decisions

---

## 8. Test Strategy (TDD)

### 8.1 Test Hierarchy

```
Level 1: Unit Tests (per module)
├── address_tests     - ADRS encoding/decoding
├── wots_tests        - WOTS+ chain, keygen, sign, verify
├── xmss_tests        - Tree construction, auth paths
├── fors_tests        - FORS keygen, sign, verify
└── hypertree_tests   - Multi-layer tree operations

Level 2: Integration Tests
├── keygen_sign_verify_roundtrip
├── invalid_signature_rejection
├── wrong_key_rejection
└── message_modification_detection

Level 3: Known Answer Tests (KATs)
├── NIST ACVP vectors (when available)
├── SPHINCS+ reference vectors
└── Cross-implementation validation

Level 4: Property-Based Tests
├── sign_verify_roundtrip (proptest)
├── signature_uniqueness
└── key_independence

Level 5: Constant-Time Tests
├── dudect checkpoints (see 7.2)
└── valgrind memcheck analysis
```

### 8.2 KAT Vector Sources

1. **NIST CAVP** (primary): Official test vectors when released
2. **SPHINCS+ Reference**: https://sphincs.org/data/sphincs+-r3.1-specification.pdf
3. **PQCrypto-SIGN**: Reference implementation test vectors

### 8.3 Test File Structure

```rust
// crates/arcanum-pqc/src/slh_dsa/tests/kat_vectors.rs

/// NIST Known Answer Test vectors for SLH-DSA-SHA2-128f
#[test]
fn kat_sha2_128f_sign_verify() {
    let test_vectors = include_str!("../../../test-vectors/slh-dsa-sha2-128f.json");
    let vectors: Vec<KatVector> = serde_json::from_str(test_vectors).unwrap();

    for v in vectors {
        let sk = SlhDsaSigningKey::<Sha2_128f>::from_bytes(&v.sk);
        let vk = SlhDsaVerifyingKey::<Sha2_128f>::from_bytes(&v.pk);

        let sig = SlhDsaSha2_128f::sign(&sk, &v.message);
        assert_eq!(sig.to_bytes(), v.expected_signature);

        assert!(SlhDsaSha2_128f::verify(&vk, &v.message, &sig).is_ok());
    }
}
```

---

## 9. Implementation Phases

### Phase 1: Foundation (Target: 2 weeks effort)

**Deliverables**:
- [ ] `params.rs` - All parameter set definitions
- [ ] `address.rs` - ADRS scheme implementation
- [ ] `hash.rs` - Hash function abstractions for SHA2
- [ ] `wots.rs` - Complete WOTS+ implementation
- [ ] Unit tests for above modules
- [ ] KAT vectors for WOTS+

**Exit Criteria**:
- All WOTS+ unit tests pass
- WOTS+ matches reference implementation output

### Phase 2: Tree Structures (Target: 2 weeks effort)

**Deliverables**:
- [ ] `xmss.rs` - XMSS tree implementation
- [ ] `fors.rs` - FORS implementation
- [ ] `hypertree.rs` - Hypertree construction
- [ ] Unit tests for tree operations

**Exit Criteria**:
- Tree construction matches reference
- Auth path verification works

### Phase 3: Full Algorithm (Target: 1 week effort)

**Deliverables**:
- [ ] `keygen.rs` - Key generation
- [ ] `sign.rs` - Signing algorithm
- [ ] `verify.rs` - Verification
- [ ] `mod.rs` - Public API
- [ ] Integration tests

**Exit Criteria**:
- Full sign/verify roundtrip works
- All KAT vectors pass

### Phase 4: Hardening (Target: 1 week effort)

**Deliverables**:
- [ ] Constant-time audit (dudect)
- [ ] Memory zeroization verification
- [ ] Error handling review
- [ ] Documentation

**Exit Criteria**:
- All dudect checkpoints pass
- No secret data in error messages
- API documentation complete

### Phase 5: Optimization (Target: 2 weeks effort)

**Deliverables**:
- [ ] SIMD acceleration for batch hashing
- [ ] Performance benchmarks
- [ ] Comparison vs reference implementation

**Exit Criteria**:
- Meets Phase 2 performance targets
- Benchmark report published

---

## 10. Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| NIST spec ambiguity | Low | Medium | Reference SPHINCS+ impl |
| Performance miss | Medium | Medium | Early benchmarking in Phase 3 |
| Constant-time violation | Medium | High | Continuous dudect testing |
| SHAKE256 dependency | Medium | Low | Phase 1 uses SHA2 only |
| API inconsistency | Low | Medium | Follow existing arcanum patterns |

---

## 11. Design Decisions (Resolved)

1. **SHAKE256 Support**: ✅ Add native implementation to arcanum-primitives
   - Maintains zero external crypto dependencies philosophy
   - Enables SHAKE variants for full FIPS 205 coverage

2. **Deterministic vs Randomized Signing**: ✅ Default to randomized, deterministic via flag
   - Randomized: Better for production (hedged signatures)
   - Deterministic: Available via `sign_deterministic()` for testing/debugging
   - API: `sign()` = randomized, `sign_deterministic()` = reproducible

3. **no_std Support**: ✅ Required for v1
   - Design with `#![no_std]` from the start
   - Use `alloc` for dynamic allocations
   - Feature flag: `std` for std-dependent functionality

### 11.1 Deferred Decisions

4. **Batch Verification API**: Defer to Phase 5
   - Profile single verification first
   - Assess if batch provides meaningful speedup

---

## 12. References

1. FIPS 205: Stateless Hash-Based Digital Signature Standard
   https://csrc.nist.gov/pubs/fips/205/final

2. SPHINCS+ Specification (Round 3.1)
   https://sphincs.org/data/sphincs+-r3.1-specification.pdf

3. SPHINCS+ Reference Implementation
   https://github.com/sphincs/sphincsplus

4. Arcanum Primitives Documentation
   `crates/arcanum-primitives/src/lib.rs`

---

## Appendix A: ADRS Structure

```
ADRS (Address) - 32 bytes total
┌────────────────────────────────────────────────────────────┐
│ Bytes 0-3   │ Layer address (hypertree layer)              │
│ Bytes 4-11  │ Tree address (tree index within layer)       │
│ Bytes 12-15 │ Type (0=WOTS, 1=WOTS_PRF, 2=TREE, 3=FORS...) │
│ Bytes 16-31 │ Type-specific fields                         │
└────────────────────────────────────────────────────────────┘

Type-specific fields vary by address type:
- WOTS_HASH:     keypair_addr(4), chain_addr(4), hash_addr(4), padding(4)
- WOTS_PK:       keypair_addr(4), padding(12)
- TREE:          padding(4), tree_height(4), tree_index(4), padding(4)
- FORS_TREE:     keypair_addr(4), tree_height(4), tree_index(4), padding(4)
- FORS_ROOTS:    keypair_addr(4), padding(12)
```

---

## Appendix B: Estimated Lines of Code

| Module | Estimated LOC | Notes |
|--------|---------------|-------|
| params.rs | 150 | Const generics, 6 param sets |
| address.rs | 200 | ADRS types and encoding |
| hash.rs | 250 | Hash abstractions |
| wots.rs | 400 | Chain computation, keygen, sign |
| xmss.rs | 350 | Tree construction, auth paths |
| fors.rs | 300 | FORS trees and signatures |
| hypertree.rs | 300 | Multi-layer coordination |
| keygen.rs | 150 | Key pair generation |
| sign.rs | 200 | Signing algorithm |
| verify.rs | 150 | Verification algorithm |
| mod.rs | 100 | Public API |
| **Total** | **~2,550** | Excluding tests |
| tests/ | ~1,500 | KATs, unit, integration |
| **Grand Total** | **~4,050** | |

---

*Document Status: Ready for Review*
*Next Step: Approval → TDD Suite Creation → Red Phase*
