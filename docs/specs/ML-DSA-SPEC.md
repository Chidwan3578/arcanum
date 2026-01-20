# ML-DSA Implementation Specification

**Version**: 1.0.0
**Status**: Draft
**Target**: arcanum-pqc native implementation
**Standard**: FIPS 204 (Module-Lattice-Based Digital Signature Standard)
**Date**: 2026-01-20

---

## 1. Executive Summary

This specification defines the native implementation of ML-DSA (Module-Lattice-Based Digital Signature Algorithm) for the Arcanum cryptography library. ML-DSA is standardized in FIPS 204 and provides post-quantum security based on the hardness of the Module Learning With Errors (M-LWE) problem.

### 1.1 Why Native Implementation?

- **Dependency Independence**: Eliminates reliance on external crates with potential API instability (see: ml-dsa rand_core version conflicts)
- **Performance Control**: Enables SIMD optimization for NTT operations using Arcanum's existing infrastructure
- **Consistency**: Follows established patterns from SLH-DSA native implementation
- **AVX2/AVX-512 Optimization**: Direct control over vectorized polynomial arithmetic

### 1.2 Security Properties

- **Post-Quantum Secure**: Security based on M-LWE and M-SIS hardness
- **NIST Level 2/3/5**: Three security levels covering 128/192/256-bit security
- **EUF-CMA Secure**: Existentially Unforgeable under Adaptive Chosen Message Attack
- **Deterministic/Randomized**: Supports both signing modes

### 1.3 Comparison with SLH-DSA

| Property | ML-DSA | SLH-DSA |
|----------|--------|---------|
| Assumption | Lattice (M-LWE) | Hash functions |
| Signature Size | Small (~2-5 KB) | Large (~8-50 KB) |
| Sign Speed | Fast | Slow |
| Verify Speed | Fast | Fast |
| Key Size | Medium | Small |
| Maturity | Well-studied | Very conservative |

### 1.4 Prerequisites

**BLOCKING DEPENDENCY**: This implementation requires SHAKE128/SHAKE256 primitives.

| Prerequisite | Location | Status | Spec |
|--------------|----------|--------|------|
| SHAKE128 | arcanum-primitives | **NOT IMPLEMENTED** | [SHAKE-SPEC.md](./SHAKE-SPEC.md) |
| SHAKE256 | arcanum-primitives | **NOT IMPLEMENTED** | [SHAKE-SPEC.md](./SHAKE-SPEC.md) |

ML-DSA uses SHAKE (SHA-3 XOF) extensively for:
- **ExpandA**: Generating public matrix A (SHAKE128)
- **ExpandS**: Sampling secret vectors (SHAKE256)
- **ExpandMask**: Generating masking polynomials (SHAKE256)
- **H/G functions**: Domain-separated hashing (SHAKE256)
- **SampleInBall**: Sampling challenge polynomial (SHAKE256)

**Implementation Order**:
1. Implement SHAKE128/SHAKE256 in arcanum-primitives (see SHAKE-SPEC.md)
2. Add feature flag `shake` to arcanum-primitives
3. Update arcanum-pqc dependency on arcanum-primitives
4. Proceed with ML-DSA Green Phase

---

## 2. Algorithm Overview

### 2.1 FIPS 204 Structure

ML-DSA operates over polynomial rings and uses Fiat-Shamir with Aborts:

```
ML-DSA Signature Scheme
┌────────────────────────────────────────────────────────────────┐
│                     Key Generation                              │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ (A, t) ← KeyGen(seed)                                     │  │
│  │   A: public matrix in R_q^(k×l)                          │  │
│  │   t: public vector = As₁ + s₂                             │  │
│  │   (s₁, s₂): secret vectors with small coefficients        │  │
│  └──────────────────────────────────────────────────────────┘  │
├────────────────────────────────────────────────────────────────┤
│                        Signing                                  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ σ = (z, h, c̃) ← Sign(sk, msg)                             │  │
│  │   1. Sample masking vector y                              │  │
│  │   2. Compute w = Ay                                       │  │
│  │   3. Compute challenge c = H(msg || w₁)                   │  │
│  │   4. Compute z = y + cs₁                                  │  │
│  │   5. If ||z||∞ ≥ γ₁ - β, restart (rejection sampling)    │  │
│  │   6. Compute hint h for reconstruction                    │  │
│  └──────────────────────────────────────────────────────────┘  │
├────────────────────────────────────────────────────────────────┤
│                      Verification                               │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ {0,1} ← Verify(pk, msg, σ)                                │  │
│  │   1. Recompute w' = Az - ct                               │  │
│  │   2. Use hint h to recover w₁'                            │  │
│  │   3. Verify c = H(msg || w₁')                             │  │
│  │   4. Check ||z||∞ < γ₁ - β                                │  │
│  └──────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────┘
```

### 2.2 Core Mathematical Objects

#### Polynomial Ring R_q
- R = Z[X] / (X^256 + 1): Polynomial ring with 256 coefficients
- q = 8380417: Prime modulus (q ≡ 1 mod 512 for efficient NTT)
- Coefficients in [-q/2, q/2) using centered representation

#### Module Structure
- Public matrix A ∈ R_q^(k×l)
- Secret vectors s₁ ∈ R_q^l, s₂ ∈ R_q^k with small coefficients
- Dimensions (k, l) vary by security level

### 2.3 Parameter Sets (FIPS 204)

| Parameter | ML-DSA-44 | ML-DSA-65 | ML-DSA-87 |
|-----------|-----------|-----------|-----------|
| Security Level | NIST 2 (128-bit) | NIST 3 (192-bit) | NIST 5 (256-bit) |
| n | 256 | 256 | 256 |
| q | 8380417 | 8380417 | 8380417 |
| (k, l) | (4, 4) | (6, 5) | (8, 7) |
| η | 2 | 4 | 2 |
| β | 78 | 196 | 120 |
| γ₁ | 2^17 | 2^19 | 2^19 |
| γ₂ | (q-1)/88 | (q-1)/32 | (q-1)/32 |
| τ | 39 | 49 | 60 |
| d | 13 | 13 | 13 |
| PK Size | 1312 bytes | 1952 bytes | 2592 bytes |
| SK Size | 2560 bytes | 4032 bytes | 4896 bytes |
| Sig Size | 2420 bytes | 3309 bytes | 4627 bytes |

---

## 3. Module Structure

### 3.1 File Organization

```
crates/arcanum-pqc/src/
├── ml_dsa/
│   ├── mod.rs              # Public API, re-exports
│   ├── params.rs           # Parameter set definitions
│   ├── ntt.rs              # Number Theoretic Transform
│   ├── poly.rs             # Polynomial arithmetic
│   ├── packing.rs          # Bit packing/unpacking
│   ├── sampling.rs         # Rejection sampling, ExpandA, etc.
│   ├── rounding.rs         # Power2Round, Decompose, MakeHint
│   ├── keygen.rs           # Key generation
│   ├── sign.rs             # Signing algorithm
│   ├── verify.rs           # Verification algorithm
│   ├── hash.rs             # H, G, ExpandA, ExpandS, ExpandMask
│   └── tests/
│       ├── mod.rs
│       ├── kat_vectors.rs  # NIST Known Answer Tests
│       ├── ntt_tests.rs
│       ├── poly_tests.rs
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
              ┌─────────┼─────────┐
              │         │         │
              ▼         ▼         ▼
         ┌─────────┐ ┌─────────┐ ┌──────────┐
         │ sampling│ │rounding │ │ packing  │
         └────┬────┘ └────┬────┘ └────┬─────┘
              │           │           │
              └───────────┼───────────┘
                          │
                    ┌─────┴─────┐
                    │           │
                    ▼           ▼
               ┌────────┐  ┌────────┐
               │  poly  │  │  hash  │
               └───┬────┘  └───┬────┘
                   │           │
                   ▼           │
               ┌────────┐      │
               │  ntt   │      │
               └───┬────┘      │
                   │           │
                   └─────┬─────┘
                         │
                         ▼
                  ┌────────────┐
                  │ primitives │ ──► SHAKE128, SHAKE256
                  └────────────┘
```

---

## 4. API Design

### 4.1 Public Types

```rust
/// ML-DSA signing key (private key)
pub struct MlDsaSigningKey<P: MlDsaParams> {
    rho: [u8; 32],           // Public seed for A
    key: [u8; 32],           // Key for signing randomness
    tr: [u8; 64],            // Hash of public key
    s1: PolyVec<P::L>,       // Secret vector s₁
    s2: PolyVec<P::K>,       // Secret vector s₂
    t0: PolyVec<P::K>,       // Low bits of t
    _params: PhantomData<P>,
}

/// ML-DSA verifying key (public key)
pub struct MlDsaVerifyingKey<P: MlDsaParams> {
    rho: [u8; 32],           // Public seed for A
    t1: PolyVec<P::K>,       // High bits of t
    _params: PhantomData<P>,
}

/// ML-DSA signature
pub struct MlDsaSignature<P: MlDsaParams> {
    c_tilde: [u8; P::LAMBDA / 4], // Commitment hash
    z: PolyVec<P::L>,             // Masking response
    h: HintVec<P::K>,             // Hint for reconstruction
    _params: PhantomData<P>,
}

/// Single polynomial in R_q
pub struct Poly {
    coeffs: [i32; 256],
}

/// Vector of polynomials
pub struct PolyVec<const N: usize> {
    polys: [Poly; N],
}
```

### 4.2 Trait Definitions

```rust
/// Parameter set trait - compile-time constants
pub trait MlDsaParams: Clone + 'static {
    /// Dimension k (rows)
    const K: usize;

    /// Dimension l (columns)
    const L: usize;

    /// Small coefficient bound η
    const ETA: usize;

    /// Rejection bound β
    const BETA: u32;

    /// Masking range γ₁
    const GAMMA1: u32;

    /// Decomposition divisor γ₂
    const GAMMA2: u32;

    /// Challenge weight τ
    const TAU: usize;

    /// Dropped bits d
    const D: usize;

    /// Security level λ in bits (128, 192, or 256)
    const LAMBDA: usize;

    /// Public key size in bytes
    const PK_SIZE: usize;

    /// Secret key size in bytes
    const SK_SIZE: usize;

    /// Signature size in bytes
    const SIG_SIZE: usize;

    /// Algorithm identifier
    const ALGORITHM: &'static str;
}

/// Main signature interface
pub trait MlDsa<P: MlDsaParams>: PostQuantumSignature {
    fn generate_keypair() -> (MlDsaSigningKey<P>, MlDsaVerifyingKey<P>);
    fn sign(sk: &MlDsaSigningKey<P>, message: &[u8]) -> MlDsaSignature<P>;
    fn verify(vk: &MlDsaVerifyingKey<P>, message: &[u8], sig: &MlDsaSignature<P>) -> Result<()>;
}
```

### 4.3 Type Aliases

```rust
// Parameter set markers
pub struct Params44;  // ML-DSA-44 (NIST Level 2)
pub struct Params65;  // ML-DSA-65 (NIST Level 3)
pub struct Params87;  // ML-DSA-87 (NIST Level 5)

// Convenience aliases
pub type MlDsa44 = MlDsa<Params44>;
pub type MlDsa65 = MlDsa<Params65>;
pub type MlDsa87 = MlDsa<Params87>;
```

---

## 5. Core Algorithms

### 5.1 Number Theoretic Transform (NTT)

The NTT is the performance-critical operation. For q = 8380417:

```rust
/// Root of unity: ζ = 1753 (primitive 512th root of unity mod q)
const ZETA: i32 = 1753;

/// NTT domain representation
impl Poly {
    /// Forward NTT: coefficient → NTT domain
    pub fn ntt(&mut self) {
        // Cooley-Tukey butterfly, bit-reversed order
        // 7 layers for n=256
    }

    /// Inverse NTT: NTT domain → coefficient
    pub fn inv_ntt(&mut self) {
        // Gentleman-Sande butterfly
        // Multiply by n^(-1) mod q at the end
    }

    /// Pointwise multiplication in NTT domain
    pub fn pointwise_mul(&self, other: &Poly) -> Poly {
        // Element-wise multiplication mod q
    }
}
```

### 5.2 Polynomial Arithmetic

```rust
impl Poly {
    /// Add two polynomials
    pub fn add(&self, other: &Poly) -> Poly;

    /// Subtract two polynomials
    pub fn sub(&self, other: &Poly) -> Poly;

    /// Reduce coefficients mod q
    pub fn reduce(&mut self);

    /// Reduce to centered representation [-q/2, q/2)
    pub fn reduce_centered(&mut self);

    /// Check infinity norm bound
    pub fn check_norm(&self, bound: u32) -> bool;
}
```

### 5.3 Sampling Functions

```rust
/// Sample polynomial with coefficients in [-η, η]
pub fn sample_poly_eta<const ETA: usize>(seed: &[u8], nonce: u16) -> Poly;

/// Sample polynomial with coefficients in [0, γ₁)
pub fn sample_poly_gamma1(seed: &[u8], nonce: u16) -> Poly;

/// Expand seed to matrix A using SHAKE128
pub fn expand_a<const K: usize, const L: usize>(rho: &[u8]) -> [[Poly; L]; K];

/// Sample challenge polynomial with τ coefficients in {-1, 1}
pub fn sample_challenge<const TAU: usize>(seed: &[u8]) -> Poly;
```

### 5.4 Rounding Functions

```rust
/// Power2Round: decompose t into (t₁, t₀) where t = t₁·2^d + t₀
pub fn power2round(t: i32) -> (i32, i32);

/// Decompose: decompose r into (r₁, r₀) where r = r₁·α + r₀
pub fn decompose(r: i32, alpha: i32) -> (i32, i32);

/// HighBits: extract high bits after decomposition
pub fn high_bits(r: i32, alpha: i32) -> i32;

/// LowBits: extract low bits after decomposition
pub fn low_bits(r: i32, alpha: i32) -> i32;

/// MakeHint: compute hint for recovering w₁ from w - cs₂
pub fn make_hint(z0: i32, r1: i32, alpha: i32) -> bool;

/// UseHint: recover w₁ using hint
pub fn use_hint(h: bool, r: i32, alpha: i32) -> i32;
```

---

## 6. Hash Functions (FIPS 204 Section 8)

### 6.1 Required Primitives

| Function | Input | Output | Primitive |
|----------|-------|--------|-----------|
| H | arbitrary | 64 bytes | SHAKE256 |
| G | arbitrary | 128 bytes | SHAKE256 |
| ExpandA | rho, indices | Poly | SHAKE128 |
| ExpandS | rho', indices | Poly | SHAKE256 |
| ExpandMask | seed, nonce | Poly | SHAKE256 |
| SampleInBall | seed | Poly (sparse) | SHAKE256 |

### 6.2 Primitive Dependencies

```rust
// Required additions to arcanum-primitives
pub struct Shake128 { ... }
pub struct Shake256 { ... }

impl Shake128 {
    pub fn new() -> Self;
    pub fn update(&mut self, data: &[u8]);
    pub fn finalize_xof(self) -> Shake128Xof;
}

impl Shake128Xof {
    pub fn squeeze(&mut self, out: &mut [u8]);
}
```

**Note**: SHAKE128/SHAKE256 must be added to arcanum-primitives before ML-DSA can be implemented natively.

---

## 7. Performance Targets

### 7.1 Reference Benchmarks

Based on CRYSTALS-Dilithium reference implementation (C, single-threaded):

| Variant | KeyGen | Sign | Verify |
|---------|--------|------|--------|
| ML-DSA-44 | 0.15 ms | 0.5 ms | 0.15 ms |
| ML-DSA-65 | 0.25 ms | 0.8 ms | 0.25 ms |
| ML-DSA-87 | 0.40 ms | 1.1 ms | 0.40 ms |

### 7.2 Arcanum Performance Targets

**Phase 1 Targets** (Pure Rust, no SIMD):

| Variant | KeyGen | Sign | Verify | vs Reference |
|---------|--------|------|--------|--------------|
| ML-DSA-44 | ≤ 0.25 ms | ≤ 0.8 ms | ≤ 0.25 ms | ≤ 1.6x |
| ML-DSA-65 | ≤ 0.40 ms | ≤ 1.3 ms | ≤ 0.40 ms | ≤ 1.6x |
| ML-DSA-87 | ≤ 0.65 ms | ≤ 1.8 ms | ≤ 0.65 ms | ≤ 1.6x |

**Phase 2 Targets** (With AVX2 optimization):

| Variant | KeyGen | Sign | Verify | vs Reference |
|---------|--------|------|--------|--------------|
| ML-DSA-44 | ≤ 0.12 ms | ≤ 0.4 ms | ≤ 0.12 ms | ≤ 0.8x |
| ML-DSA-65 | ≤ 0.20 ms | ≤ 0.6 ms | ≤ 0.20 ms | ≤ 0.8x |
| ML-DSA-87 | ≤ 0.32 ms | ≤ 0.9 ms | ≤ 0.32 ms | ≤ 0.8x |

### 7.3 Memory Targets

| Metric | Target | Notes |
|--------|--------|-------|
| Stack usage (sign) | ≤ 16 KB | Polynomial vectors on stack |
| Stack usage (verify) | ≤ 8 KB | Verification is lighter |
| Heap allocations | 0 | All operations stack-based |

---

## 8. Constant-Time Requirements

### 8.1 Critical Operations

| Operation | Risk | Mitigation |
|-----------|------|------------|
| Secret key access | Key extraction | Use SecretBytes wrapper |
| NTT butterfly | Coefficient-dependent timing | Fixed iteration count |
| Coefficient reduction | Branch on sign | Use constant-time reduction |
| Rejection sampling | Loop count leaks | Bound iterations, constant-time check |
| Hint computation | Branch on comparison | Use constant-time comparison |
| Norm checking | Early exit | Scan all coefficients |

### 8.2 Montgomery Reduction

Use Montgomery arithmetic for constant-time modular reduction:

```rust
const Q: i32 = 8380417;
const QINV: i32 = 58728449;  // q^(-1) mod 2^32

/// Montgomery reduction: compute a·R^(-1) mod q
fn montgomery_reduce(a: i64) -> i32 {
    let t = (a as i32).wrapping_mul(QINV);
    let t = a - (t as i64) * (Q as i64);
    (t >> 32) as i32
}
```

---

## 9. Test Strategy (TDD)

### 9.1 Test Hierarchy

```
Level 1: Unit Tests (per module)
├── ntt_tests         - Forward/inverse NTT, pointwise mul
├── poly_tests        - Add, sub, reduce, norm check
├── sampling_tests    - Uniform, eta, gamma1, challenge
├── rounding_tests    - Power2Round, Decompose, Hint
└── packing_tests     - Bit packing/unpacking

Level 2: Integration Tests
├── keygen_sign_verify_roundtrip
├── invalid_signature_rejection
├── wrong_key_rejection
└── message_modification_detection

Level 3: Known Answer Tests (KATs)
├── NIST ACVP vectors (FIPS 204)
├── CRYSTALS-Dilithium reference vectors
└── Cross-implementation validation

Level 4: Property-Based Tests
├── ntt_inverse_roundtrip (proptest)
├── sign_verify_roundtrip
└── serialization_roundtrip

Level 5: Constant-Time Tests
├── dudect checkpoints
└── valgrind memcheck analysis
```

### 9.2 Critical KAT Tests

```rust
#[test]
fn test_ntt_known_answer() {
    // FIPS 204 test vector for NTT
    let input = [/* known coefficients */];
    let expected = [/* expected NTT output */];

    let mut poly = Poly { coeffs: input };
    poly.ntt();

    assert_eq!(poly.coeffs, expected);
}

#[test]
fn test_keygen_deterministic() {
    // FIPS 204 keygen test vector
    let seed = hex!("...");
    let expected_pk = hex!("...");
    let expected_sk = hex!("...");

    let (pk, sk) = MlDsa65::generate_from_seed(&seed);
    assert_eq!(pk.to_bytes(), expected_pk);
    assert_eq!(sk.to_bytes(), expected_sk);
}
```

---

## 10. Implementation Phases

### Phase 1: SHAKE Primitives (Prerequisite)

**Deliverables**:
- [ ] SHAKE128 in arcanum-primitives
- [ ] SHAKE256 in arcanum-primitives
- [ ] XOF interface for streaming output

**Exit Criteria**:
- Passes NIST SHAKE test vectors
- no_std compatible

### Phase 2: Core Arithmetic

**Deliverables**:
- [ ] `ntt.rs` - Forward/inverse NTT, Montgomery arithmetic
- [ ] `poly.rs` - Polynomial operations
- [ ] Unit tests for NTT correctness

**Exit Criteria**:
- NTT roundtrip: inv_ntt(ntt(p)) = p
- NTT multiplication matches schoolbook

### Phase 3: Sampling and Rounding

**Deliverables**:
- [ ] `sampling.rs` - All sampling functions
- [ ] `rounding.rs` - Power2Round, Decompose, Hint
- [ ] `packing.rs` - Bit packing utilities

**Exit Criteria**:
- Sampling matches reference distribution
- Rounding satisfies FIPS 204 equations

### Phase 4: Full Algorithm

**Deliverables**:
- [ ] `keygen.rs` - Key generation
- [ ] `sign.rs` - Signing with rejection sampling
- [ ] `verify.rs` - Verification
- [ ] `mod.rs` - Public API

**Exit Criteria**:
- Full sign/verify roundtrip
- KAT vectors pass

### Phase 5: Hardening

**Deliverables**:
- [ ] Constant-time audit
- [ ] Memory zeroization
- [ ] Error handling review
- [ ] Documentation

**Exit Criteria**:
- dudect tests pass
- No timing side-channels

### Phase 6: Optimization

**Deliverables**:
- [ ] AVX2 NTT implementation
- [ ] Performance benchmarks
- [ ] Comparison report

**Exit Criteria**:
- Meets Phase 2 performance targets

---

## 11. Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| SHAKE dependency delay | Medium | High | Implement SHAKE first |
| NTT bugs | Medium | High | Extensive KAT testing |
| Constant-time violation | Medium | High | Continuous CT testing |
| Performance miss | Low | Medium | Early benchmarking |
| API inconsistency | Low | Low | Follow SLH-DSA patterns |

---

## 12. Design Decisions

### 12.1 Resolved

1. **SHAKE Implementation**: Add native SHAKE128/256 to arcanum-primitives
   - Required for all ML-DSA operations
   - Enables future SHAKE-based algorithms

2. **Signing Mode**: Default to randomized, deterministic via flag
   - `sign()` = randomized (hedged)
   - `sign_deterministic()` = reproducible (for testing)

3. **no_std Support**: Required from the start
   - Use `alloc` for dynamic allocations if needed
   - Most operations can be fully stack-based

### 12.2 Deferred

4. **Batch Verification**: Defer to optimization phase
   - Assess speedup from batched NTT

5. **AVX2 Implementation**: Phase 6
   - Focus on correctness first

---

## 13. References

1. FIPS 204: Module-Lattice-Based Digital Signature Standard
   https://csrc.nist.gov/pubs/fips/204/final

2. CRYSTALS-Dilithium Specification (Round 3)
   https://pq-crystals.org/dilithium/data/dilithium-specification-round3-20210208.pdf

3. CRYSTALS-Dilithium Reference Implementation
   https://github.com/pq-crystals/dilithium

4. New Hope NTT Implementation Guide
   https://newhopecrypto.org/

5. Arcanum SLH-DSA Specification (for patterns)
   `docs/specs/SLH-DSA-SPEC.md`

---

## Appendix A: NTT Constants

```rust
// Precomputed powers of ζ in bit-reversed order
const ZETAS: [i32; 256] = [
    // ζ^(bit_rev(i)) mod q for i in 0..256
    // Generated from ζ = 1753
];

// Precomputed powers of ζ^(-1) for inverse NTT
const ZETAS_INV: [i32; 256] = [
    // ζ^(-bit_rev(i)) mod q for i in 0..256
];
```

---

## Appendix B: Estimated Lines of Code

| Module | Estimated LOC | Notes |
|--------|---------------|-------|
| params.rs | 100 | Const generics, 3 param sets |
| ntt.rs | 300 | NTT, Montgomery arithmetic |
| poly.rs | 400 | Polynomial operations |
| packing.rs | 250 | Bit packing utilities |
| sampling.rs | 350 | All sampling functions |
| rounding.rs | 200 | Decompose, hints |
| hash.rs | 150 | Hash function wrappers |
| keygen.rs | 200 | Key generation |
| sign.rs | 300 | Signing with rejection |
| verify.rs | 200 | Verification |
| mod.rs | 150 | Public API |
| **Total** | **~2,600** | Excluding tests |
| tests/ | ~1,800 | KATs, unit, integration |
| **Grand Total** | **~4,400** | |

---

*Document Status: Ready for Review*
*Next Step: Approval → SHAKE Implementation → TDD Suite Creation → Red Phase*
*Prerequisite: SHAKE128/SHAKE256 must be added to arcanum-primitives first*
