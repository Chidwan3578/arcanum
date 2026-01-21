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

**STATUS**: All prerequisites are now met. Ready for Green Phase.

| Prerequisite | Location | Status | Spec |
|--------------|----------|--------|------|
| SHAKE128 | arcanum-primitives | ✅ IMPLEMENTED | [SHAKE-SPEC.md](./SHAKE-SPEC.md) |
| SHAKE256 | arcanum-primitives | ✅ IMPLEMENTED | [SHAKE-SPEC.md](./SHAKE-SPEC.md) |

ML-DSA uses SHAKE (SHA-3 XOF) extensively for:
- **ExpandA**: Generating public matrix A (SHAKE128)
- **ExpandS**: Sampling secret vectors (SHAKE256)
- **ExpandMask**: Generating masking polynomials (SHAKE256)
- **H/G functions**: Domain-separated hashing (SHAKE256)
- **SampleInBall**: Sampling challenge polynomial (SHAKE256)

**Implementation Order**:
1. ~~Implement SHAKE128/SHAKE256 in arcanum-primitives~~ ✅ Done
2. ~~Add feature flag `shake` to arcanum-primitives~~ ✅ Done
3. Update arcanum-pqc dependency on arcanum-primitives (add `shake` feature)
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

## 5.5 Key Generation Seed Expansion (FIPS 204 Algorithm 6)

**CRITICAL**: FIPS 204 requires domain separation via K and L parameters in the seed expansion.

```
Input: ξ (32-byte seed)
Output: (ρ, ρ', K) - public seed, secret seed, signing key

1. (ρ, ρ', K) ← H(ξ || K || L)
   - Input to SHAKE256 is EXACTLY 34 bytes: ξ (32 bytes) || K (1 byte) || L (1 byte)
   - K and L are the dimension parameters for the security level
   - Output: 32 + 64 + 32 = 128 bytes squeezed from SHAKE256
```

| Security Level | K | L | Input bytes |
|----------------|---|---|-------------|
| ML-DSA-44 | 4 | 4 | ξ ∥ 0x04 ∥ 0x04 |
| ML-DSA-65 | 6 | 5 | ξ ∥ 0x06 ∥ 0x05 |
| ML-DSA-87 | 8 | 7 | ξ ∥ 0x08 ∥ 0x07 |

**Why this matters for ACVP**: NIST test vectors assume this exact domain separation.
Without appending K and L, the derived keys will differ from NIST KAT vectors.

---

## 5.6 Hint Mechanism (FIPS 204 Algorithms 37-38)

The hint mechanism enables signature compression while allowing verification to recover
the correct high bits for challenge reconstruction.

### 5.6.1 Core Invariants

**Signing produces**: `w₁ = HighBits(w)` where `w = Ay`

**Verification recovers**: `w'₁ = UseHint(h, w')` where `w' = Az - ct₁·2^d`

**Critical relationship**:
```
w' = Az - ct₁·2^d
   = A(y + cs₁) - ct₁·2^d        [since z = y + cs₁]
   = Ay + cAs₁ - ct₁·2^d
   = w + c(t - s₂) - ct₁·2^d     [since As₁ = t - s₂]
   = w + ct - cs₂ - ct₁·2^d
   = w + ct₀ - cs₂               [since t = t₁·2^d + t₀]
```

Therefore: **w' = w - cs₂ + ct₀**

### 5.6.2 MakeHint (Algorithm 37)

```rust
/// MakeHint(z, r, γ₂) → {0, 1}
/// Returns 1 if HighBits(r) ≠ HighBits(r + z), 0 otherwise
fn make_hint(z: i32, r: i32, gamma2: i32) -> bool {
    high_bits(r, gamma2) != high_bits(r + z, gamma2)
}
```

**In signing**: `h = MakeHint(-ct₀, w - cs₂ + ct₀)`
- This checks if `HighBits(w - cs₂ + ct₀) ≠ HighBits(w - cs₂)`

### 5.6.3 UseHint (Algorithm 38)

```rust
/// UseHint(h, r, γ₂) → r₁
/// Recovers HighBits(r + z) from HighBits(r) using hint h
fn use_hint(h: bool, r: i32, gamma2: i32) -> i32 {
    let (r1, r0) = decompose(r, gamma2);

    if !h {
        return r1;  // No correction needed
    }

    // m = (q - 1) / (2γ₂) - 1 (maximum valid r₁ after corner case adjustment)
    let alpha = 2 * gamma2;
    let m = (Q - 1) / alpha - 1;

    // Adjust based on sign of r₀
    if r0 > 0 {
        if r1 == m { 0 } else { r1 + 1 }
    } else {
        if r1 == 0 { m } else { r1 - 1 }
    }
}
```

**Critical**: The value `m = (q-1)/(2γ₂) - 1` accounts for the corner case in Decompose
where `r - r₀ = q - 1` causes `r₁` to wrap to 0.

| Param | γ₂ | Theoretical max | Actual m |
|-------|-----|-----------------|----------|
| ML-DSA-44 | (q-1)/88 | 44 | 43 |
| ML-DSA-65 | (q-1)/32 | 16 | 15 |
| ML-DSA-87 | (q-1)/32 | 16 | 15 |

### 5.6.4 Verification Condition

For verification to succeed, the hint must satisfy:
```
UseHint(h, w') = HighBits(w - cs₂) = HighBits(w) = w₁
```

This equality `HighBits(w - cs₂) = HighBits(w)` is ensured by rejection sampling
in signing, which rejects when `||LowBits(w - cs₂)||∞ ≥ γ₂ - β`.

---

## 5.7 Decompose Corner Case (FIPS 204 Algorithm 36)

The Decompose function has a critical corner case that must be handled correctly:

```rust
fn decompose(r: i32, gamma2: i32) -> (i32, i32) {
    let r = if r < 0 { r + Q } else { r % Q };  // Normalize to [0, q)
    let alpha = 2 * gamma2;

    // Standard decomposition
    let mut r0 = r % alpha;
    if r0 > gamma2 {
        r0 -= alpha;
    }
    let mut r1 = (r - r0) / alpha;

    // CRITICAL CORNER CASE: when r - r₀ = q - 1
    // This happens when r is near q-1 and r₀ would cause r₁ to exceed bounds
    if r - r0 == Q - 1 {
        r1 = 0;
        r0 = r0 - 1;
    }

    (r1, r0)
}
```

**Why this matters**: Without this corner case handling, `r₁` could equal `(q-1)/α`,
which exceeds the valid range `[0, m]` where `m = (q-1)/α - 1`.

---

## 5.8 Verification w' Computation (FIPS 204 Algorithm 3, Step 10)

**CRITICAL**: The w' computation must properly handle reduction to ensure consistency
with the signing algorithm's w computation.

### 5.8.1 Algorithm

```
Input: A (public matrix), z (response), c (challenge), t₁ (public key high bits)
Output: w' (reconstructed commitment)

1. Az ← NTT⁻¹(Â · ẑ)              // Matrix-vector multiply in NTT domain, then inv_ntt
2. ct₁ ← NTT⁻¹(ĉ · t̂₁)           // Challenge times t₁ in NTT domain
3. For each coefficient:
   w'[i] = Az[i] - ct₁[i] · 2^d   // Subtract scaled ct₁
   w'[i] = w'[i] mod⁺ q           // Reduce to [0, q)
```

### 5.8.2 Reduction Consistency

Both signing and verification must use the same reduction for HighBits to match:

| Operation | Domain | Reduction |
|-----------|--------|-----------|
| w = Ay (signing) | After inv_ntt | Reduce to [0, q) |
| w' = Az - ct₁·2^d (verify) | After computation | Reduce to [0, q) |
| HighBits input | Both | Must be in [0, q) |
| UseHint input | Verify only | Must be in [0, q) |

**Failure mode**: If reductions differ, HighBits(w) in signing won't match
UseHint output in verification, causing spurious verification failures.

### 5.8.3 Numerical Stability

The computation `Az - ct₁·2^d` requires care:
- ct₁ coefficients can be in centered form after inv_ntt: [-q/2, q/2]
- Scaled by 2^d = 8192, range becomes ≈ [-34 billion, +34 billion]
- Use 64-bit arithmetic to avoid overflow
- Final reduction must produce values in [0, q)

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
