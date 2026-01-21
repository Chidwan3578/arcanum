//! Arcanum-DSA Parameter Sets
//!
//! SIMD-optimized parameters for Arcanum-DSA variants.
//! All L values are multiples of 4 for efficient 4-way SIMD batching.
//!
//! These parameters implement `MlDsaParams` for compatibility with the
//! existing ML-DSA keygen/sign/verify implementation.

use crate::ml_dsa::params::MlDsaParams;

/// Ring dimension (fixed for all variants)
pub const N: usize = 256;

/// Modulus q = 2²³ - 2¹³ + 1 = 8380417 (same as ML-DSA)
pub const Q: i32 = 8380417;

/// Trait defining Arcanum-DSA parameter sets
///
/// # Invariants (verified by tests)
///
/// - `L % 4 == 0` (SIMD batching requirement)
/// - `N * (K + L) >= ML_DSA_DIMENSION` (security equivalence)
/// - `GAMMA1` is power of 2 (efficient sampling)
/// - `BETA = TAU * ETA` (rejection bound)
/// - `OMEGA` bounds hint weight
pub trait ArcanumDsaParams: Clone + Send + Sync + 'static {
    /// Number of rows in matrix A (public key dimension)
    const K: usize;

    /// Number of columns in matrix A (secret key dimension)
    /// INVARIANT: Must be multiple of 4 for SIMD optimization
    const L: usize;

    /// Secret coefficient bound: coefficients in [-η, η]
    const ETA: usize;

    /// Challenge polynomial weight (number of ±1 coefficients)
    const TAU: usize;

    /// Rejection bound β = τ·η
    const BETA: u32;

    /// Gamma1: range for masking polynomial y
    const GAMMA1: u32;

    /// Gamma2: low-order rounding range
    const GAMMA2: u32;

    /// Maximum hint weight
    const OMEGA: usize;

    /// Commitment hash length in bytes
    const LAMBDA: usize;

    /// Equivalent ML-DSA dimension for security comparison
    const ML_DSA_EQUIVALENT_DIM: usize;

    /// Actual dimension N×(K+L)
    const DIMENSION: usize = N * (Self::K + Self::L);

    /// Security margin: how much larger our dimension is
    const SECURITY_MARGIN_PERCENT: usize =
        (Self::DIMENSION * 100 / Self::ML_DSA_EQUIVALENT_DIM) - 100;
}

/// Arcanum-DSA-44: NIST Level 2 equivalent
///
/// Identical to ML-DSA-44 (L=4 already optimal for SIMD)
///
/// # Security
/// - Dimension: 2048 (same as ML-DSA-44)
/// - Security level: NIST Level 2 (~128-bit classical)
#[derive(Clone, Copy, Debug)]
pub struct Params44;

impl ArcanumDsaParams for Params44 {
    const K: usize = 4;
    const L: usize = 4;  // Already SIMD-optimal
    const ETA: usize = 2;
    const TAU: usize = 39;
    const BETA: u32 = 78;  // TAU * ETA
    const GAMMA1: u32 = 1 << 17;  // 2^17
    const GAMMA2: u32 = (Q as u32 - 1) / 88;
    const OMEGA: usize = 80;
    const LAMBDA: usize = 32;  // 256 bits
    const ML_DSA_EQUIVALENT_DIM: usize = 2048;  // 256 * (4+4)
}

// Implement MlDsaParams for Params44 (identical to ML-DSA-44)
impl MlDsaParams for Params44 {
    const K: usize = 4;
    const L: usize = 4;
    const ETA: usize = 2;
    const BETA: u32 = 78;
    const GAMMA1: u32 = 1 << 17;
    const GAMMA2: u32 = (Q as u32 - 1) / 88;
    const TAU: usize = 39;
    const LAMBDA: usize = 128;  // bits
    const OMEGA: usize = 80;
    const PK_SIZE: usize = 1312;   // 32 + 4×320
    const SK_SIZE: usize = 2560;   // 32 + 32 + 64 + 4×96 + 4×96 + 4×416
    const SIG_SIZE: usize = 2420;  // 32 + 4×576 + 84
    const ALGORITHM: &'static str = "Arcanum-DSA-44";
    const SECURITY_LEVEL: usize = 2;
}

/// Arcanum-DSA-65: NIST Level 3 equivalent (SIMD-optimized)
///
/// Modified from ML-DSA-65: K=6,L=5 → K=7,L=4
///
/// # Security
/// - ML-DSA-65 dimension: 2816 (256 × 11)
/// - Arcanum-65 dimension: 2816 (256 × 11) - SAME!
/// - Security margin: 0% (identical dimension)
///
/// # SIMD Benefit
/// - expand_mask: 1 full batch of 4 (was 1 batch + 1 leftover)
/// - L REDUCED from 5 to 4 (-20% work in expand_mask!)
/// - expand_a: 7 batches of 4 (K×L=28, perfectly divisible)
///
/// # Trade-offs
/// - Smaller signatures (L=4 vs L=5): 2670 bytes vs 3309 bytes (-19%)
/// - Larger public key (K=7 vs K=6): 2272 bytes vs 1952 bytes (+16%)
#[derive(Clone, Copy, Debug)]
pub struct Params65;

impl ArcanumDsaParams for Params65 {
    const K: usize = 7;
    const L: usize = 4;  // SIMD-optimized (down from 5!)
    const ETA: usize = 4;
    const TAU: usize = 49;
    const BETA: u32 = 196;  // TAU * ETA
    const GAMMA1: u32 = 1 << 19;  // 2^19
    const GAMMA2: u32 = (Q as u32 - 1) / 32;
    const OMEGA: usize = 55;
    const LAMBDA: usize = 48;  // 384 bits
    const ML_DSA_EQUIVALENT_DIM: usize = 2816;  // 256 * (6+5)
}

// Implement MlDsaParams for Params65 (K=7, L=4 variant)
impl MlDsaParams for Params65 {
    const K: usize = 7;
    const L: usize = 4;
    const ETA: usize = 4;
    const BETA: u32 = 196;
    const GAMMA1: u32 = 1 << 19;
    const GAMMA2: u32 = (Q as u32 - 1) / 32;
    const TAU: usize = 49;
    const LAMBDA: usize = 192;  // bits (48 bytes)
    const OMEGA: usize = 55;
    // PK: ρ (32) + t₁ (K×320) = 32 + 7×320 = 2272
    const PK_SIZE: usize = 2272;
    // SK: ρ (32) + K (32) + tr (64) + s₁ (L×128) + s₂ (K×128) + t₀ (K×416)
    //   = 32 + 32 + 64 + 4×128 + 7×128 + 7×416 = 4448
    const SK_SIZE: usize = 4448;
    // SIG: c̃ (48) + z (L×640) + h (ω+K) = 48 + 4×640 + 62 = 2670
    const SIG_SIZE: usize = 2670;
    const ALGORITHM: &'static str = "Arcanum-DSA-65";
    const SECURITY_LEVEL: usize = 3;
}

/// Arcanum-DSA-87: NIST Level 5 equivalent (SIMD-optimized)
///
/// Modified from ML-DSA-87: K=8,L=7 → K=8,L=8
///
/// # Security
/// - ML-DSA-87 dimension: 3840 (256 × 15)
/// - Arcanum-87 dimension: 4096 (256 × 16)
/// - Security margin: +7% over ML-DSA-87
///
/// # SIMD Benefit
/// - expand_mask: 2 full batches of 4 (was 1 batch + 3 leftover)
/// - expand_a: 16 batches of 4 (was ~14 with uneven distribution)
#[derive(Clone, Debug)]
pub struct Params87;

impl ArcanumDsaParams for Params87 {
    const K: usize = 8;
    const L: usize = 8;  // SIMD-optimized (was 7)
    const ETA: usize = 2;
    const TAU: usize = 60;
    const BETA: u32 = 120;  // TAU * ETA
    const GAMMA1: u32 = 1 << 19;  // 2^19
    const GAMMA2: u32 = (Q as u32 - 1) / 32;
    const OMEGA: usize = 75;
    const LAMBDA: usize = 64;  // 512 bits
    const ML_DSA_EQUIVALENT_DIM: usize = 3840;  // 256 * (8+7)
}

// Implement MlDsaParams for Params87 (K=8, L=8 variant)
impl MlDsaParams for Params87 {
    const K: usize = 8;
    const L: usize = 8;
    const ETA: usize = 2;
    const BETA: u32 = 120;
    const GAMMA1: u32 = 1 << 19;
    const GAMMA2: u32 = (Q as u32 - 1) / 32;
    const TAU: usize = 60;
    const LAMBDA: usize = 256;  // bits (64 bytes)
    const OMEGA: usize = 75;
    // PK: ρ (32) + t₁ (K×320) = 32 + 8×320 = 2592
    const PK_SIZE: usize = 2592;
    // SK: ρ (32) + K (32) + tr (64) + s₁ (L×96) + s₂ (K×96) + t₀ (K×416)
    //   = 32 + 32 + 64 + 8×96 + 8×96 + 8×416 = 4992
    const SK_SIZE: usize = 4992;
    // SIG: c̃ (64) + z (L×640) + h (ω+K) = 64 + 8×640 + 83 = 5267
    const SIG_SIZE: usize = 5267;
    const ALGORITHM: &'static str = "Arcanum-DSA-87";
    const SECURITY_LEVEL: usize = 5;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Compile-time parameter validation
// ═══════════════════════════════════════════════════════════════════════════════

/// Compile-time assertion helper
const fn const_assert(condition: bool, _msg: &str) {
    if !condition {
        panic!("Compile-time assertion failed");
    }
}

/// Validate parameters at compile time
const fn validate_params<P: ArcanumDsaParams>() {
    // SIMD optimization: L must be multiple of 4
    const_assert(P::L % 4 == 0, "L must be multiple of 4 for SIMD");

    // Security: dimension must meet or exceed ML-DSA equivalent
    const_assert(
        P::DIMENSION >= P::ML_DSA_EQUIVALENT_DIM,
        "Dimension must meet ML-DSA security level"
    );

    // Rejection bound consistency
    const_assert(
        P::BETA == (P::TAU * P::ETA) as u32,
        "BETA must equal TAU * ETA"
    );

    // Gamma1 must be power of 2 for efficient sampling
    const_assert(
        P::GAMMA1.is_power_of_two(),
        "GAMMA1 must be power of 2"
    );
}

// Trigger compile-time validation for all parameter sets
const _: () = validate_params::<Params44>();
const _: () = validate_params::<Params65>();
const _: () = validate_params::<Params87>();
