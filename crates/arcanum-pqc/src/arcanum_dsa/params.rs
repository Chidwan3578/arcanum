//! Arcanum-DSA Parameter Sets
//!
//! SIMD-optimized parameters for Arcanum-DSA variants.
//! All L values are multiples of 4 for efficient 4-way SIMD batching.

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
#[derive(Clone, Debug)]
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

/// Arcanum-DSA-65: NIST Level 3 equivalent (SIMD-optimized)
///
/// Modified from ML-DSA-65: K=6,L=5 → K=4,L=8
///
/// # Security
/// - ML-DSA-65 dimension: 2816 (256 × 11)
/// - Arcanum-65 dimension: 3072 (256 × 12)
/// - Security margin: +9% over ML-DSA-65
///
/// # SIMD Benefit
/// - expand_mask: 2 full batches of 4 (was 1 batch + 1 leftover)
/// - expand_a: 8 batches of 4 (was ~8 batches with uneven distribution)
#[derive(Clone, Debug)]
pub struct Params65;

impl ArcanumDsaParams for Params65 {
    const K: usize = 4;
    const L: usize = 8;  // SIMD-optimized (was 5)
    const ETA: usize = 4;
    const TAU: usize = 49;
    const BETA: u32 = 196;  // TAU * ETA
    const GAMMA1: u32 = 1 << 19;  // 2^19
    const GAMMA2: u32 = (Q as u32 - 1) / 32;
    const OMEGA: usize = 55;
    const LAMBDA: usize = 48;  // 384 bits
    const ML_DSA_EQUIVALENT_DIM: usize = 2816;  // 256 * (6+5)
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
