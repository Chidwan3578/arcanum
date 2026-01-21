//! Rounding functions for ML-DSA (FIPS 204)
//!
//! This module implements the rounding and decomposition algorithms:
//! - Power2Round: Decompose t into (t₁, t₀) where t = t₁·2^d + t₀
//! - Decompose: Decompose r into (r₁, r₀) where r = r₁·α + r₀
//! - HighBits/LowBits: Extract high/low parts of a decomposition
//! - MakeHint/UseHint: Hint computation for signature compression

#![allow(dead_code)]

use super::params::{N, Q};
use super::poly::Poly;

/// The dropped bits parameter d = 13 (from FIPS 204)
pub const D: u32 = 13;

/// 2^d for Power2Round
const TWO_POW_D: i32 = 1 << D;

// ═══════════════════════════════════════════════════════════════════════════════
// Power2Round (FIPS 204 Algorithm 35)
// ═══════════════════════════════════════════════════════════════════════════════

/// Decompose r into (r₁, r₀) such that r = r₁·2^d + r₀
///
/// This is used in key generation to split t = As₁ + s₂ into
/// public t₁ and secret t₀.
///
/// # Arguments
///
/// * `r` - Input value in [0, q)
///
/// # Returns
///
/// (r₁, r₀) where:
/// - r₁ = ⌊r/2^d⌋ (high bits)
/// - r₀ = r mod 2^d (low bits, centered around 0)
///
/// The low bits r₀ are in the range [-(2^(d-1)), 2^(d-1))
#[inline]
pub fn power2round(r: i32) -> (i32, i32) {
    // Ensure r is positive
    let r = if r < 0 { r + Q } else { r };

    // r₁ = ⌊(r + 2^(d-1)) / 2^d⌋
    // r₀ = r - r₁·2^d
    let r1 = (r + (1 << (D - 1))) >> D;
    let r0 = r - (r1 << D);

    (r1, r0)
}

/// Apply Power2Round to all coefficients of a polynomial
pub fn poly_power2round(poly: &Poly) -> (Poly, Poly) {
    let mut high = Poly::zero();
    let mut low = Poly::zero();

    for i in 0..N {
        let (h, l) = power2round(poly.coeffs[i]);
        high.coeffs[i] = h;
        low.coeffs[i] = l;
    }

    (high, low)
}

// ═══════════════════════════════════════════════════════════════════════════════
// Decompose (FIPS 204 Algorithm 36)
// ═══════════════════════════════════════════════════════════════════════════════

/// Decompose r into (r₁, r₀) such that r = r₁·α + r₀
///
/// This is used in signing to decompose w = Ay into high and low parts.
///
/// # Arguments
///
/// * `r` - Input value
/// * `gamma2` - The decomposition parameter γ₂
///
/// # Returns
///
/// (r₁, r₀) where:
/// - r₁ = high bits used for commitment
/// - r₀ = low bits in range (-γ₂, γ₂]
#[inline]
pub fn decompose(r: i32, gamma2: i32) -> (i32, i32) {
    // Ensure r is in [0, q)
    let r = if r < 0 { r + Q } else { r % Q };

    // α = 2γ₂ (the decomposition base)
    let alpha = 2 * gamma2;

    // r₀ = r mod α (centered)
    let mut r0 = r % alpha;
    if r0 > gamma2 {
        r0 -= alpha;
    }

    // r₁ = (r - r₀) / α
    let mut r1 = (r - r0) / alpha;

    // Handle corner case: if r - r₀ = q - 1, set r₁ = 0
    if r - r0 == Q - 1 {
        r1 = 0;
        r0 = r0 - 1;
    }

    (r1, r0)
}

/// Extract high bits: r₁ = HighBits(r)
#[inline]
pub fn high_bits(r: i32, gamma2: i32) -> i32 {
    decompose(r, gamma2).0
}

/// Extract low bits: r₀ = LowBits(r)
#[inline]
pub fn low_bits(r: i32, gamma2: i32) -> i32 {
    decompose(r, gamma2).1
}

/// Apply Decompose to all coefficients of a polynomial
pub fn poly_decompose(poly: &Poly, gamma2: i32) -> (Poly, Poly) {
    let mut high = Poly::zero();
    let mut low = Poly::zero();

    for i in 0..N {
        let (h, l) = decompose(poly.coeffs[i], gamma2);
        high.coeffs[i] = h;
        low.coeffs[i] = l;
    }

    (high, low)
}

/// Apply HighBits to all coefficients of a polynomial
pub fn poly_high_bits(poly: &Poly, gamma2: i32) -> Poly {
    let mut result = Poly::zero();
    for i in 0..N {
        result.coeffs[i] = high_bits(poly.coeffs[i], gamma2);
    }
    result
}

/// Apply LowBits to all coefficients of a polynomial
pub fn poly_low_bits(poly: &Poly, gamma2: i32) -> Poly {
    let mut result = Poly::zero();
    for i in 0..N {
        result.coeffs[i] = low_bits(poly.coeffs[i], gamma2);
    }
    result
}

// ═══════════════════════════════════════════════════════════════════════════════
// Hint Functions (FIPS 204 Algorithms 37-38)
// ═══════════════════════════════════════════════════════════════════════════════

/// Compute hint bit for a single coefficient
///
/// MakeHint returns 1 if HighBits(r) ≠ HighBits(r + z), 0 otherwise.
/// This is Algorithm 37 from FIPS 204.
///
/// # Arguments
///
/// * `z` - The value to add (typically -ct₀)
/// * `r` - The base value (typically w - cs₂ + ct₀)
/// * `gamma2` - The decomposition parameter γ₂
#[inline]
pub fn make_hint(z: i32, r: i32, gamma2: i32) -> bool {
    // Compute HighBits(r) and HighBits(r + z)
    let h0 = high_bits(r, gamma2);
    let h1 = high_bits(r + z, gamma2);

    h0 != h1
}

/// Use hint to recover the correct high bits
///
/// UseHint uses the hint h to recover HighBits(r + z) from HighBits(r).
/// This is Algorithm 38 from FIPS 204.
///
/// # Arguments
///
/// * `h` - The hint bit (true if correction needed)
/// * `r` - The value to adjust
/// * `gamma2` - The decomposition parameter γ₂
#[inline]
pub fn use_hint(h: bool, r: i32, gamma2: i32) -> i32 {
    let (r1, r0) = decompose(r, gamma2);

    if !h {
        return r1;
    }

    // Determine the maximum value of r₁
    // Note: Due to the corner case in decompose (when r - r0 = q - 1, r1 wraps to 0),
    // the actual maximum r1 is one less than the theoretical (q-1)/(2γ₂).
    // For ML-DSA-44: theoretical m = 44, actual max r1 = 43
    // For ML-DSA-65/87: theoretical m = 16, actual max r1 = 15
    let alpha = 2 * gamma2;
    let m = (Q - 1) / alpha - 1;

    // Adjust r₁ based on sign of r₀
    // (r1 + 1) mod (m + 1) or (r1 - 1) mod (m + 1)
    if r0 > 0 {
        if r1 == m { 0 } else { r1 + 1 }
    } else if r1 == 0 {
        m
    } else {
        r1 - 1
    }
}

/// Apply MakeHint to all coefficients of two polynomials
///
/// Returns the hint polynomial and the count of 1-bits
pub fn poly_make_hint(z: &Poly, r: &Poly, gamma2: i32) -> (Poly, usize) {
    let mut hint = Poly::zero();
    let mut count = 0;

    for i in 0..N {
        if make_hint(z.coeffs[i], r.coeffs[i], gamma2) {
            hint.coeffs[i] = 1;
            count += 1;
        }
    }

    (hint, count)
}

/// Apply UseHint to all coefficients
pub fn poly_use_hint(hint: &Poly, r: &Poly, gamma2: i32) -> Poly {
    let mut result = Poly::zero();

    for i in 0..N {
        let h = hint.coeffs[i] != 0;
        result.coeffs[i] = use_hint(h, r.coeffs[i], gamma2);
    }

    result
}

/// Count the number of 1-bits in a hint polynomial
pub fn hint_weight(hint: &Poly) -> usize {
    hint.coeffs.iter().filter(|&&c| c != 0).count()
}

// ═══════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_power2round_zero() {
        let (r1, r0) = power2round(0);
        assert_eq!(r1, 0);
        assert_eq!(r0, 0);
    }

    #[test]
    fn test_power2round_reconstruction() {
        // Test that r = r₁·2^d + r₀
        for r in [0, 1, 100, 1000, 8192, Q / 2, Q - 1] {
            let (r1, r0) = power2round(r);
            let reconstructed = r1 * TWO_POW_D + r0;
            assert_eq!(
                reconstructed, r,
                "Power2Round reconstruction failed for r={}",
                r
            );
        }
    }

    #[test]
    fn test_power2round_bounds() {
        // r₀ should be in [-(2^(d-1)), 2^(d-1))
        let half_d = (1 << (D - 1)) as i32;
        for r in [0, 1, 100, 1000, Q / 2, Q - 1] {
            let (_, r0) = power2round(r);
            assert!(
                r0 >= -half_d && r0 < half_d,
                "r0={} out of bounds for r={}",
                r0,
                r
            );
        }
    }

    #[test]
    fn test_decompose_gamma2_95232() {
        // γ₂ = (q-1)/88 = 95232 for ML-DSA-44
        let gamma2 = (Q - 1) / 88;
        let alpha = 2 * gamma2;

        for r in [0, 1, gamma2, gamma2 + 1, Q / 2, Q - 1] {
            let (r1, r0) = decompose(r, gamma2);

            // r₀ should be in (-γ₂, γ₂]
            assert!(
                r0 > -gamma2 && r0 <= gamma2,
                "r0={} out of bounds for r={}, gamma2={}",
                r0,
                r,
                gamma2
            );

            // Verify reconstruction (mod q)
            // The decompose function handles r=Q-1 specially by setting r1=0, r0=-1
            // This is correct because: 0 * alpha + (-1) ≡ -1 ≡ Q-1 (mod q)
            let reconstructed = r1 * alpha + r0;
            let reconstructed_mod_q = if reconstructed < 0 {
                reconstructed + Q
            } else {
                reconstructed % Q
            };
            let r_mod_q = r % Q;
            assert_eq!(
                reconstructed_mod_q, r_mod_q,
                "Decompose reconstruction failed: r={}, r1={}, r0={}, reconstructed={}",
                r, r1, r0, reconstructed
            );
        }
    }

    #[test]
    fn test_decompose_gamma2_261888() {
        // γ₂ = (q-1)/32 = 261888 for ML-DSA-65/87
        let gamma2 = (Q - 1) / 32;

        for r in [0, 1, gamma2, gamma2 + 1, Q / 2, Q - 1] {
            let (r1, r0) = decompose(r, gamma2);

            // r₀ should be in (-γ₂, γ₂]
            assert!(
                r0 > -gamma2 && r0 <= gamma2,
                "r0={} out of bounds for r={}, gamma2={}",
                r0,
                r,
                gamma2
            );
        }
    }

    #[test]
    fn test_high_low_bits() {
        let gamma2 = (Q - 1) / 32;

        for r in [0, 1000, Q / 2, Q - 1] {
            let (r1, r0) = decompose(r, gamma2);
            assert_eq!(high_bits(r, gamma2), r1);
            assert_eq!(low_bits(r, gamma2), r0);
        }
    }

    #[test]
    fn test_make_use_hint_roundtrip() {
        // The key property: UseHint(MakeHint(z₀, r), r + z₀) = HighBits(r + z₀)
        let gamma2 = (Q - 1) / 32;

        for r in [0, 1000, Q / 2] {
            for z0 in [-100, 0, 100, gamma2 / 2] {
                let r1 = high_bits(r, gamma2);
                let h = make_hint(z0, r1, gamma2);
                let recovered = use_hint(h, r, gamma2);
                let expected = high_bits(r + z0, gamma2);

                // Handle modular arithmetic
                let expected_mod = if expected < 0 {
                    expected + (Q - 1) / (2 * gamma2) + 1
                } else {
                    expected
                };
                let recovered_mod = if recovered < 0 {
                    recovered + (Q - 1) / (2 * gamma2) + 1
                } else {
                    recovered
                };

                assert_eq!(
                    recovered_mod, expected_mod,
                    "Hint roundtrip failed: r={}, z0={}, h={}, recovered={}, expected={}",
                    r, z0, h, recovered, expected
                );
            }
        }
    }

    #[test]
    fn test_poly_power2round() {
        let mut poly = Poly::zero();
        poly.coeffs[0] = 0;
        poly.coeffs[1] = 1000;
        poly.coeffs[2] = Q / 2;

        let (high, low) = poly_power2round(&poly);

        // Verify each coefficient
        for i in 0..3 {
            let (expected_h, expected_l) = power2round(poly.coeffs[i]);
            assert_eq!(high.coeffs[i], expected_h, "High mismatch at {}", i);
            assert_eq!(low.coeffs[i], expected_l, "Low mismatch at {}", i);
        }
    }

    #[test]
    fn test_poly_decompose() {
        let gamma2 = (Q - 1) / 32;
        let mut poly = Poly::zero();
        poly.coeffs[0] = 0;
        poly.coeffs[1] = 1000;
        poly.coeffs[2] = Q / 2;

        let (high, low) = poly_decompose(&poly, gamma2);

        for i in 0..3 {
            let (expected_h, expected_l) = decompose(poly.coeffs[i], gamma2);
            assert_eq!(high.coeffs[i], expected_h, "High mismatch at {}", i);
            assert_eq!(low.coeffs[i], expected_l, "Low mismatch at {}", i);
        }
    }

    #[test]
    fn test_hint_weight() {
        let mut hint = Poly::zero();
        hint.coeffs[0] = 1;
        hint.coeffs[5] = 1;
        hint.coeffs[100] = 1;

        assert_eq!(hint_weight(&hint), 3);
    }

    #[test]
    fn test_hint_weight_empty() {
        let hint = Poly::zero();
        assert_eq!(hint_weight(&hint), 0);
    }
}
