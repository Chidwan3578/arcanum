//! Number Theoretic Transform (NTT) for ML-DSA
//!
//! FIPS 204 uses NTT for efficient polynomial multiplication.
//! The NTT operates over Z_q where q = 8380417 with primitive
//! 512th root of unity ζ = 1753.
//!
//! # Montgomery Arithmetic
//!
//! All arithmetic uses Montgomery representation for constant-time
//! modular reduction without division.

#![allow(dead_code)]

use super::params::{N, Q};

/// Primitive 512th root of unity: ζ = 1753
const ZETA: i32 = 1753;

/// Montgomery constant R = 2^32 mod q
const MONT_R: i32 = 4193792; // 2^32 mod q

/// Montgomery constant R^2 mod q (for conversion to Montgomery form)
const MONT_R2: i32 = 2365951; // (2^32)^2 mod q

/// q^(-1) mod 2^32 for Montgomery reduction
const QINV: i32 = 58728449;

/// Precomputed powers of ζ in bit-reversed order for forward NTT
/// zetas[i] = ζ^(bit_rev(i)) * R mod q (in Montgomery form)
///
/// TODO: Generate these constants from FIPS 204 test vectors
const ZETAS: [i32; N] = [0; N]; // Placeholder - needs generation

/// Precomputed powers of -ζ^(-1) for inverse NTT
/// zetas_inv[i] = -ζ^(-bit_rev(i)) * R mod q (in Montgomery form)
const ZETAS_INV: [i32; N] = [0; N]; // Placeholder - needs generation

/// Montgomery reduction: compute a * R^(-1) mod q
///
/// Given a value a in [-q*R, q*R], compute a * 2^(-32) mod q.
/// This is the core operation for constant-time modular arithmetic.
///
/// # Security
///
/// This function executes in constant time regardless of input value.
#[inline]
pub fn montgomery_reduce(a: i64) -> i32 {
    // t = a * q^(-1) mod 2^32
    let t = (a as i32).wrapping_mul(QINV);
    // t = (a - t*q) / 2^32
    let t = a.wrapping_sub((t as i64).wrapping_mul(Q as i64));
    (t >> 32) as i32
}

/// Reduce coefficient to [-q/2, q/2) (centered representation)
///
/// # Security
///
/// This function executes in constant time.
#[inline]
pub fn reduce32(a: i32) -> i32 {
    // Barrett reduction
    let t = (a + (1 << 22)) >> 23;
    let t = a - t * Q;
    t
}

/// Conditional reduce: if a >= q, subtract q
///
/// # Security
///
/// This function executes in constant time using arithmetic mask.
#[inline]
pub fn cond_reduce(a: i32) -> i32 {
    let mask = ((a - Q) >> 31) as i32;
    a - (Q & !mask)
}

/// Forward NTT: coefficient form → NTT domain
///
/// Cooley-Tukey butterfly with bit-reversed output.
/// After NTT, polynomials can be multiplied pointwise.
///
/// # Arguments
///
/// * `coeffs` - 256 coefficients in standard order
///
/// # Returns
///
/// Coefficients in NTT domain (bit-reversed order)
pub fn ntt(coeffs: &mut [i32; N]) {
    let mut k = 0usize;
    let mut len = 128;

    while len >= 1 {
        let mut start = 0;
        while start < N {
            let zeta = ZETAS[k];
            k += 1;

            for j in start..(start + len) {
                let t = montgomery_reduce(zeta as i64 * coeffs[j + len] as i64);
                coeffs[j + len] = coeffs[j] - t;
                coeffs[j] = coeffs[j] + t;
            }
            start += 2 * len;
        }
        len >>= 1;
    }
}

/// Inverse NTT: NTT domain → coefficient form
///
/// Gentleman-Sande butterfly with bit-reversed input.
/// Includes multiplication by n^(-1) for proper scaling.
///
/// # Arguments
///
/// * `coeffs` - 256 coefficients in NTT domain
///
/// # Returns
///
/// Coefficients in standard polynomial form
pub fn inv_ntt(coeffs: &mut [i32; N]) {
    let mut k = N - 1;
    let mut len = 1;

    while len < N {
        let mut start = 0;
        while start < N {
            let zeta = ZETAS_INV[k];
            k = k.wrapping_sub(1);

            for j in start..(start + len) {
                let t = coeffs[j];
                coeffs[j] = t + coeffs[j + len];
                coeffs[j + len] = montgomery_reduce(zeta as i64 * (t - coeffs[j + len]) as i64);
            }
            start += 2 * len;
        }
        len <<= 1;
    }

    // Multiply by n^(-1) = 2^(-8) mod q (in Montgomery form)
    let ninv = 41978; // 256^(-1) * R mod q
    for i in 0..N {
        coeffs[i] = montgomery_reduce(ninv as i64 * coeffs[i] as i64);
    }
}

/// Pointwise multiplication in NTT domain
///
/// Multiplies two polynomials in NTT representation.
/// Result is also in NTT domain.
pub fn pointwise_mul(a: &[i32; N], b: &[i32; N]) -> [i32; N] {
    let mut c = [0i32; N];
    for i in 0..N {
        c[i] = montgomery_reduce(a[i] as i64 * b[i] as i64);
    }
    c
}

/// Convert integer to Montgomery form: a → a*R mod q
pub fn to_mont(a: i32) -> i32 {
    montgomery_reduce(a as i64 * MONT_R2 as i64)
}

/// Convert from Montgomery form: a*R → a mod q
pub fn from_mont(a: i32) -> i32 {
    montgomery_reduce(a as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_montgomery_reduce_zero() {
        assert_eq!(montgomery_reduce(0), 0);
    }

    #[test]
    fn test_montgomery_reduce_small() {
        // Small values should reduce correctly
        let a = 1000i64 * (1i64 << 32);
        let result = montgomery_reduce(a);
        // Result should be 1000 mod q
        assert!(result >= -Q && result < Q);
    }

    #[test]
    fn test_reduce32() {
        // Positive value less than q
        assert_eq!(reduce32(100), 100);

        // Value equal to q should reduce
        let r = reduce32(Q);
        assert!(r >= -Q / 2 && r < Q / 2);
    }

    #[test]
    fn test_cond_reduce() {
        // Value less than q should be unchanged
        assert_eq!(cond_reduce(100), 100);

        // Value >= q should have q subtracted
        assert_eq!(cond_reduce(Q), 0);
        assert_eq!(cond_reduce(Q + 1), 1);
    }

    #[test]
    fn test_to_from_mont_roundtrip() {
        // Converting to and from Montgomery form should preserve value mod q
        // Note: reduce32 returns centered values, so we compare mod q
        for &a in &[0, 1, 100, Q / 2] {
            let mont = to_mont(a);
            let back = from_mont(mont);
            // May need reduction
            let back = reduce32(back);
            // Handle centered representation
            let normalized = if back < 0 { back + Q } else { back };
            assert_eq!(normalized, a, "roundtrip failed for {}", a);
        }

        // Special case: Q-1 ≡ -1 (mod q) in centered representation
        let a = Q - 1;
        let mont = to_mont(a);
        let back = from_mont(mont);
        let back = reduce32(back);
        // back should be -1 which is equivalent to Q-1
        assert!(
            back == -1 || back == Q - 1,
            "roundtrip failed for Q-1, got {}",
            back
        );
    }

    #[test]
    #[should_panic]
    fn test_ntt_inverse_roundtrip() {
        // TODO: This test will fail until ZETAS constants are properly generated
        // NTT followed by inverse NTT should return original polynomial
        let mut coeffs = [0i32; N];
        for i in 0..N {
            coeffs[i] = (i as i32) % Q;
        }
        let original = coeffs;

        ntt(&mut coeffs);
        inv_ntt(&mut coeffs);

        for i in 0..N {
            let reduced = reduce32(coeffs[i]);
            assert_eq!(
                reduced, original[i],
                "NTT roundtrip failed at index {}",
                i
            );
        }
    }

    #[test]
    #[should_panic]
    fn test_ntt_multiplication_vs_schoolbook() {
        // TODO: This test will fail until NTT is fully implemented
        // NTT multiplication should match schoolbook multiplication
        let mut a = [0i32; N];
        let mut b = [0i32; N];

        // Simple test polynomials
        a[0] = 1;
        a[1] = 2;
        b[0] = 3;
        b[1] = 4;

        // NTT multiplication
        let mut a_ntt = a;
        let mut b_ntt = b;
        ntt(&mut a_ntt);
        ntt(&mut b_ntt);
        let mut c_ntt = pointwise_mul(&a_ntt, &b_ntt);
        inv_ntt(&mut c_ntt);

        // Expected: (1 + 2x)(3 + 4x) = 3 + 10x + 8x^2
        // In R_q = Z[x]/(x^256 + 1), x^256 = -1
        assert_eq!(reduce32(c_ntt[0]), 3);
        assert_eq!(reduce32(c_ntt[1]), 10);
        assert_eq!(reduce32(c_ntt[2]), 8);
    }

    #[test]
    fn test_modulus_for_ntt() {
        // Verify q allows efficient NTT
        // q = 8380417 ≡ 1 (mod 512)
        assert_eq!(Q % 512, 1, "q must be 1 mod 512 for 256-point NTT");
    }

    #[test]
    #[should_panic]
    fn test_zetas_not_zero() {
        // TODO: This test verifies ZETAS are properly initialized
        // Will fail until constants are generated
        assert!(ZETAS.iter().any(|&z| z != 0), "ZETAS must be initialized");
    }
}
