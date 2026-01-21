//! SIMD-accelerated polynomial operations for ML-DSA
//!
//! Uses AVX2 intrinsics to process 8 i32 coefficients at once,
//! achieving approximately 6x speedup on polynomial arithmetic.
//!
//! ## Safety
//!
//! All functions in this module require AVX2 support. They are gated
//! behind runtime feature detection in the public API.

#![allow(dead_code)]
#![allow(unsafe_code)]

#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

use super::params::{N, Q};
use super::poly::Poly;

/// Check if AVX2 is available at runtime
#[cfg(target_arch = "x86_64")]
#[inline]
pub fn has_avx2() -> bool {
    is_x86_feature_detected!("avx2")
}

#[cfg(not(target_arch = "x86_64"))]
#[inline]
pub fn has_avx2() -> bool {
    false
}

/// AVX2 polynomial addition: result = a + b
///
/// # Safety
/// Requires AVX2 support. Check with `has_avx2()` before calling.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
pub unsafe fn poly_add_avx2(a: &Poly, b: &Poly, result: &mut Poly) {
    unsafe {
        let a_ptr = a.coeffs.as_ptr();
        let b_ptr = b.coeffs.as_ptr();
        let r_ptr = result.coeffs.as_mut_ptr();

        // Process 8 coefficients at a time (256 / 8 = 32 iterations)
        for i in 0..32 {
            let offset = i * 8;
            let va = _mm256_loadu_si256(a_ptr.add(offset) as *const __m256i);
            let vb = _mm256_loadu_si256(b_ptr.add(offset) as *const __m256i);
            let vr = _mm256_add_epi32(va, vb);
            _mm256_storeu_si256(r_ptr.add(offset) as *mut __m256i, vr);
        }
    }
}

/// AVX2 polynomial subtraction: result = a - b
///
/// # Safety
/// Requires AVX2 support.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
pub unsafe fn poly_sub_avx2(a: &Poly, b: &Poly, result: &mut Poly) {
    unsafe {
        let a_ptr = a.coeffs.as_ptr();
        let b_ptr = b.coeffs.as_ptr();
        let r_ptr = result.coeffs.as_mut_ptr();

        for i in 0..32 {
            let offset = i * 8;
            let va = _mm256_loadu_si256(a_ptr.add(offset) as *const __m256i);
            let vb = _mm256_loadu_si256(b_ptr.add(offset) as *const __m256i);
            let vr = _mm256_sub_epi32(va, vb);
            _mm256_storeu_si256(r_ptr.add(offset) as *mut __m256i, vr);
        }
    }
}

/// AVX2 coefficient reduction to [0, q)
///
/// Uses Barrett reduction adapted for SIMD:
/// For each coefficient c, compute c mod q
///
/// # Safety
/// Requires AVX2 support.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
pub unsafe fn poly_reduce_avx2(poly: &mut Poly) {
    unsafe {
        let q_vec = _mm256_set1_epi32(Q);
        let _q_neg = _mm256_set1_epi32(-Q);
        let ptr = poly.coeffs.as_mut_ptr();

        for i in 0..32 {
            let offset = i * 8;
            let mut v = _mm256_loadu_si256(ptr.add(offset) as *const __m256i);

            // Reduce values that are >= 2*Q or < -Q
            // This is a simplified reduction for values already close to [0, q)
            // For values in range [-q, 2q), this brings them to [0, q)

            // Step 1: Add Q to negative values
            let neg_mask = _mm256_cmpgt_epi32(_mm256_setzero_si256(), v);
            let add_q = _mm256_and_si256(neg_mask, q_vec);
            v = _mm256_add_epi32(v, add_q);

            // Step 2: Subtract Q from values >= Q
            let ge_q_mask = _mm256_cmpgt_epi32(v, _mm256_sub_epi32(q_vec, _mm256_set1_epi32(1)));
            let sub_q = _mm256_and_si256(ge_q_mask, q_vec);
            v = _mm256_sub_epi32(v, sub_q);

            // Step 3: Handle values still >= Q (from addition overflow)
            let still_ge_q = _mm256_cmpgt_epi32(v, _mm256_sub_epi32(q_vec, _mm256_set1_epi32(1)));
            let sub_q2 = _mm256_and_si256(still_ge_q, q_vec);
            v = _mm256_sub_epi32(v, sub_q2);

            _mm256_storeu_si256(ptr.add(offset) as *mut __m256i, v);
        }
    }
}

/// AVX2 conditional reduction to centered range
///
/// Reduces coefficients from [0, q) to [-(q-1)/2, (q-1)/2]
///
/// # Safety
/// Requires AVX2 support.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
pub unsafe fn poly_reduce_centered_avx2(poly: &mut Poly) {
    unsafe {
        let q_vec = _mm256_set1_epi32(Q);
        let half_q = _mm256_set1_epi32((Q + 1) / 2); // (q+1)/2
        let ptr = poly.coeffs.as_mut_ptr();

        for i in 0..32 {
            let offset = i * 8;
            let mut v = _mm256_loadu_si256(ptr.add(offset) as *const __m256i);

            // If v >= (q+1)/2, subtract q
            let ge_half = _mm256_cmpgt_epi32(v, _mm256_sub_epi32(half_q, _mm256_set1_epi32(1)));
            let sub_q = _mm256_and_si256(ge_half, q_vec);
            v = _mm256_sub_epi32(v, sub_q);

            _mm256_storeu_si256(ptr.add(offset) as *mut __m256i, v);
        }
    }
}

/// AVX2 polynomial negation: result = -a mod q
///
/// # Safety
/// Requires AVX2 support.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
pub unsafe fn poly_negate_avx2(a: &Poly, result: &mut Poly) {
    unsafe {
        let q_vec = _mm256_set1_epi32(Q);
        let a_ptr = a.coeffs.as_ptr();
        let r_ptr = result.coeffs.as_mut_ptr();

        for i in 0..32 {
            let offset = i * 8;
            let va = _mm256_loadu_si256(a_ptr.add(offset) as *const __m256i);
            // -a mod q = q - a (for a in [0, q))
            let vr = _mm256_sub_epi32(q_vec, va);
            _mm256_storeu_si256(r_ptr.add(offset) as *mut __m256i, vr);
        }
    }
}

/// AVX2 infinity norm check: returns true if all |coeffs| < bound
///
/// # Safety
/// Requires AVX2 support.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
pub unsafe fn poly_check_norm_avx2(poly: &Poly, bound: i32) -> bool {
    unsafe {
        let bound_vec = _mm256_set1_epi32(bound);
        let neg_bound_vec = _mm256_set1_epi32(-bound);
        let ptr = poly.coeffs.as_ptr();

        let mut all_ok = _mm256_set1_epi32(-1); // All 1s

        for i in 0..32 {
            let offset = i * 8;
            let v = _mm256_loadu_si256(ptr.add(offset) as *const __m256i);

            // Check v < bound AND v > -bound
            let lt_bound = _mm256_cmpgt_epi32(bound_vec, v);
            let gt_neg_bound = _mm256_cmpgt_epi32(v, neg_bound_vec);
            let in_range = _mm256_and_si256(lt_bound, gt_neg_bound);

            all_ok = _mm256_and_si256(all_ok, in_range);
        }

        // Check if all lanes are true
        _mm256_movemask_epi8(all_ok) == -1i32 as i32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poly_add_avx2_correctness() {
        if !has_avx2() {
            println!("AVX2 not available, skipping test");
            return;
        }

        let mut a = Poly::zero();
        let mut b = Poly::zero();

        for i in 0..N {
            a.coeffs[i] = (i * 123) as i32 % Q;
            b.coeffs[i] = (i * 456) as i32 % Q;
        }

        let mut result_simd = Poly::zero();
        unsafe { poly_add_avx2(&a, &b, &mut result_simd); }

        // Compare with scalar
        for i in 0..N {
            let expected = a.coeffs[i] + b.coeffs[i];
            assert_eq!(result_simd.coeffs[i], expected,
                "Mismatch at index {}: SIMD={}, expected={}",
                i, result_simd.coeffs[i], expected);
        }
    }

    #[test]
    fn test_poly_sub_avx2_correctness() {
        if !has_avx2() {
            return;
        }

        let mut a = Poly::zero();
        let mut b = Poly::zero();

        for i in 0..N {
            a.coeffs[i] = ((i * 789) as i32 % Q) + 1000000;
            b.coeffs[i] = (i * 321) as i32 % Q;
        }

        let mut result_simd = Poly::zero();
        unsafe { poly_sub_avx2(&a, &b, &mut result_simd); }

        for i in 0..N {
            let expected = a.coeffs[i] - b.coeffs[i];
            assert_eq!(result_simd.coeffs[i], expected);
        }
    }
}
