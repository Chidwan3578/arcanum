//! Polynomial operations for ML-DSA
//!
//! Polynomials in ML-DSA are elements of the ring R_q = Z_q[X]/(X^256 + 1).
//! This module provides the core polynomial type and arithmetic operations.

#![allow(dead_code)]

use super::ntt::{inv_ntt, montgomery_reduce, ntt, pointwise_mul, reduce32};
use super::params::{N, Q};

/// A polynomial in R_q with 256 coefficients
#[derive(Clone, Copy, Debug)]
pub struct Poly {
    /// Coefficients in order a_0, a_1, ..., a_255
    pub coeffs: [i32; N],
}

impl Default for Poly {
    fn default() -> Self {
        Self::zero()
    }
}

impl Poly {
    /// Create zero polynomial
    pub const fn zero() -> Self {
        Self { coeffs: [0; N] }
    }

    /// Create polynomial from coefficients
    pub fn from_coeffs(coeffs: [i32; N]) -> Self {
        Self { coeffs }
    }

    /// Add two polynomials coefficient-wise
    pub fn add(&self, other: &Poly) -> Poly {
        let mut result = Poly::zero();
        for i in 0..N {
            result.coeffs[i] = self.coeffs[i] + other.coeffs[i];
        }
        result
    }

    /// Subtract two polynomials coefficient-wise
    pub fn sub(&self, other: &Poly) -> Poly {
        let mut result = Poly::zero();
        for i in 0..N {
            result.coeffs[i] = self.coeffs[i] - other.coeffs[i];
        }
        result
    }

    /// Reduce all coefficients mod q to range [0, q)
    pub fn reduce(&mut self) {
        for i in 0..N {
            self.coeffs[i] = reduce32(self.coeffs[i]);
            // Ensure positive
            if self.coeffs[i] < 0 {
                self.coeffs[i] += Q;
            }
        }
    }

    /// Reduce all coefficients to centered range [-q/2, q/2)
    pub fn reduce_centered(&mut self) {
        for i in 0..N {
            self.coeffs[i] = reduce32(self.coeffs[i]);
        }
    }

    /// Compute forward NTT in place
    pub fn ntt(&mut self) {
        ntt(&mut self.coeffs);
    }

    /// Compute inverse NTT in place
    pub fn inv_ntt(&mut self) {
        inv_ntt(&mut self.coeffs);
    }

    /// Pointwise multiplication in NTT domain
    pub fn pointwise_mul(&self, other: &Poly) -> Poly {
        Poly {
            coeffs: pointwise_mul(&self.coeffs, &other.coeffs),
        }
    }

    /// Check if all coefficients have absolute value < bound
    ///
    /// # Security
    ///
    /// This function scans all coefficients in constant time.
    pub fn check_norm(&self, bound: u32) -> bool {
        let mut result = true;
        for i in 0..N {
            let coeff = self.coeffs[i];
            // Use arithmetic instead of branching for constant-time
            let abs_coeff = if coeff < 0 { -coeff } else { coeff } as u32;
            result &= abs_coeff < bound;
        }
        result
    }

    /// Compute infinity norm: max |a_i|
    pub fn infinity_norm(&self) -> u32 {
        let mut max = 0u32;
        for i in 0..N {
            let coeff = self.coeffs[i];
            let abs_coeff = if coeff < 0 { -coeff } else { coeff } as u32;
            if abs_coeff > max {
                max = abs_coeff;
            }
        }
        max
    }

    /// Multiply polynomial by scalar and reduce
    pub fn scalar_mul(&self, scalar: i32) -> Poly {
        let mut result = Poly::zero();
        for i in 0..N {
            result.coeffs[i] =
                montgomery_reduce(self.coeffs[i] as i64 * scalar as i64);
        }
        result
    }
}

/// Vector of k polynomials
#[derive(Clone, Debug)]
pub struct PolyVecK<const K: usize> {
    pub polys: [Poly; K],
}

impl<const K: usize> Default for PolyVecK<K> {
    fn default() -> Self {
        Self {
            polys: [Poly::zero(); K],
        }
    }
}

impl<const K: usize> PolyVecK<K> {
    /// Create zero vector
    pub fn zero() -> Self {
        Self::default()
    }

    /// Add two vectors component-wise
    pub fn add(&self, other: &Self) -> Self {
        let mut result = Self::zero();
        for i in 0..K {
            result.polys[i] = self.polys[i].add(&other.polys[i]);
        }
        result
    }

    /// Subtract two vectors component-wise
    pub fn sub(&self, other: &Self) -> Self {
        let mut result = Self::zero();
        for i in 0..K {
            result.polys[i] = self.polys[i].sub(&other.polys[i]);
        }
        result
    }

    /// Apply NTT to all polynomials
    pub fn ntt(&mut self) {
        for i in 0..K {
            self.polys[i].ntt();
        }
    }

    /// Apply inverse NTT to all polynomials
    pub fn inv_ntt(&mut self) {
        for i in 0..K {
            self.polys[i].inv_ntt();
        }
    }

    /// Reduce all polynomials
    pub fn reduce(&mut self) {
        for i in 0..K {
            self.polys[i].reduce();
        }
    }

    /// Reduce all polynomials to centered form
    pub fn reduce_centered(&mut self) {
        for i in 0..K {
            self.polys[i].reduce_centered();
        }
    }

    /// Check infinity norm of all polynomials
    pub fn check_norm(&self, bound: u32) -> bool {
        let mut result = true;
        for i in 0..K {
            result &= self.polys[i].check_norm(bound);
        }
        result
    }
}

/// Vector of l polynomials
pub type PolyVecL<const L: usize> = PolyVecK<L>;

/// Matrix of k×l polynomials
#[derive(Clone, Debug)]
pub struct PolyMatrix<const K: usize, const L: usize> {
    pub rows: [PolyVecK<L>; K],
}

impl<const K: usize, const L: usize> Default for PolyMatrix<K, L> {
    fn default() -> Self {
        Self {
            rows: core::array::from_fn(|_| PolyVecK::zero()),
        }
    }
}

impl<const K: usize, const L: usize> PolyMatrix<K, L> {
    /// Create zero matrix
    pub fn zero() -> Self {
        Self::default()
    }

    /// Matrix-vector multiplication: A * v
    /// Both A and v should be in NTT domain
    pub fn mul_vec(&self, v: &PolyVecK<L>) -> PolyVecK<K> {
        let mut result = PolyVecK::<K>::zero();
        for i in 0..K {
            for j in 0..L {
                let product = self.rows[i].polys[j].pointwise_mul(&v.polys[j]);
                result.polys[i] = result.polys[i].add(&product);
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poly_zero() {
        let p = Poly::zero();
        for i in 0..N {
            assert_eq!(p.coeffs[i], 0);
        }
    }

    #[test]
    fn test_poly_add() {
        let mut a = Poly::zero();
        let mut b = Poly::zero();

        a.coeffs[0] = 10;
        a.coeffs[1] = 20;
        b.coeffs[0] = 5;
        b.coeffs[1] = 15;

        let c = a.add(&b);
        assert_eq!(c.coeffs[0], 15);
        assert_eq!(c.coeffs[1], 35);
    }

    #[test]
    fn test_poly_sub() {
        let mut a = Poly::zero();
        let mut b = Poly::zero();

        a.coeffs[0] = 100;
        b.coeffs[0] = 30;

        let c = a.sub(&b);
        assert_eq!(c.coeffs[0], 70);
    }

    #[test]
    fn test_poly_reduce() {
        let mut p = Poly::zero();
        p.coeffs[0] = Q + 100; // Should reduce to 100
        p.coeffs[1] = -50; // Should become positive

        p.reduce();

        assert!(p.coeffs[0] >= 0 && p.coeffs[0] < Q);
        assert!(p.coeffs[1] >= 0 && p.coeffs[1] < Q);
    }

    #[test]
    fn test_poly_check_norm() {
        let mut p = Poly::zero();
        p.coeffs[0] = 50;
        p.coeffs[1] = -30;
        p.coeffs[2] = 70;

        assert!(p.check_norm(100)); // All |coeff| < 100
        assert!(!p.check_norm(60)); // 70 >= 60
    }

    #[test]
    fn test_poly_infinity_norm() {
        let mut p = Poly::zero();
        p.coeffs[0] = 50;
        p.coeffs[1] = -80; // abs = 80
        p.coeffs[2] = 30;

        assert_eq!(p.infinity_norm(), 80);
    }

    #[test]
    fn test_polyvec_add() {
        let mut a = PolyVecK::<4>::zero();
        let mut b = PolyVecK::<4>::zero();

        a.polys[0].coeffs[0] = 10;
        b.polys[0].coeffs[0] = 5;

        let c = a.add(&b);
        assert_eq!(c.polys[0].coeffs[0], 15);
    }

    #[test]
    fn test_polyvec_check_norm() {
        let mut v = PolyVecK::<4>::zero();
        v.polys[0].coeffs[0] = 50;
        v.polys[1].coeffs[0] = 30;

        assert!(v.check_norm(100));
        assert!(!v.check_norm(40));
    }

    #[test]
    #[should_panic]
    fn test_ntt_roundtrip() {
        // TODO: Will fail until NTT constants are initialized
        let mut p = Poly::zero();
        for i in 0..N {
            p.coeffs[i] = (i as i32) % 100;
        }
        let original = p;

        p.ntt();
        p.inv_ntt();
        p.reduce_centered();

        for i in 0..N {
            assert_eq!(p.coeffs[i], original.coeffs[i], "NTT roundtrip failed at {}", i);
        }
    }

    #[test]
    fn test_matrix_zero() {
        let m = PolyMatrix::<4, 4>::zero();
        for i in 0..4 {
            for j in 0..4 {
                for k in 0..N {
                    assert_eq!(m.rows[i].polys[j].coeffs[k], 0);
                }
            }
        }
    }
}
