//! ML-DSA Parameter Sets (FIPS 204)
//!
//! Defines compile-time constants for ML-DSA-44, ML-DSA-65, and ML-DSA-87.

#![allow(dead_code)]

use core::marker::PhantomData;

/// Modulus q for ML-DSA
pub const Q: i32 = 8380417;

/// Polynomial degree (n = 256)
pub const N: usize = 256;

/// Number of dropped bits (d = 13 for all variants)
pub const D: usize = 13;

/// Parameter set trait for ML-DSA variants
pub trait MlDsaParams: Clone + 'static {
    /// Matrix dimension k (number of rows)
    const K: usize;

    /// Matrix dimension l (number of columns)
    const L: usize;

    /// Small coefficient bound η (eta)
    const ETA: usize;

    /// Rejection bound β (beta)
    const BETA: u32;

    /// Masking range γ₁ (gamma1)
    const GAMMA1: u32;

    /// Decomposition divisor γ₂ (gamma2)
    const GAMMA2: u32;

    /// Challenge weight τ (tau) - number of non-zero coefficients
    const TAU: usize;

    /// Security level λ in bits
    const LAMBDA: usize;

    /// Maximum hint weight (ω)
    const OMEGA: usize;

    /// Public key size in bytes
    const PK_SIZE: usize;

    /// Secret key size in bytes
    const SK_SIZE: usize;

    /// Signature size in bytes
    const SIG_SIZE: usize;

    /// Algorithm identifier string
    const ALGORITHM: &'static str;

    /// NIST security level (2, 3, or 5)
    const SECURITY_LEVEL: usize;
}

/// ML-DSA-44 parameters (NIST Level 2, 128-bit security)
#[derive(Clone, Copy, Debug)]
pub struct Params44;

impl MlDsaParams for Params44 {
    const K: usize = 4;
    const L: usize = 4;
    const ETA: usize = 2;
    const BETA: u32 = 78;
    const GAMMA1: u32 = 1 << 17; // 2^17 = 131072
    const GAMMA2: u32 = (Q as u32 - 1) / 88; // 95232
    const TAU: usize = 39;
    const LAMBDA: usize = 128;
    const OMEGA: usize = 80;
    const PK_SIZE: usize = 1312;
    const SK_SIZE: usize = 2560;
    const SIG_SIZE: usize = 2420;
    const ALGORITHM: &'static str = "ML-DSA-44";
    const SECURITY_LEVEL: usize = 2;
}

/// ML-DSA-65 parameters (NIST Level 3, 192-bit security)
#[derive(Clone, Copy, Debug)]
pub struct Params65;

impl MlDsaParams for Params65 {
    const K: usize = 6;
    const L: usize = 5;
    const ETA: usize = 4;
    const BETA: u32 = 196;
    const GAMMA1: u32 = 1 << 19; // 2^19 = 524288
    const GAMMA2: u32 = (Q as u32 - 1) / 32; // 261888
    const TAU: usize = 49;
    const LAMBDA: usize = 192;
    const OMEGA: usize = 55;
    const PK_SIZE: usize = 1952;
    const SK_SIZE: usize = 4032;
    const SIG_SIZE: usize = 3309;
    const ALGORITHM: &'static str = "ML-DSA-65";
    const SECURITY_LEVEL: usize = 3;
}

/// ML-DSA-87 parameters (NIST Level 5, 256-bit security)
#[derive(Clone, Copy, Debug)]
pub struct Params87;

impl MlDsaParams for Params87 {
    const K: usize = 8;
    const L: usize = 7;
    const ETA: usize = 2;
    const BETA: u32 = 120;
    const GAMMA1: u32 = 1 << 19; // 2^19 = 524288
    const GAMMA2: u32 = (Q as u32 - 1) / 32; // 261888
    const TAU: usize = 60;
    const LAMBDA: usize = 256;
    const OMEGA: usize = 75;
    const PK_SIZE: usize = 2592;
    const SK_SIZE: usize = 4896;
    const SIG_SIZE: usize = 4627;
    const ALGORITHM: &'static str = "ML-DSA-87";
    const SECURITY_LEVEL: usize = 5;
}

/// Marker for ML-DSA algorithm with specific parameters
pub struct MlDsaAlgorithm<P: MlDsaParams> {
    _params: PhantomData<P>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_params44_constants() {
        assert_eq!(Params44::K, 4);
        assert_eq!(Params44::L, 4);
        assert_eq!(Params44::ETA, 2);
        assert_eq!(Params44::PK_SIZE, 1312);
        assert_eq!(Params44::SK_SIZE, 2560);
        assert_eq!(Params44::SIG_SIZE, 2420);
    }

    #[test]
    fn test_params65_constants() {
        assert_eq!(Params65::K, 6);
        assert_eq!(Params65::L, 5);
        assert_eq!(Params65::ETA, 4);
        assert_eq!(Params65::PK_SIZE, 1952);
        assert_eq!(Params65::SK_SIZE, 4032);
        assert_eq!(Params65::SIG_SIZE, 3309);
    }

    #[test]
    fn test_params87_constants() {
        assert_eq!(Params87::K, 8);
        assert_eq!(Params87::L, 7);
        assert_eq!(Params87::ETA, 2);
        assert_eq!(Params87::PK_SIZE, 2592);
        assert_eq!(Params87::SK_SIZE, 4896);
        assert_eq!(Params87::SIG_SIZE, 4627);
    }

    #[test]
    fn test_gamma2_calculation() {
        // γ₂ = (q-1)/88 for ML-DSA-44
        assert_eq!(Params44::GAMMA2, 95232);

        // γ₂ = (q-1)/32 for ML-DSA-65 and ML-DSA-87
        assert_eq!(Params65::GAMMA2, 261888);
        assert_eq!(Params87::GAMMA2, 261888);
    }

    #[test]
    fn test_modulus_properties() {
        // q should be prime
        assert_eq!(Q, 8380417);

        // q ≡ 1 (mod 512) for efficient NTT
        assert_eq!(Q % 512, 1);

        // Verify q is in valid range for i32
        assert!(Q > 0);
        assert!(Q < i32::MAX);
    }
}
