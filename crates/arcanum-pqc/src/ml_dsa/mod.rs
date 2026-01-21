//! ML-DSA (Module-Lattice-Based Digital Signature Algorithm)
//!
//! Native implementation of FIPS 204 for Arcanum.
//!
//! **Status**: Core implementation complete (Green Phase).
//!
//! ## Overview
//!
//! ML-DSA (formerly CRYSTALS-Dilithium) is a post-quantum digital signature
//! algorithm based on the Module Learning With Errors (M-LWE) problem.
//!
//! ## Security Levels
//!
//! | Variant | NIST Level | Security |
//! |---------|------------|----------|
//! | ML-DSA-44 | Level 2 | 128-bit |
//! | ML-DSA-65 | Level 3 | 192-bit |
//! | ML-DSA-87 | Level 5 | 256-bit |
//!
//! ## Dependencies
//!
//! This implementation uses SHAKE256 from arcanum-primitives for
//! hashing, sampling, and XOF operations as specified in FIPS 204.
//!
//! ## Example
//!
//! ```
//! use arcanum_pqc::ml_dsa::{MlDsa65, MlDsa};
//!
//! // Generate keypair
//! let (sk, vk) = MlDsa65::generate_keypair();
//!
//! // Sign a message
//! let message = b"Hello, post-quantum world!";
//! let signature = MlDsa65::sign(&sk, message);
//!
//! // Verify signature
//! assert!(MlDsa65::verify(&vk, message, &signature).is_ok());
//! ```
//!
//! ## Implementation Status
//!
//! - [x] Parameter definitions (params.rs)
//! - [x] Polynomial types (poly.rs)
//! - [x] NTT constants (ZETAS from Dilithium reference)
//! - [x] NTT implementation (forward/inverse, Montgomery arithmetic)
//! - [x] Sampling functions (ExpandA, ExpandS, ExpandMask, SampleInBall)
//! - [x] Rounding functions (Power2Round, Decompose, MakeHint, UseHint)
//! - [x] Key generation (keygen.rs)
//! - [x] Signing (sign.rs)
//! - [x] Verification (verify.rs)
//! - [x] Deterministic tests with NIST-style vectors

#![allow(dead_code)]

pub mod keygen;
pub mod ntt;
pub mod params;
pub mod poly;
#[cfg(all(feature = "simd", target_arch = "x86_64"))]
#[allow(unsafe_code)]
pub mod poly_simd;
pub mod rounding;
pub mod sampling;
pub mod sign;
pub mod verify;

#[cfg(test)]
mod tests;

// Re-exports
pub use params::{MlDsaParams, Params44, Params65, Params87};
pub use poly::{Poly, PolyMatrix, PolyVecK};

use core::marker::PhantomData;

/// ML-DSA signing key (private key)
///
/// Contains the secret vectors s₁, s₂ and auxiliary data for signing.
#[derive(Clone)]
pub struct MlDsaSigningKey<P: MlDsaParams> {
    /// Public seed for matrix A
    rho: [u8; 32],
    /// Key for signing randomness
    key: [u8; 32],
    /// Hash of public key (tr)
    tr: [u8; 64],
    /// Secret vector s₁ (in NTT form)
    // s1: PolyVecK<{P::L}>, // Requires const generics improvement
    /// Secret vector s₂ (in NTT form)
    // s2: PolyVecK<{P::K}>,
    /// Low bits of t
    // t0: PolyVecK<{P::K}>,
    /// Raw bytes (placeholder until const generics work)
    bytes: alloc::vec::Vec<u8>,
    _params: PhantomData<P>,
}

impl<P: MlDsaParams> MlDsaSigningKey<P> {
    /// Size of the signing key in bytes
    pub const SIZE: usize = P::SK_SIZE;

    /// Create from raw bytes
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != Self::SIZE {
            return None;
        }
        Some(Self {
            rho: [0; 32],   // TODO: Extract from bytes
            key: [0; 32],   // TODO: Extract from bytes
            tr: [0; 64],    // TODO: Extract from bytes
            bytes: bytes.to_vec(),
            _params: PhantomData,
        })
    }

    /// Export to bytes
    pub fn to_bytes(&self) -> alloc::vec::Vec<u8> {
        self.bytes.clone()
    }
}

impl<P: MlDsaParams> core::fmt::Debug for MlDsaSigningKey<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "MlDsaSigningKey<{}>([REDACTED])", P::ALGORITHM)
    }
}

/// ML-DSA verifying key (public key)
///
/// Contains the public seed ρ and high bits of t.
#[derive(Clone, PartialEq, Eq)]
pub struct MlDsaVerifyingKey<P: MlDsaParams> {
    /// Public seed for matrix A
    rho: [u8; 32],
    /// High bits of t (t₁)
    // t1: PolyVecK<{P::K}>,
    /// Raw bytes (placeholder)
    bytes: alloc::vec::Vec<u8>,
    _params: PhantomData<P>,
}

impl<P: MlDsaParams> MlDsaVerifyingKey<P> {
    /// Size of the verifying key in bytes
    pub const SIZE: usize = P::PK_SIZE;

    /// Create from raw bytes
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != Self::SIZE {
            return None;
        }
        Some(Self {
            rho: [0; 32], // TODO: Extract from bytes
            bytes: bytes.to_vec(),
            _params: PhantomData,
        })
    }

    /// Export to bytes
    pub fn to_bytes(&self) -> alloc::vec::Vec<u8> {
        self.bytes.clone()
    }
}

impl<P: MlDsaParams> core::fmt::Debug for MlDsaVerifyingKey<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "MlDsaVerifyingKey<{}>({} bytes)",
            P::ALGORITHM,
            self.bytes.len()
        )
    }
}

/// ML-DSA signature
///
/// Contains commitment hash c̃, response z, and hint h.
#[derive(Clone, PartialEq, Eq)]
pub struct MlDsaSignature<P: MlDsaParams> {
    /// Raw signature bytes
    bytes: alloc::vec::Vec<u8>,
    _params: PhantomData<P>,
}

impl<P: MlDsaParams> MlDsaSignature<P> {
    /// Size of the signature in bytes
    pub const SIZE: usize = P::SIG_SIZE;

    /// Create from raw bytes
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != Self::SIZE {
            return None;
        }
        Some(Self {
            bytes: bytes.to_vec(),
            _params: PhantomData,
        })
    }

    /// Export to bytes
    pub fn to_bytes(&self) -> alloc::vec::Vec<u8> {
        self.bytes.clone()
    }
}

impl<P: MlDsaParams> core::fmt::Debug for MlDsaSignature<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "MlDsaSignature<{}>({} bytes)",
            P::ALGORITHM,
            self.bytes.len()
        )
    }
}

/// ML-DSA algorithm trait
pub trait MlDsa<P: MlDsaParams> {
    /// Generate a new keypair
    fn generate_keypair() -> (MlDsaSigningKey<P>, MlDsaVerifyingKey<P>);

    /// Sign a message
    fn sign(sk: &MlDsaSigningKey<P>, message: &[u8]) -> MlDsaSignature<P>;

    /// Verify a signature
    fn verify(
        vk: &MlDsaVerifyingKey<P>,
        message: &[u8],
        signature: &MlDsaSignature<P>,
    ) -> Result<(), MlDsaError>;
}

/// Errors that can occur in ML-DSA operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MlDsaError {
    /// Signature verification failed
    VerificationFailed,
    /// Invalid key format
    InvalidKey,
    /// Invalid signature format
    InvalidSignature,
    /// Internal error (should not occur)
    InternalError,
}

impl core::fmt::Display for MlDsaError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::VerificationFailed => write!(f, "signature verification failed"),
            Self::InvalidKey => write!(f, "invalid key format"),
            Self::InvalidSignature => write!(f, "invalid signature format"),
            Self::InternalError => write!(f, "internal error"),
        }
    }
}

// Type aliases for convenience
/// ML-DSA-44 (NIST Level 2, 128-bit security)
pub type MlDsa44 = MlDsaNative<Params44>;
/// ML-DSA-65 (NIST Level 3, 192-bit security)
pub type MlDsa65 = MlDsaNative<Params65>;
/// ML-DSA-87 (NIST Level 5, 256-bit security)
pub type MlDsa87 = MlDsaNative<Params87>;

/// Native ML-DSA implementation
///
/// This is the main implementation struct. Once complete, it will
/// implement the full FIPS 204 algorithm.
pub struct MlDsaNative<P: MlDsaParams> {
    _params: PhantomData<P>,
}

impl<P: MlDsaParams> MlDsa<P> for MlDsaNative<P> {
    fn generate_keypair() -> (MlDsaSigningKey<P>, MlDsaVerifyingKey<P>) {
        // FIPS 204 Algorithm 1 (ML-DSA.KeyGen)
        //
        // 1. Sample random seed ξ ← {0,1}^256
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).expect("Failed to generate random seed");

        // 2-9. Generate keypair internally
        let kp = keygen::generate_keypair_internal::<P>(&seed);

        // 10. Pack keys for output
        let pk_bytes = keygen::pack_pk::<P>(&kp.rho, &kp.t1);
        let sk_bytes = keygen::pack_sk::<P>(
            &kp.rho,
            &kp.key,
            &kp.tr,
            &kp.s1,
            &kp.s2,
            &kp.t0,
        );

        let sk = MlDsaSigningKey {
            rho: kp.rho,
            key: kp.key,
            tr: kp.tr,
            bytes: sk_bytes,
            _params: PhantomData,
        };

        let vk = MlDsaVerifyingKey {
            rho: kp.rho,
            bytes: pk_bytes,
            _params: PhantomData,
        };

        (sk, vk)
    }

    fn sign(sk: &MlDsaSigningKey<P>, message: &[u8]) -> MlDsaSignature<P> {
        // FIPS 204 Algorithm 2 (ML-DSA.Sign)
        let sig_bytes = sign::sign_internal::<P>(&sk.bytes, message)
            .expect("Signing failed - this should not happen with valid keys");

        MlDsaSignature {
            bytes: sig_bytes,
            _params: PhantomData,
        }
    }

    fn verify(
        vk: &MlDsaVerifyingKey<P>,
        message: &[u8],
        signature: &MlDsaSignature<P>,
    ) -> Result<(), MlDsaError> {
        // FIPS 204 Algorithm 3 (ML-DSA.Verify)
        if verify::verify_internal::<P>(&vk.bytes, message, &signature.bytes) {
            Ok(())
        } else {
            Err(MlDsaError::VerificationFailed)
        }
    }
}

// Needed for alloc::vec::Vec
extern crate alloc;

#[cfg(test)]
mod api_tests {
    use super::*;

    #[test]
    fn test_signing_key_size() {
        assert_eq!(MlDsaSigningKey::<Params44>::SIZE, 2560);
        assert_eq!(MlDsaSigningKey::<Params65>::SIZE, 4032);
        assert_eq!(MlDsaSigningKey::<Params87>::SIZE, 4896);
    }

    #[test]
    fn test_verifying_key_size() {
        assert_eq!(MlDsaVerifyingKey::<Params44>::SIZE, 1312);
        assert_eq!(MlDsaVerifyingKey::<Params65>::SIZE, 1952);
        assert_eq!(MlDsaVerifyingKey::<Params87>::SIZE, 2592);
    }

    #[test]
    fn test_signature_size() {
        assert_eq!(MlDsaSignature::<Params44>::SIZE, 2420);
        assert_eq!(MlDsaSignature::<Params65>::SIZE, 3309);
        assert_eq!(MlDsaSignature::<Params87>::SIZE, 4627);
    }

    #[test]
    fn test_key_from_bytes_wrong_size() {
        let bytes = vec![0u8; 100];
        assert!(MlDsaSigningKey::<Params65>::from_bytes(&bytes).is_none());
        assert!(MlDsaVerifyingKey::<Params65>::from_bytes(&bytes).is_none());
    }

    #[test]
    fn test_signature_from_bytes_wrong_size() {
        let bytes = vec![0u8; 100];
        assert!(MlDsaSignature::<Params65>::from_bytes(&bytes).is_none());
    }

    #[test]
    fn test_key_roundtrip() {
        let bytes = vec![0u8; Params65::SK_SIZE];
        let sk = MlDsaSigningKey::<Params65>::from_bytes(&bytes).unwrap();
        assert_eq!(sk.to_bytes(), bytes);
    }

    #[test]
    fn test_generate_keypair_44() {
        let (sk, vk) = MlDsa44::generate_keypair();
        assert_eq!(sk.to_bytes().len(), Params44::SK_SIZE);
        assert_eq!(vk.to_bytes().len(), Params44::PK_SIZE);
    }

    #[test]
    fn test_generate_keypair_65() {
        let (sk, vk) = MlDsa65::generate_keypair();
        assert_eq!(sk.to_bytes().len(), Params65::SK_SIZE);
        assert_eq!(vk.to_bytes().len(), Params65::PK_SIZE);
    }

    #[test]
    fn test_generate_keypair_87() {
        let (sk, vk) = MlDsa87::generate_keypair();
        assert_eq!(sk.to_bytes().len(), Params87::SK_SIZE);
        assert_eq!(vk.to_bytes().len(), Params87::PK_SIZE);
    }

    #[test]
    fn test_keypair_keys_are_different() {
        // Two keypairs should be different (random)
        let (sk1, vk1) = MlDsa65::generate_keypair();
        let (sk2, vk2) = MlDsa65::generate_keypair();

        assert_ne!(sk1.to_bytes(), sk2.to_bytes());
        assert_ne!(vk1.to_bytes(), vk2.to_bytes());
    }
}
