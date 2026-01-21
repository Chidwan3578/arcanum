//! Arcanum-DSA API
//!
//! Provides convenient type aliases and re-exports for using Arcanum-DSA
//! with SIMD-optimized parameters.
//!
//! # Example
//!
//! ```ignore
//! use arcanum_pqc::arcanum_dsa::{ArcanumDsa65, ArcanumDsa};
//!
//! // Generate keypair
//! let (sk, vk) = ArcanumDsa65::generate_keypair();
//!
//! // Sign a message
//! let signature = ArcanumDsa65::sign(&sk, b"Hello, SIMD world!");
//!
//! // Verify signature
//! assert!(ArcanumDsa65::verify(&vk, b"Hello, SIMD world!", &signature).is_ok());
//! ```

use super::params::{Params44, Params65, Params87};
use crate::ml_dsa::{MlDsa, MlDsaError, MlDsaNative, MlDsaSignature, MlDsaSigningKey, MlDsaVerifyingKey};

// ═══════════════════════════════════════════════════════════════════════════════
// Type Aliases
// ═══════════════════════════════════════════════════════════════════════════════

/// Arcanum-DSA-44: NIST Level 2 equivalent (identical to ML-DSA-44)
///
/// K=4, L=4, optimal 4-way SIMD batching.
/// Dimension: 2048 (same as ML-DSA-44)
pub type ArcanumDsa44 = MlDsaNative<Params44>;

/// Arcanum-DSA-65: NIST Level 3 equivalent with SIMD optimization
///
/// K=7, L=4 (SIMD-optimized from ML-DSA-65's K=6, L=5)
/// Dimension: 2816 (same as ML-DSA-65)
///
/// Key insight: L is *reduced* from 5 to 4, giving:
/// - 20% less ExpandMask work
/// - Perfect 4-way SIMD batching
/// - 19% smaller signatures (2670 vs 3309 bytes)
pub type ArcanumDsa65 = MlDsaNative<Params65>;

/// Arcanum-DSA-87: NIST Level 5 equivalent with +7% security margin
///
/// K=8, L=8 (SIMD-optimized from ML-DSA-87's K=8, L=7)
/// Dimension: 4096 vs ML-DSA-87's 3840
pub type ArcanumDsa87 = MlDsaNative<Params87>;

// ═══════════════════════════════════════════════════════════════════════════════
// Re-exports
// ═══════════════════════════════════════════════════════════════════════════════

/// Signing key for Arcanum-DSA-44
pub type ArcanumSigningKey44 = MlDsaSigningKey<Params44>;
/// Verifying key for Arcanum-DSA-44
pub type ArcanumVerifyingKey44 = MlDsaVerifyingKey<Params44>;
/// Signature for Arcanum-DSA-44
pub type ArcanumSignature44 = MlDsaSignature<Params44>;

/// Signing key for Arcanum-DSA-65
pub type ArcanumSigningKey65 = MlDsaSigningKey<Params65>;
/// Verifying key for Arcanum-DSA-65
pub type ArcanumVerifyingKey65 = MlDsaVerifyingKey<Params65>;
/// Signature for Arcanum-DSA-65
pub type ArcanumSignature65 = MlDsaSignature<Params65>;

/// Signing key for Arcanum-DSA-87
pub type ArcanumSigningKey87 = MlDsaSigningKey<Params87>;
/// Verifying key for Arcanum-DSA-87
pub type ArcanumVerifyingKey87 = MlDsaVerifyingKey<Params87>;
/// Signature for Arcanum-DSA-87
pub type ArcanumSignature87 = MlDsaSignature<Params87>;

/// Re-export the MlDsa trait for ergonomic usage
pub use crate::ml_dsa::MlDsa as ArcanumDsa;

/// Re-export error type
pub use crate::ml_dsa::MlDsaError as ArcanumDsaError;

// ═══════════════════════════════════════════════════════════════════════════════
// Size Constants
// ═══════════════════════════════════════════════════════════════════════════════

/// Arcanum-DSA-44 key and signature sizes
pub mod sizes_44 {
    use super::Params44;
    use crate::ml_dsa::params::MlDsaParams;

    /// Public key size in bytes
    pub const PK_SIZE: usize = Params44::PK_SIZE;
    /// Secret key size in bytes
    pub const SK_SIZE: usize = Params44::SK_SIZE;
    /// Signature size in bytes
    pub const SIG_SIZE: usize = Params44::SIG_SIZE;
}

/// Arcanum-DSA-65 key and signature sizes
pub mod sizes_65 {
    use super::Params65;
    use crate::ml_dsa::params::MlDsaParams;

    /// Public key size in bytes
    pub const PK_SIZE: usize = Params65::PK_SIZE;
    /// Secret key size in bytes
    pub const SK_SIZE: usize = Params65::SK_SIZE;
    /// Signature size in bytes
    pub const SIG_SIZE: usize = Params65::SIG_SIZE;
}

/// Arcanum-DSA-87 key and signature sizes
pub mod sizes_87 {
    use super::Params87;
    use crate::ml_dsa::params::MlDsaParams;

    /// Public key size in bytes
    pub const PK_SIZE: usize = Params87::PK_SIZE;
    /// Secret key size in bytes
    pub const SK_SIZE: usize = Params87::SK_SIZE;
    /// Signature size in bytes
    pub const SIG_SIZE: usize = Params87::SIG_SIZE;
}
