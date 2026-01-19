//! # Arcanum Post-Quantum Cryptography
//!
//! Post-quantum cryptographic algorithms resistant to attacks by quantum computers.
//!
//! ## NIST Standards
//!
//! These algorithms are standardized by NIST for post-quantum cryptography:
//!
//! ### Key Encapsulation Mechanisms (KEMs)
//!
//! - **ML-KEM** (Module-Lattice KEM, formerly CRYSTALS-Kyber): FIPS 203
//!   - ML-KEM-512: 128-bit security
//!   - ML-KEM-768: 192-bit security (recommended)
//!   - ML-KEM-1024: 256-bit security
//!
//! ### Digital Signatures
//!
//! - **ML-DSA** (Module-Lattice Digital Signature, formerly CRYSTALS-Dilithium): FIPS 204
//!   - ML-DSA-44: 128-bit security
//!   - ML-DSA-65: 192-bit security (recommended)
//!   - ML-DSA-87: 256-bit security
//!
//! - **SLH-DSA** (Stateless Hash-based Digital Signature, formerly SPHINCS+): FIPS 205
//!   - Hash-based, very conservative security assumptions
//!
//! ## Hybrid Schemes
//!
//! Hybrid schemes combine classical and post-quantum algorithms for defense-in-depth:
//!
//! - **X25519-ML-KEM-768**: Classical ECDH + ML-KEM
//!
//! ## Example
//!
//! ```rust,no_run
//! use arcanum_pqc::prelude::*;
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // ML-KEM key encapsulation
//!     let (dk, ek) = MlKem768::generate_keypair()?;
//!     let (ciphertext, shared_secret) = MlKem768::encapsulate(&ek)?;
//!     let decapsulated = MlKem768::decapsulate(&dk, &ciphertext)?;
//!     assert_eq!(shared_secret, decapsulated);
//!
//!     // ML-DSA signatures
//!     let (sk, vk) = MlDsa65::generate_keypair()?;
//!     let signature = MlDsa65::sign(&sk, b"message")?;
//!     MlDsa65::verify(&vk, b"message", &signature)?;
//!     Ok(())
//! }
//! ```

#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

#[cfg(feature = "ml-kem")]
pub mod kem;

#[cfg(feature = "ml-dsa")]
pub mod dsa;

#[cfg(feature = "hybrid")]
pub mod hybrid;

mod traits;

pub use traits::{KeyEncapsulation, PostQuantumSignature};

#[cfg(feature = "ml-kem")]
pub use kem::{MlKem512, MlKem768, MlKem1024};

#[cfg(feature = "ml-dsa")]
pub use dsa::{MlDsa44, MlDsa65, MlDsa87};

#[cfg(feature = "hybrid")]
pub use hybrid::X25519MlKem768;

/// Prelude for convenient imports.
pub mod prelude {
    pub use crate::traits::{KeyEncapsulation, PostQuantumSignature};

    #[cfg(feature = "ml-kem")]
    pub use crate::kem::{MlKem512, MlKem768, MlKem1024};

    #[cfg(feature = "ml-dsa")]
    pub use crate::dsa::{MlDsa44, MlDsa65, MlDsa87};

    #[cfg(feature = "hybrid")]
    pub use crate::hybrid::X25519MlKem768;
}
