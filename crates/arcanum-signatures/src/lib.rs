//! # Arcanum Digital Signatures
//!
//! High-performance digital signature algorithms with a unified interface.
//!
//! ## Supported Algorithms
//!
//! ### Edwards Curves
//!
//! - **Ed25519**: Fast, secure, widely used. Recommended default.
//!
//! ### ECDSA (Elliptic Curve Digital Signature Algorithm)
//!
//! - **ECDSA-P256**: NIST P-256 curve, widely supported
//! - **ECDSA-P384**: NIST P-384 curve, higher security level
//! - **ECDSA-secp256k1**: Bitcoin/Ethereum curve
//!
//! ### Schnorr Signatures
//!
//! - **Schnorr-secp256k1**: BIP-340 compatible (Bitcoin Taproot)
//!
//! ## Example
//!
//! ```ignore
//! use arcanum_signatures::{Ed25519, SigningKey};
//!
//! // Generate a new key pair
//! let signing_key = Ed25519::generate();
//! let verifying_key = signing_key.verifying_key();
//!
//! // Sign a message
//! let message = b"Hello, Arcanum!";
//! let signature = signing_key.sign(message);
//!
//! // Verify
//! assert!(verifying_key.verify(message, &signature).is_ok());
//! ```
//!
//! ## Security Considerations
//!
//! - Always use fresh randomness for key generation
//! - Protect signing keys from exposure
//! - Ed25519 provides deterministic signatures (no additional randomness needed)
//! - ECDSA requires secure random nonces (use deterministic RFC 6979 variant)

#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

#[cfg(feature = "ed25519")]
pub mod ed25519;

#[cfg(feature = "ecdsa")]
pub mod ecdsa_impl;

#[cfg(feature = "schnorr")]
pub mod schnorr;

mod traits;

pub use traits::{SigningKey, VerifyingKey, Signature, BatchVerifier};

#[cfg(feature = "ed25519")]
pub use ed25519::{Ed25519SigningKey, Ed25519VerifyingKey, Ed25519Signature};

#[cfg(feature = "ecdsa")]
pub use ecdsa_impl::{
    P256SigningKey, P256VerifyingKey, P256Signature,
    P384SigningKey, P384VerifyingKey, P384Signature,
    Secp256k1SigningKey, Secp256k1VerifyingKey, Secp256k1Signature,
};

#[cfg(feature = "schnorr")]
pub use schnorr::{SchnorrSigningKey, SchnorrVerifyingKey, SchnorrSignature};

/// Prelude for convenient imports.
pub mod prelude {
    pub use crate::traits::{SigningKey, VerifyingKey, Signature};

    #[cfg(feature = "ed25519")]
    pub use crate::ed25519::{Ed25519SigningKey, Ed25519VerifyingKey, Ed25519Signature};

    #[cfg(feature = "ecdsa")]
    pub use crate::ecdsa_impl::{
        P256SigningKey, P256VerifyingKey, P256Signature,
        Secp256k1SigningKey, Secp256k1VerifyingKey, Secp256k1Signature,
    };

    #[cfg(feature = "schnorr")]
    pub use crate::schnorr::{SchnorrSigningKey, SchnorrVerifyingKey, SchnorrSignature};
}
