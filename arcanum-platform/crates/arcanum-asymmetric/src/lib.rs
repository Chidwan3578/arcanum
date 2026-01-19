//! # Arcanum Asymmetric Cryptography
//!
//! Asymmetric (public-key) cryptography algorithms for encryption,
//! key exchange, and key agreement.
//!
//! ## RSA
//!
//! RSA encryption and signatures with modern padding schemes:
//! - **RSA-OAEP**: Optimal Asymmetric Encryption Padding
//! - **RSA-PSS**: Probabilistic Signature Scheme
//! - **RSA-PKCS#1**: Legacy padding (use OAEP/PSS for new applications)
//!
//! ## ECIES
//!
//! Elliptic Curve Integrated Encryption Scheme:
//! - ECIES-P256: Using NIST P-256 curve
//! - ECIES-P384: Using NIST P-384 curve
//! - ECIES-secp256k1: Using Bitcoin's curve
//!
//! ## Key Exchange
//!
//! - **X25519**: Curve25519 Diffie-Hellman (recommended)
//! - **X448**: Curve448 Diffie-Hellman (higher security)
//! - **ECDH**: Elliptic Curve Diffie-Hellman (P-256, P-384, secp256k1)
//!
//! ## Example
//!
//! ```rust,no_run
//! use arcanum_asymmetric::prelude::*;
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // X25519 key exchange
//!     let alice_secret = X25519SecretKey::generate();
//!     let alice_public = alice_secret.public_key();
//!
//!     let bob_secret = X25519SecretKey::generate();
//!     let bob_public = bob_secret.public_key();
//!
//!     let alice_shared = alice_secret.derive_shared_secret(&bob_public);
//!     let bob_shared = bob_secret.derive_shared_secret(&alice_public);
//!     assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
//!     Ok(())
//! }
//! ```

#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

mod traits;

#[cfg(feature = "rsa")]
pub mod rsa_impl;

#[cfg(feature = "ecies")]
pub mod ecies;

#[cfg(feature = "x25519")]
pub mod x25519;

#[cfg(feature = "x448")]
pub mod x448_impl;

pub mod ecdh;

pub use traits::*;

#[cfg(feature = "rsa")]
pub use rsa_impl::{
    RsaPrivateKey, RsaPublicKey, RsaKeyPair,
    RsaOaepCiphertext, RsaPkcs1Ciphertext,
    RsaPssSignature, RsaPkcs1Signature,
};

#[cfg(feature = "ecies")]
pub use ecies::{
    EciesP256, EciesP384, EciesSecp256k1,
    EciesCiphertext,
};

#[cfg(feature = "x25519")]
pub use x25519::{X25519SecretKey, X25519PublicKey, X25519SharedSecret};

#[cfg(feature = "x448")]
pub use x448_impl::{X448SecretKey, X448PublicKey, X448SharedSecret};

pub use ecdh::{
    EcdhP256, EcdhP384, EcdhSecp256k1,
    P256SecretKey, P256PublicKey,
    P384SecretKey, P384PublicKey,
    Secp256k1SecretKey, Secp256k1PublicKey,
};

/// Prelude for convenient imports.
pub mod prelude {
    pub use crate::traits::*;

    #[cfg(feature = "rsa")]
    pub use crate::rsa_impl::{RsaPrivateKey, RsaPublicKey, RsaKeyPair};

    #[cfg(feature = "ecies")]
    pub use crate::ecies::{EciesP256, EciesP384, EciesSecp256k1, EciesCiphertext};

    #[cfg(feature = "x25519")]
    pub use crate::x25519::{X25519SecretKey, X25519PublicKey, X25519SharedSecret};

    #[cfg(feature = "x448")]
    pub use crate::x448_impl::{X448SecretKey, X448PublicKey, X448SharedSecret};

    pub use crate::ecdh::{EcdhP256, EcdhP384, EcdhSecp256k1};
}
