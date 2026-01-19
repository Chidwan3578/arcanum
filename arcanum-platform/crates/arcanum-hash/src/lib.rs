//! # Arcanum Hash
//!
//! Cryptographic hash functions and key derivation for the Arcanum engine.
//!
//! ## Hash Functions
//!
//! - **SHA-2**: SHA-256, SHA-384, SHA-512 (NIST standard)
//! - **SHA-3**: SHA3-256, SHA3-512, SHAKE128, SHAKE256 (Keccak)
//! - **Blake2**: Blake2b, Blake2s (fast, secure)
//! - **Blake3**: Ultra-fast, parallelizable
//!
//! ## Key Derivation Functions
//!
//! - **Argon2id**: Password hashing (PHC winner, recommended)
//! - **HKDF**: Key derivation from high-entropy input (RFC 5869)
//! - **scrypt**: Memory-hard password hashing
//! - **PBKDF2**: Legacy password hashing
//!
//! ## Message Authentication Codes
//!
//! - **HMAC**: Hash-based MAC (with any hash function)
//!
//! ## Example
//!
//! ```rust,no_run
//! use arcanum_hash::prelude::*;
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Simple hashing
//!     let hash = Sha256::hash(b"hello world");
//!
//!     // Incremental hashing
//!     let mut hasher = Blake3::new();
//!     hasher.update(b"hello ");
//!     hasher.update(b"world");
//!     let hash = hasher.finalize();
//!
//!     // Password hashing
//!     let hash = Argon2::hash_password(b"password", &Argon2Params::default())?;
//!     assert!(Argon2::verify_password(b"password", &hash)?);
//!
//!     // Key derivation (using type alias for HKDF-SHA256)
//!     let ikm = b"input key material";
//!     let salt = Some(b"salt".as_slice());
//!     let info = Some(b"info".as_slice());
//!     let key = HkdfSha256::derive(ikm, salt, info, 32)?;
//!     Ok(())
//! }
//! ```

#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

#[cfg(feature = "sha2")]
pub mod sha2_impl;

#[cfg(feature = "sha3")]
pub mod sha3_impl;

#[cfg(feature = "blake2")]
pub mod blake2_impl;

#[cfg(feature = "blake3")]
pub mod blake3_impl;

#[cfg(feature = "argon2")]
pub mod argon2_impl;

#[cfg(feature = "hkdf")]
pub mod hkdf_impl;

#[cfg(feature = "scrypt")]
pub mod scrypt_impl;

#[cfg(feature = "mac")]
pub mod hmac_impl;

mod traits;

pub use traits::{Hasher, HashOutput, KeyDerivation, PasswordHash};

#[cfg(feature = "sha2")]
pub use sha2_impl::{Sha256, Sha384, Sha512};

#[cfg(feature = "sha3")]
pub use sha3_impl::{Sha3_256, Sha3_512, Shake128, Shake256};

#[cfg(feature = "blake2")]
pub use blake2_impl::{Blake2b, Blake2s};

#[cfg(feature = "blake3")]
pub use blake3_impl::Blake3;

#[cfg(feature = "argon2")]
pub use argon2_impl::{Argon2, Argon2Params, Argon2ParamsBuilder};

#[cfg(feature = "hkdf")]
pub use hkdf_impl::Hkdf;

/// Re-export sha2 crate types for use with generic types like Hkdf<T>.
///
/// Use `arcanum_hash::sha2_types::Sha256` with `Hkdf<Sha256>`.
#[cfg(feature = "sha2")]
pub mod sha2_types {
    pub use sha2::{Sha256, Sha384, Sha512};
}

#[cfg(feature = "scrypt")]
pub use scrypt_impl::{Scrypt, ScryptParams, ScryptParamsBuilder};

#[cfg(feature = "mac")]
pub use hmac_impl::Hmac;

/// Prelude for convenient imports.
///
/// Import everything you need with a single line:
/// ```rust
/// use arcanum_hash::prelude::*;
/// ```
pub mod prelude {
    // Core traits
    pub use crate::traits::{Hasher, HashOutput, KeyDerivation, PasswordHash};

    // SHA-2 family
    #[cfg(feature = "sha2")]
    pub use crate::sha2_impl::{Sha256, Sha384, Sha512};

    // SHA-3 family
    #[cfg(feature = "sha3")]
    pub use crate::sha3_impl::{Sha3_256, Sha3_512, Shake128, Shake256};

    // Blake family
    #[cfg(feature = "blake2")]
    pub use crate::blake2_impl::{Blake2b, Blake2s};

    #[cfg(feature = "blake3")]
    pub use crate::blake3_impl::Blake3;

    // Password hashing
    #[cfg(feature = "argon2")]
    pub use crate::argon2_impl::{Argon2, Argon2Params, Argon2ParamsBuilder};

    #[cfg(feature = "scrypt")]
    pub use crate::scrypt_impl::{Scrypt, ScryptParams, ScryptParamsBuilder};

    // Key derivation
    #[cfg(feature = "hkdf")]
    pub use crate::hkdf_impl::{Hkdf, HkdfSha256, HkdfSha384, HkdfSha512};

    // Message authentication
    #[cfg(feature = "mac")]
    pub use crate::hmac_impl::Hmac;
}
