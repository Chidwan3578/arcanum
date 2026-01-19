//! # Arcanum Symmetric Encryption
//!
//! High-performance symmetric encryption algorithms with a unified interface.
//!
//! ## Supported Algorithms
//!
//! ### AEAD (Authenticated Encryption with Associated Data)
//!
//! - **AES-256-GCM**: Industry standard, hardware-accelerated on modern CPUs
//! - **AES-128-GCM**: Faster variant with 128-bit keys
//! - **AES-256-GCM-SIV**: Nonce-misuse resistant variant
//! - **ChaCha20-Poly1305**: Fast software implementation, constant-time
//! - **XChaCha20-Poly1305**: Extended nonce variant (192-bit nonces)
//!
//! ### Stream Ciphers
//!
//! - **AES-CTR**: Counter mode for streaming encryption
//! - **ChaCha20**: Standalone stream cipher
//!
//! ## Example
//!
//! ```rust,no_run
//! use arcanum_symmetric::prelude::*;
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Generate a random key and nonce
//!     let key = Aes256Gcm::generate_key();
//!     let nonce = Aes256Gcm::generate_nonce();
//!
//!     // Encrypt
//!     let plaintext = b"secret message";
//!     let ciphertext = Aes256Gcm::encrypt(&key, &nonce, plaintext, None)?;
//!
//!     // Decrypt
//!     let decrypted = Aes256Gcm::decrypt(&key, &nonce, &ciphertext, None)?;
//!     assert_eq!(decrypted, plaintext);
//!     Ok(())
//! }
//! ```
//!
//! ## Security Considerations
//!
//! - **Never reuse nonces** with the same key. This is catastrophic for GCM.
//! - Use XChaCha20-Poly1305 if nonce reuse is a concern (larger nonce space).
//! - Use AES-256-GCM-SIV for nonce-misuse resistance.

#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

#[cfg(feature = "aes")]
pub mod aes_ciphers;

#[cfg(feature = "chacha20")]
pub mod chacha_ciphers;

mod traits;
mod encrypted;
pub mod types;

pub use encrypted::{EncryptedData, EncryptedPayload};
pub use traits::{Cipher, CipherBuilder, CipherInstance, NonceStrategy, StreamCipher};
pub use types::{Plaintext, Ciphertext, Nonce, Nonce96, Nonce128, Nonce192};

#[cfg(feature = "aes")]
pub use aes_ciphers::{Aes128Gcm, Aes256Gcm, Aes256GcmSiv, Aes256Ctr};

#[cfg(feature = "chacha20")]
pub use chacha_ciphers::{ChaCha20Poly1305Cipher, XChaCha20Poly1305Cipher, ChaCha20Stream};

#[cfg(test)]
mod proptest_tests;

/// Prelude for convenient imports.
pub mod prelude {
    pub use crate::traits::{Cipher, CipherBuilder, CipherInstance, NonceStrategy, StreamCipher};
    pub use crate::encrypted::{EncryptedData, EncryptedPayload};
    pub use crate::types::{Plaintext, Ciphertext, Nonce, Nonce96, Nonce128, Nonce192};

    #[cfg(feature = "aes")]
    pub use crate::aes_ciphers::{Aes128Gcm, Aes256Gcm, Aes256GcmSiv};

    #[cfg(feature = "chacha20")]
    pub use crate::chacha_ciphers::{ChaCha20Poly1305Cipher, XChaCha20Poly1305Cipher};
}
