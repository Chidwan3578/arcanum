//! # Arcanum Protocols
//!
//! Cryptographic protocol implementations for secure communication.
//!
//! This crate provides high-level protocols built on Arcanum primitives:
//!
//! ## Key Exchange
//!
//! - **X25519 Key Exchange**: Elliptic curve Diffie-Hellman
//! - **Key Agreement**: Two-party key agreement with key confirmation
//!
//! ## Secure Channels
//!
//! - **Encrypted Channel**: Bidirectional encrypted communication
//! - **Authenticated Channel**: Encryption with message authentication
//!
//! ## Session Management
//!
//! - **Session Keys**: Derive session keys from shared secrets
//! - **Key Rotation**: Automatic key rotation support
//!
//! ## Example
//!
//! ```rust,no_run
//! use arcanum_protocols::prelude::*;
//!
//! # fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
//! // Key exchange between Alice and Bob
//! let (alice_secret, alice_public) = KeyExchangeProtocol::generate_keypair();
//! let (bob_secret, bob_public) = KeyExchangeProtocol::generate_keypair();
//!
//! // Both derive the same shared secret
//! let alice_shared = KeyExchangeProtocol::derive_shared_secret(&alice_secret, &bob_public)?;
//! let bob_shared = KeyExchangeProtocol::derive_shared_secret(&bob_secret, &alice_public)?;
//!
//! // Derive session keys
//! let alice_session = SessionKeys::derive(&alice_shared, b"session-v1")?;
//! let bob_session = SessionKeys::derive(&bob_shared, b"session-v1")?;
//!
//! // Create encrypted channels
//! let mut alice_channel = SecureChannel::new(alice_session);
//! let mut bob_channel = SecureChannel::new(bob_session);
//!
//! // Exchange encrypted messages
//! let encrypted = alice_channel.encrypt(b"Hello Bob!")?;
//! let decrypted = bob_channel.decrypt(&encrypted)?;
//! assert_eq!(decrypted, b"Hello Bob!");
//! # Ok(())
//! # }
//! ```

#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

mod error;

#[cfg(feature = "key-exchange")]
mod key_exchange;

#[cfg(feature = "secure-channel")]
mod channel;

#[cfg(feature = "secure-channel")]
mod session;

pub use error::{ProtocolError, Result};

#[cfg(feature = "key-exchange")]
pub use key_exchange::{KeyExchangeProtocol, ExchangePublicKey, ExchangeSecretKey, SharedSecret};

#[cfg(feature = "secure-channel")]
pub use channel::{SecureChannel, EncryptedMessage};

#[cfg(feature = "secure-channel")]
pub use session::SessionKeys;

/// Prelude for convenient imports.
pub mod prelude {
    pub use crate::error::{ProtocolError, Result};

    #[cfg(feature = "key-exchange")]
    pub use crate::key_exchange::{KeyExchangeProtocol, ExchangePublicKey, ExchangeSecretKey, SharedSecret};

    #[cfg(feature = "secure-channel")]
    pub use crate::channel::{SecureChannel, EncryptedMessage};

    #[cfg(feature = "secure-channel")]
    pub use crate::session::SessionKeys;
}
