//! # Arcanum Core
//!
//! The foundational crate for the Arcanum cryptographic engine.
//!
//! This crate provides:
//! - Core traits for cryptographic operations
//! - Error types and result handling
//! - Secure memory types with automatic zeroization
//! - Cryptographically secure random number generation
//! - Key representations and type-safe wrappers
//! - Constant-time comparison utilities
//!
//! ## Design Principles
//!
//! 1. **Memory Safety**: All sensitive data is zeroized on drop
//! 2. **Type Safety**: Distinct types prevent mixing incompatible keys
//! 3. **Constant Time**: Side-channel resistant operations by default
//! 4. **Fail Secure**: Errors don't leak sensitive information
//! 5. **Composability**: Traits enable algorithm-agnostic code
//!
//! ## Example
//!
//! ```rust,no_run
//! use arcanum_core::prelude::*;
//!
//! // Use the random number generator
//! let mut rng = OsRng;
//!
//! // Encode data as hex
//! let data = b"Hello, Arcanum!";
//! let encoded = Hex::encode(data);
//! let decoded = Hex::decode(&encoded).unwrap();
//! assert_eq!(decoded, data);
//! ```

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms, unreachable_pub)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

pub mod buffer;
pub mod encoding;
pub mod error;
pub mod key;
pub mod nonce;
pub mod random;
pub mod traits;
pub mod time;
pub mod version;

/// Re-exports of commonly used types.
///
/// Import everything you need with a single line:
/// ```rust
/// use arcanum_core::prelude::*;
/// ```
pub mod prelude {
    // Buffer types
    pub use crate::buffer::{SecretBuffer, SecureVec};

    // Key type aliases
    pub use crate::buffer::{Key128, Key192, Key256, Key384, Key512};

    // Encoding utilities
    pub use crate::encoding::{Base58, Base64, Bech32, Hex, Pem};

    // Error handling
    pub use crate::error::{
        CertificateErrorKind, EncodingErrorKind, Error, HardwareErrorKind,
        ParseErrorKind, ProtocolErrorKind, Result, StorageErrorKind,
    };

    // Key types
    pub use crate::key::{
        KeyAlgorithm, KeyId, KeyMetadata, KeyPair, KeyUsage, PublicKey, SecretKey,
    };

    // Nonce management
    pub use crate::nonce::{Nonce, NonceGenerator, NonceTracker};

    // Random number generation
    pub use crate::random::{
        random_array, random_bytes, random_id, random_token,
        CryptoRng, DeterministicRng, OsRng, ThreadLocalRng,
    };

    // Core traits
    pub use crate::traits::*;

    // Timing utilities
    pub use crate::time::{
        constant_time, is_timestamp_valid, unix_timestamp,
        MonotonicClock, TimestampRange,
    };

    // Version info
    pub use crate::version::{AlgorithmId, ProtocolId, Version};

    // Re-exports from dependencies
    pub use crate::{Choice, ConstantTimeEq, CtOption};
    pub use crate::{ExposeSecret, SecretBox, SecretString};
    pub use crate::{Zeroize, ZeroizeOnDrop};
}

// Re-export for convenience
pub use zeroize::{Zeroize, ZeroizeOnDrop};
pub use secrecy::{ExposeSecret, SecretBox, SecretString};
pub use subtle::{Choice, ConstantTimeEq, CtOption};

/// Type alias for Secret for backwards compatibility
pub type Secret<T> = SecretBox<T>;
