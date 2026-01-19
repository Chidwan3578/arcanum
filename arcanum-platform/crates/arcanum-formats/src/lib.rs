//! # Arcanum Formats
//!
//! Cryptographic data format encoding and parsing.
//!
//! This crate provides utilities for encoding and decoding cryptographic
//! data in various formats:
//!
//! ## Encoding Formats
//!
//! - **PEM**: Privacy-Enhanced Mail format (RFC 7468)
//! - **Base64**: Standard and URL-safe Base64 encoding
//! - **Hex**: Hexadecimal encoding
//!
//! ## Example
//!
//! ```rust
//! use arcanum_formats::prelude::*;
//!
//! // Base64 encoding
//! let data = b"Hello, World!";
//! let encoded = Base64::encode(data);
//! let decoded = Base64::decode(&encoded).unwrap();
//! assert_eq!(decoded, data);
//!
//! // Hex encoding
//! let hex_encoded = Hex::encode(data);
//! let hex_decoded = Hex::decode(&hex_encoded).unwrap();
//! assert_eq!(hex_decoded, data);
//!
//! // PEM encoding for keys
//! let key_data = vec![0u8; 32];
//! let pem = Pem::encode("PRIVATE KEY", &key_data);
//! let (label, decoded) = Pem::decode(&pem).unwrap();
//! assert_eq!(label, "PRIVATE KEY");
//! assert_eq!(decoded, key_data);
//! ```

#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

mod error;

#[cfg(feature = "pem")]
mod pem;

#[cfg(feature = "base64")]
mod base64;

#[cfg(feature = "hex")]
mod hex_encoding;

pub use error::{FormatError, Result};

#[cfg(feature = "pem")]
pub use pem::Pem;

#[cfg(feature = "base64")]
pub use base64::Base64;

#[cfg(feature = "hex")]
pub use hex_encoding::Hex;

/// Prelude for convenient imports.
pub mod prelude {
    pub use crate::error::{FormatError, Result};

    #[cfg(feature = "pem")]
    pub use crate::pem::Pem;

    #[cfg(feature = "base64")]
    pub use crate::base64::Base64;

    #[cfg(feature = "hex")]
    pub use crate::hex_encoding::Hex;
}
