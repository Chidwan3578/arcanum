//! Error types for format operations.

use thiserror::Error;

/// Format error type.
#[derive(Debug, Error)]
pub enum FormatError {
    /// Invalid PEM format.
    #[error("invalid PEM format: {0}")]
    InvalidPem(String),

    /// Invalid Base64 encoding.
    #[error("invalid Base64: {0}")]
    InvalidBase64(String),

    /// Invalid hexadecimal encoding.
    #[error("invalid hex: {0}")]
    InvalidHex(String),

    /// Invalid label.
    #[error("invalid label: expected {expected}, got {actual}")]
    LabelMismatch {
        /// Expected label
        expected: String,
        /// Actual label found
        actual: String,
    },

    /// Data too short.
    #[error("data too short: expected at least {expected} bytes, got {actual}")]
    DataTooShort {
        /// Expected minimum length
        expected: usize,
        /// Actual length
        actual: usize,
    },

    /// Invalid character in input.
    #[error("invalid character at position {position}: {character:?}")]
    InvalidCharacter {
        /// Position of invalid character
        position: usize,
        /// The invalid character
        character: char,
    },
}

/// Result type for format operations.
pub type Result<T> = std::result::Result<T, FormatError>;
