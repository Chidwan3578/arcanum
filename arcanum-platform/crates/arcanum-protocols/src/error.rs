//! Error types for protocol operations.

use thiserror::Error;

// ═══════════════════════════════════════════════════════════════════════════════
// PROTOCOL-SPECIFIC ERROR KINDS
// ═══════════════════════════════════════════════════════════════════════════════

/// Key exchange failure reasons.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum KeyExchangeReason {
    /// Invalid public key received.
    #[error("invalid public key")]
    InvalidPublicKey,
    /// Point validation failed (not on curve).
    #[error("point not on curve")]
    PointNotOnCurve,
    /// Low-order point (small subgroup attack).
    #[error("low-order point detected")]
    LowOrderPoint,
    /// Identity point produced.
    #[error("identity point produced")]
    IdentityPoint,
    /// Contribution mismatch in multi-party.
    #[error("contribution mismatch")]
    ContributionMismatch,
    /// Other failure.
    #[error("{0}")]
    Other(String),
}

/// Key derivation failure reasons.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum KeyDerivationReason {
    /// Input key material too short.
    #[error("input key material too short")]
    IkmTooShort,
    /// Requested output length exceeds maximum.
    #[error("output length {requested} exceeds max {max}")]
    OutputTooLong {
        /// Requested length.
        requested: usize,
        /// Maximum allowed.
        max: usize,
    },
    /// Invalid salt.
    #[error("invalid salt")]
    InvalidSalt,
    /// Invalid info parameter.
    #[error("invalid info parameter")]
    InvalidInfo,
    /// Other failure.
    #[error("{0}")]
    Other(String),
}

/// Message validation failure reasons.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum InvalidMessageReason {
    /// Message too short.
    #[error("too short: expected at least {min} bytes, got {actual}")]
    TooShort {
        /// Minimum expected.
        min: usize,
        /// Actual length.
        actual: usize,
    },
    /// Message too long.
    #[error("too long: maximum {max} bytes, got {actual}")]
    TooLong {
        /// Maximum allowed.
        max: usize,
        /// Actual length.
        actual: usize,
    },
    /// Invalid header.
    #[error("invalid header")]
    InvalidHeader,
    /// Invalid version.
    #[error("unsupported version {0}")]
    UnsupportedVersion(u32),
    /// Invalid encoding.
    #[error("invalid encoding")]
    InvalidEncoding,
    /// Missing required field.
    #[error("missing field: {0}")]
    MissingField(String),
    /// Malformed structure.
    #[error("malformed structure")]
    Malformed,
}

/// Invalid key reasons.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum InvalidKeyReason {
    /// Wrong key length.
    #[error("wrong length: expected {expected}, got {actual}")]
    WrongLength {
        /// Expected length.
        expected: usize,
        /// Actual length.
        actual: usize,
    },
    /// Key is all zeros.
    #[error("key is all zeros")]
    AllZeros,
    /// Key is weak (e.g., low entropy).
    #[error("weak key detected")]
    WeakKey,
    /// Wrong key type for operation.
    #[error("wrong key type")]
    WrongType,
    /// Key has expired.
    #[error("key expired")]
    Expired,
    /// Key not yet valid.
    #[error("key not yet valid")]
    NotYetValid,
}

/// Protocol error type.
#[derive(Debug, Error)]
pub enum ProtocolError {
    /// Key exchange failed (typed reason).
    #[error("key exchange failed: {0}")]
    KeyExchange(KeyExchangeReason),

    /// Key exchange failed (legacy string).
    #[error("key exchange failed: {0}")]
    KeyExchangeFailed(String),

    /// Key derivation failed (typed reason).
    #[error("key derivation failed: {0}")]
    KeyDerivation(KeyDerivationReason),

    /// Key derivation failed (legacy string).
    #[error("key derivation failed: {0}")]
    KeyDerivationFailed(String),

    /// Encryption failed.
    #[error("encryption failed: {0}")]
    EncryptionFailed(String),

    /// Decryption failed.
    #[error("decryption failed: {0}")]
    DecryptionFailed(String),

    /// Authentication failed.
    #[error("authentication failed")]
    AuthenticationFailed,

    /// Invalid message format (typed reason).
    #[error("invalid message format: {0}")]
    InvalidMessageReason(InvalidMessageReason),

    /// Invalid message format (legacy string).
    #[error("invalid message format: {0}")]
    InvalidMessage(String),

    /// Session expired.
    #[error("session expired")]
    SessionExpired,

    /// Nonce reuse detected.
    #[error("nonce reuse detected")]
    NonceReuse,

    /// Replay attack detected.
    #[error("replay attack detected")]
    ReplayDetected,

    /// Counter overflow.
    #[error("counter overflow - key rotation required")]
    CounterOverflow,

    /// Invalid key (typed reason).
    #[error("invalid key: {0}")]
    InvalidKeyReason(InvalidKeyReason),

    /// Invalid key (legacy string).
    #[error("invalid key: {0}")]
    InvalidKey(String),

    /// Serialization error.
    #[error("serialization error: {0}")]
    SerializationError(String),

    /// Core cryptographic error.
    #[error("crypto error: {0}")]
    CryptoError(#[from] arcanum_core::error::Error),
}

/// Result type for protocol operations.
pub type Result<T> = std::result::Result<T, ProtocolError>;

impl From<bincode::Error> for ProtocolError {
    fn from(err: bincode::Error) -> Self {
        ProtocolError::SerializationError(err.to_string())
    }
}

impl ProtocolError {
    /// Check if this error indicates a security violation.
    pub fn is_security_violation(&self) -> bool {
        matches!(
            self,
            ProtocolError::NonceReuse
                | ProtocolError::ReplayDetected
                | ProtocolError::AuthenticationFailed
        )
    }

    /// Check if this error indicates a key exchange issue.
    pub fn is_key_exchange_error(&self) -> bool {
        matches!(
            self,
            ProtocolError::KeyExchange(_)
                | ProtocolError::KeyExchangeFailed(_)
                | ProtocolError::InvalidKeyReason(_)
                | ProtocolError::InvalidKey(_)
        )
    }

    /// Check if this error indicates the session should be terminated.
    pub fn should_terminate_session(&self) -> bool {
        matches!(
            self,
            ProtocolError::NonceReuse
                | ProtocolError::ReplayDetected
                | ProtocolError::CounterOverflow
                | ProtocolError::SessionExpired
                | ProtocolError::AuthenticationFailed
        )
    }
}
