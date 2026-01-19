//! Error types for keystore operations.

use arcanum_core::key::KeyId;
use thiserror::Error;

// ═══════════════════════════════════════════════════════════════════════════════
// KEYSTORE-SPECIFIC ERROR KINDS
// ═══════════════════════════════════════════════════════════════════════════════

/// Reason why a key ID is invalid.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum InvalidKeyIdReason {
    /// Empty key ID.
    #[error("key ID is empty")]
    Empty,
    /// Invalid UUID format.
    #[error("invalid UUID format")]
    InvalidFormat,
    /// Contains invalid characters.
    #[error("contains invalid characters")]
    InvalidCharacters,
    /// Key ID too long.
    #[error("key ID too long (max {max} bytes)")]
    TooLong {
        /// Maximum allowed length.
        max: usize,
    },
}

/// Serialization error reasons.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SerializationReason {
    /// JSON serialization failed.
    #[error("JSON: {0}")]
    Json(String),
    /// Binary serialization failed.
    #[error("binary: {0}")]
    Binary(String),
    /// Invalid data structure.
    #[error("invalid structure: {0}")]
    InvalidStructure(String),
}

/// Lock error reasons.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum LockReason {
    /// Lock is poisoned (previous holder panicked).
    #[error("lock poisoned")]
    Poisoned,
    /// Lock acquisition timed out.
    #[error("lock timeout")]
    Timeout,
    /// Lock already held by current thread.
    #[error("deadlock detected")]
    Deadlock,
}

/// Metadata validation error reasons.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum MetadataReason {
    /// Missing required field.
    #[error("missing field: {0}")]
    MissingField(String),
    /// Invalid field value.
    #[error("invalid field '{field}': {reason}")]
    InvalidField {
        /// Field name.
        field: String,
        /// Reason.
        reason: String,
    },
    /// Conflicting metadata values.
    #[error("conflicting values for {0}")]
    Conflicting(String),
}

/// Keystore error type.
#[derive(Debug, Error)]
pub enum KeyStoreError {
    /// Key not found in the store (typed ID).
    #[error("key not found: {0}")]
    KeyNotFound(KeyId),

    /// Key not found by string identifier.
    #[error("key not found: {0}")]
    KeyNotFoundByName(String),

    /// Key already exists (typed ID).
    #[error("key already exists: {0}")]
    KeyAlreadyExists(KeyId),

    /// Key already exists by string identifier.
    #[error("key already exists: {0}")]
    KeyAlreadyExistsByName(String),

    /// Invalid key ID (typed reason).
    #[error("invalid key id: {0}")]
    InvalidKeyIdReason(InvalidKeyIdReason),

    /// Invalid key ID (legacy string).
    #[error("invalid key id: {0}")]
    InvalidKeyId(String),

    /// Key has expired (typed ID).
    #[error("key expired: {0}")]
    KeyExpiredId(KeyId),

    /// Key has expired (legacy string).
    #[error("key expired: {0}")]
    KeyExpired(String),

    /// Key has been revoked (typed ID).
    #[error("key revoked: {0}")]
    KeyRevokedId(KeyId),

    /// Key has been revoked (legacy string).
    #[error("key revoked: {0}")]
    KeyRevoked(String),

    /// Storage I/O error (wrapped).
    #[error("storage error: {0}")]
    Storage(#[from] std::io::Error),

    /// Storage I/O error (legacy string).
    #[error("storage error: {0}")]
    StorageError(String),

    /// Serialization error (typed reason).
    #[error("serialization error: {0}")]
    Serialization(SerializationReason),

    /// Serialization error (legacy string).
    #[error("serialization error: {0}")]
    SerializationError(String),

    /// Encryption error.
    #[error("encryption error: {0}")]
    EncryptionError(String),

    /// Decryption error.
    #[error("decryption error: {0}")]
    DecryptionError(String),

    /// Lock acquisition failed (typed reason).
    #[error("lock error: {0}")]
    Lock(LockReason),

    /// Lock acquisition failed (legacy string).
    #[error("lock error: {0}")]
    LockError(String),

    /// Invalid metadata (typed reason).
    #[error("invalid metadata: {0}")]
    Metadata(MetadataReason),

    /// Invalid metadata (legacy string).
    #[error("invalid metadata: {0}")]
    InvalidMetadata(String),

    /// Core cryptographic error.
    #[error("crypto error: {0}")]
    CryptoError(#[from] arcanum_core::error::Error),
}

/// Result type for keystore operations.
pub type Result<T> = std::result::Result<T, KeyStoreError>;

impl From<serde_json::Error> for KeyStoreError {
    fn from(err: serde_json::Error) -> Self {
        KeyStoreError::Serialization(SerializationReason::Json(err.to_string()))
    }
}

impl From<bincode::Error> for KeyStoreError {
    fn from(err: bincode::Error) -> Self {
        KeyStoreError::Serialization(SerializationReason::Binary(err.to_string()))
    }
}

impl KeyStoreError {
    /// Check if this error indicates the key was not found.
    pub fn is_not_found(&self) -> bool {
        matches!(self, KeyStoreError::KeyNotFound(_) | KeyStoreError::KeyNotFoundByName(_))
    }

    /// Check if this error indicates the key already exists.
    pub fn is_already_exists(&self) -> bool {
        matches!(self, KeyStoreError::KeyAlreadyExists(_) | KeyStoreError::KeyAlreadyExistsByName(_))
    }

    /// Check if this error indicates a storage issue.
    pub fn is_storage_error(&self) -> bool {
        matches!(self, KeyStoreError::Storage(_) | KeyStoreError::StorageError(_))
    }

    /// Check if this error indicates a key state issue (expired/revoked).
    pub fn is_key_state_error(&self) -> bool {
        matches!(
            self,
            KeyStoreError::KeyExpired(_)
                | KeyStoreError::KeyExpiredId(_)
                | KeyStoreError::KeyRevoked(_)
                | KeyStoreError::KeyRevokedId(_)
        )
    }
}
