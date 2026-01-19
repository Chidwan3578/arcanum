//! Error types for cryptographic operations.
//!
//! All errors are designed to be:
//! - Non-leaking: Error messages don't reveal sensitive information
//! - Specific: Each error type has a clear meaning
//! - Recoverable: Where possible, errors indicate how to recover

use thiserror::Error;

// ═══════════════════════════════════════════════════════════════════════════════
// SPECIFIC ERROR TYPES
// ═══════════════════════════════════════════════════════════════════════════════

/// Encoding-specific errors with typed variants.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EncodingErrorKind {
    /// Invalid UTF-8 encoding.
    #[error("invalid UTF-8")]
    InvalidUtf8,
    /// Invalid Base64 encoding.
    #[error("invalid Base64")]
    InvalidBase64,
    /// Invalid hexadecimal encoding.
    #[error("invalid hex")]
    InvalidHex,
    /// Invalid PEM format.
    #[error("invalid PEM format")]
    InvalidPem,
    /// Invalid DER format.
    #[error("invalid DER format")]
    InvalidDer,
    /// Invalid JSON format.
    #[error("invalid JSON")]
    InvalidJson,
    /// Invalid CBOR format.
    #[error("invalid CBOR")]
    InvalidCbor,
    /// Data length mismatch.
    #[error("length mismatch: expected {expected}, got {actual}")]
    LengthMismatch {
        /// Expected length.
        expected: usize,
        /// Actual length.
        actual: usize,
    },
    /// Invalid padding.
    #[error("invalid padding")]
    InvalidPadding,
    /// Other encoding error with context.
    #[error("{0}")]
    Other(String),
}

/// Parsing-specific errors with typed variants.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ParseErrorKind {
    /// Invalid UUID format.
    #[error("invalid UUID")]
    InvalidUuid,
    /// Invalid date/time format.
    #[error("invalid datetime")]
    InvalidDateTime,
    /// Invalid numeric value.
    #[error("invalid number")]
    InvalidNumber,
    /// Invalid enum variant.
    #[error("invalid variant: {0}")]
    InvalidVariant(String),
    /// Missing required field.
    #[error("missing field: {0}")]
    MissingField(String),
    /// Unexpected token or character.
    #[error("unexpected token at position {position}")]
    UnexpectedToken {
        /// Position of unexpected token.
        position: usize,
    },
    /// End of input reached unexpectedly.
    #[error("unexpected end of input")]
    UnexpectedEof,
    /// Other parsing error with context.
    #[error("{0}")]
    Other(String),
}

/// Hardware-specific error types.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum HardwareErrorKind {
    /// HSM device error.
    #[error("HSM error: {0}")]
    Hsm(String),
    /// TPM device error.
    #[error("TPM error: {0}")]
    Tpm(String),
    /// Hardware security key (FIDO, etc.).
    #[error("security key error: {0}")]
    SecurityKey(String),
    /// Hardware not available.
    #[error("hardware not available")]
    NotAvailable,
    /// Hardware not initialized.
    #[error("hardware not initialized")]
    NotInitialized,
    /// Hardware busy.
    #[error("hardware busy")]
    Busy,
    /// Communication error with hardware.
    #[error("communication error")]
    CommunicationError,
    /// Hardware operation timeout.
    #[error("operation timeout")]
    Timeout,
}

/// Protocol-specific error types.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ProtocolErrorKind {
    /// Handshake failure.
    #[error("handshake failed: {0}")]
    HandshakeFailed(String),
    /// Invalid protocol state.
    #[error("invalid state: expected {expected}, got {actual}")]
    InvalidState {
        /// Expected state.
        expected: String,
        /// Actual state.
        actual: String,
    },
    /// Message too large.
    #[error("message too large: {size} bytes exceeds maximum {max}")]
    MessageTooLarge {
        /// Actual size.
        size: usize,
        /// Maximum allowed.
        max: usize,
    },
    /// Invalid message sequence number.
    #[error("invalid sequence: expected {expected}, got {actual}")]
    InvalidSequence {
        /// Expected sequence.
        expected: u64,
        /// Actual sequence.
        actual: u64,
    },
    /// Version mismatch.
    #[error("version mismatch: expected {expected}, got {actual}")]
    VersionMismatch {
        /// Expected version.
        expected: u32,
        /// Actual version.
        actual: u32,
    },
    /// Other protocol error.
    #[error("{0}")]
    Other(String),
}

/// Storage-specific error types.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum StorageErrorKind {
    /// Item not found.
    #[error("not found")]
    NotFound,
    /// Item already exists.
    #[error("already exists")]
    AlreadyExists,
    /// Permission denied.
    #[error("permission denied")]
    PermissionDenied,
    /// Storage full.
    #[error("storage full")]
    StorageFull,
    /// Corrupt data detected.
    #[error("corrupt data")]
    CorruptData,
    /// Lock contention.
    #[error("lock contention")]
    LockContention,
    /// I/O error with context.
    #[error("I/O error: {0}")]
    Io(String),
}

/// Certificate validation failure reasons.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CertificateErrorKind {
    /// Certificate has expired.
    #[error("expired")]
    Expired,
    /// Certificate not yet valid.
    #[error("not yet valid")]
    NotYetValid,
    /// Certificate has been revoked.
    #[error("revoked")]
    Revoked,
    /// Invalid signature on certificate.
    #[error("invalid signature")]
    InvalidSignature,
    /// Untrusted root certificate.
    #[error("untrusted root")]
    UntrustedRoot,
    /// Missing required extension.
    #[error("missing extension: {0}")]
    MissingExtension(String),
    /// Invalid key usage.
    #[error("invalid key usage")]
    InvalidKeyUsage,
    /// Path validation failed.
    #[error("path validation failed")]
    PathValidationFailed,
    /// Name constraint violation.
    #[error("name constraint violation")]
    NameConstraintViolation,
}

/// The primary error type for Arcanum operations.
#[derive(Debug, Error)]
pub enum Error {
    // ═══════════════════════════════════════════════════════════════════════════
    // KEY ERRORS
    // ═══════════════════════════════════════════════════════════════════════════
    /// Invalid key length
    #[error("invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength {
        /// Expected length in bytes
        expected: usize,
        /// Actual length received
        actual: usize,
    },

    /// Key generation failed
    #[error("key generation failed")]
    KeyGenerationFailed,

    /// Key derivation failed
    #[error("key derivation failed")]
    KeyDerivationFailed,

    /// Key not found in keystore (typed key ID).
    #[error("key not found: {0}")]
    KeyNotFound(crate::key::KeyId),

    /// Key not found by string identifier (for external/legacy IDs).
    #[error("key not found: {0}")]
    KeyNotFoundByName(String),

    /// Key has expired
    #[error("key expired")]
    KeyExpired,

    /// Key has been revoked
    #[error("key revoked")]
    KeyRevoked,

    /// Key is not yet valid
    #[error("key not yet valid")]
    KeyNotYetValid,

    /// Invalid key format
    #[error("invalid key format")]
    InvalidKeyFormat,

    /// Key import failed
    #[error("key import failed")]
    KeyImportFailed,

    /// Key export failed
    #[error("key export failed")]
    KeyExportFailed,

    // ═══════════════════════════════════════════════════════════════════════════
    // ENCRYPTION/DECRYPTION ERRORS
    // ═══════════════════════════════════════════════════════════════════════════
    /// Encryption operation failed
    #[error("encryption failed")]
    EncryptionFailed,

    /// Encryption failed with algorithm context.
    #[error("encryption failed using {algorithm}")]
    EncryptionFailedWith {
        /// Algorithm that failed.
        algorithm: String,
    },

    /// Decryption operation failed (authentication or integrity failure)
    #[error("decryption failed")]
    DecryptionFailed,

    /// Decryption failed with algorithm context.
    #[error("decryption failed using {algorithm}: authentication or integrity failure")]
    DecryptionFailedWith {
        /// Algorithm that failed.
        algorithm: String,
    },

    /// Invalid ciphertext
    #[error("invalid ciphertext")]
    InvalidCiphertext,

    /// Ciphertext too short
    #[error("ciphertext too short: minimum {minimum} bytes")]
    CiphertextTooShort {
        /// Minimum expected length
        minimum: usize,
    },

    /// Plaintext too large
    #[error("plaintext too large: maximum {maximum} bytes")]
    PlaintextTooLarge {
        /// Maximum allowed length
        maximum: usize,
    },

    // ═══════════════════════════════════════════════════════════════════════════
    // NONCE/IV ERRORS
    // ═══════════════════════════════════════════════════════════════════════════
    /// Invalid nonce length
    #[error("invalid nonce length: expected {expected}, got {actual}")]
    InvalidNonceLength {
        /// Expected length in bytes
        expected: usize,
        /// Actual length received
        actual: usize,
    },

    /// Nonce reuse detected
    #[error("nonce reuse detected - security violation")]
    NonceReuse,

    /// Nonce exhausted (counter overflow)
    #[error("nonce exhausted - key rotation required")]
    NonceExhausted,

    // ═══════════════════════════════════════════════════════════════════════════
    // SIGNATURE ERRORS
    // ═══════════════════════════════════════════════════════════════════════════
    /// Signature verification failed
    #[error("signature verification failed")]
    SignatureVerificationFailed,

    /// Invalid signature format
    #[error("invalid signature format")]
    InvalidSignature,

    /// Signing operation failed
    #[error("signing failed")]
    SigningFailed,

    /// Signing failed with algorithm context.
    #[error("signing failed using {algorithm}")]
    SigningFailedWith {
        /// Algorithm that failed.
        algorithm: String,
    },

    // ═══════════════════════════════════════════════════════════════════════════
    // HASH ERRORS
    // ═══════════════════════════════════════════════════════════════════════════
    /// Invalid hash length
    #[error("invalid hash length: expected {expected}, got {actual}")]
    InvalidHashLength {
        /// Expected length in bytes
        expected: usize,
        /// Actual length received
        actual: usize,
    },

    /// Hash verification failed
    #[error("hash verification failed")]
    HashVerificationFailed,

    // ═══════════════════════════════════════════════════════════════════════════
    // MAC ERRORS
    // ═══════════════════════════════════════════════════════════════════════════
    /// MAC verification failed
    #[error("MAC verification failed")]
    MacVerificationFailed,

    /// Invalid MAC length
    #[error("invalid MAC length")]
    InvalidMacLength,

    // ═══════════════════════════════════════════════════════════════════════════
    // CERTIFICATE/FORMAT ERRORS
    // ═══════════════════════════════════════════════════════════════════════════
    /// Certificate validation failed (typed reason).
    #[error("certificate validation failed: {0}")]
    CertificateValidation(CertificateErrorKind),

    /// Certificate validation failed (legacy string).
    #[error("certificate validation failed: {reason}")]
    CertificateValidationFailed {
        /// Reason for failure
        reason: String,
    },

    /// Invalid certificate chain
    #[error("invalid certificate chain")]
    InvalidCertificateChain,

    /// Unsupported format
    #[error("unsupported format: {0}")]
    UnsupportedFormat(String),

    /// Parse error (typed).
    #[error("parse error: {0}")]
    Parse(ParseErrorKind),

    /// Parse error (legacy string).
    #[error("parse error: {0}")]
    ParseError(String),

    /// Encoding error (typed).
    #[error("encoding error: {0}")]
    Encoding(EncodingErrorKind),

    /// Encoding error (legacy string).
    #[error("encoding error: {0}")]
    EncodingError(String),

    // ═══════════════════════════════════════════════════════════════════════════
    // ALGORITHM ERRORS
    // ═══════════════════════════════════════════════════════════════════════════
    /// Unsupported algorithm (typed).
    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithmKind(crate::key::KeyAlgorithm),

    /// Unsupported algorithm (legacy string).
    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    /// Algorithm mismatch (typed).
    #[error("algorithm mismatch: expected {expected}, got {actual}")]
    AlgorithmMismatchKind {
        /// Expected algorithm
        expected: crate::key::KeyAlgorithm,
        /// Actual algorithm
        actual: crate::key::KeyAlgorithm,
    },

    /// Algorithm mismatch (legacy string).
    #[error("algorithm mismatch: expected {expected}, got {actual}")]
    AlgorithmMismatch {
        /// Expected algorithm
        expected: String,
        /// Actual algorithm
        actual: String,
    },

    /// Weak algorithm (typed).
    #[error("weak algorithm: {0}")]
    WeakAlgorithmKind(crate::key::KeyAlgorithm),

    /// Weak algorithm (legacy string).
    #[error("weak algorithm: {0}")]
    WeakAlgorithm(String),

    // ═══════════════════════════════════════════════════════════════════════════
    // PROTOCOL ERRORS
    // ═══════════════════════════════════════════════════════════════════════════
    /// Protocol error (typed).
    #[error("protocol error: {0}")]
    Protocol(ProtocolErrorKind),

    /// Protocol error (legacy string).
    #[error("protocol error: {0}")]
    ProtocolError(String),

    /// Handshake failed
    #[error("handshake failed")]
    HandshakeFailed,

    /// Session expired
    #[error("session expired")]
    SessionExpired,

    /// Replay attack detected
    #[error("replay attack detected")]
    ReplayAttack,

    // ═══════════════════════════════════════════════════════════════════════════
    // HARDWARE/EXTERNAL ERRORS
    // ═══════════════════════════════════════════════════════════════════════════
    /// Hardware error (typed).
    #[error("hardware error: {0}")]
    Hardware(HardwareErrorKind),

    /// HSM error (legacy string).
    #[error("HSM error: {0}")]
    HsmError(String),

    /// TPM error (legacy string).
    #[error("TPM error: {0}")]
    TpmError(String),

    /// Hardware not available (legacy string).
    #[error("hardware not available: {0}")]
    HardwareNotAvailable(String),

    // ═══════════════════════════════════════════════════════════════════════════
    // RANDOM NUMBER GENERATION
    // ═══════════════════════════════════════════════════════════════════════════
    /// Random number generation failed
    #[error("random number generation failed")]
    RngFailed,

    /// Insufficient entropy
    #[error("insufficient entropy")]
    InsufficientEntropy,

    // ═══════════════════════════════════════════════════════════════════════════
    // STORAGE ERRORS
    // ═══════════════════════════════════════════════════════════════════════════
    /// Storage error (typed).
    #[error("storage error: {0}")]
    Storage(StorageErrorKind),

    /// Storage error (legacy string).
    #[error("storage error: {0}")]
    StorageError(String),

    /// Data corruption detected
    #[error("data corruption detected")]
    DataCorruption,

    // ═══════════════════════════════════════════════════════════════════════════
    // ZERO-KNOWLEDGE PROOF ERRORS
    // ═══════════════════════════════════════════════════════════════════════════
    /// Proof generation failed
    #[error("proof generation failed")]
    ProofGenerationFailed,

    /// Proof verification failed
    #[error("proof verification failed")]
    ProofVerificationFailed,

    /// Invalid witness
    #[error("invalid witness")]
    InvalidWitness,

    /// Invalid proof
    #[error("invalid proof")]
    InvalidProof,

    // ═══════════════════════════════════════════════════════════════════════════
    // THRESHOLD/SECRET SHARING ERRORS
    // ═══════════════════════════════════════════════════════════════════════════
    /// Insufficient shares for reconstruction
    #[error("insufficient shares: need {threshold}, got {provided}")]
    InsufficientShares {
        /// Threshold required
        threshold: usize,
        /// Number of shares provided
        provided: usize,
    },

    /// Invalid share
    #[error("invalid share")]
    InvalidShare,

    /// Duplicate share
    #[error("duplicate share")]
    DuplicateShare,

    // ═══════════════════════════════════════════════════════════════════════════
    // GENERIC ERRORS
    // ═══════════════════════════════════════════════════════════════════════════
    /// Invalid parameter with context.
    #[error("invalid parameter '{name}': {reason}")]
    InvalidParameterContext {
        /// Parameter name.
        name: String,
        /// Reason it's invalid.
        reason: String,
    },

    /// Invalid parameter (legacy string).
    #[error("invalid parameter: {0}")]
    InvalidParameter(String),

    /// Operation not permitted
    #[error("operation not permitted")]
    NotPermitted,

    /// Internal error (should not happen)
    #[error("internal error: {0}")]
    InternalError(String),

    /// Feature not implemented
    #[error("not implemented: {0}")]
    NotImplemented(String),

    /// I/O error (wrapped).
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// I/O error (legacy string).
    #[error("I/O error: {0}")]
    IoError(String),
}

/// Result type alias for Arcanum operations.
pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    /// Check if this error indicates authentication failure.
    pub fn is_authentication_failure(&self) -> bool {
        matches!(
            self,
            Error::DecryptionFailed
                | Error::SignatureVerificationFailed
                | Error::MacVerificationFailed
                | Error::HashVerificationFailed
        )
    }

    /// Check if this error indicates a key-related issue.
    pub fn is_key_error(&self) -> bool {
        matches!(
            self,
            Error::InvalidKeyLength { .. }
                | Error::KeyGenerationFailed
                | Error::KeyDerivationFailed
                | Error::KeyNotFound(_)
                | Error::KeyNotFoundByName(_)
                | Error::KeyExpired
                | Error::KeyRevoked
                | Error::KeyNotYetValid
                | Error::InvalidKeyFormat
                | Error::KeyImportFailed
                | Error::KeyExportFailed
        )
    }

    /// Check if this error indicates a security violation.
    pub fn is_security_violation(&self) -> bool {
        matches!(
            self,
            Error::NonceReuse
                | Error::ReplayAttack
                | Error::DataCorruption
                | Error::WeakAlgorithm(_)
                | Error::WeakAlgorithmKind(_)
        )
    }

    /// Check if this error indicates a protocol issue.
    pub fn is_protocol_error(&self) -> bool {
        matches!(
            self,
            Error::Protocol(_)
                | Error::ProtocolError(_)
                | Error::HandshakeFailed
                | Error::SessionExpired
                | Error::ReplayAttack
        )
    }

    /// Check if this error indicates a hardware issue.
    pub fn is_hardware_error(&self) -> bool {
        matches!(
            self,
            Error::Hardware(_)
                | Error::HsmError(_)
                | Error::TpmError(_)
                | Error::HardwareNotAvailable(_)
        )
    }

    /// Check if this error indicates a storage issue.
    pub fn is_storage_error(&self) -> bool {
        matches!(
            self,
            Error::Storage(_)
                | Error::StorageError(_)
                | Error::DataCorruption
                | Error::Io(_)
                | Error::IoError(_)
        )
    }

    /// Check if this error indicates a format/encoding issue.
    pub fn is_format_error(&self) -> bool {
        matches!(
            self,
            Error::Encoding(_)
                | Error::EncodingError(_)
                | Error::Parse(_)
                | Error::ParseError(_)
                | Error::UnsupportedFormat(_)
                | Error::InvalidKeyFormat
        )
    }

    /// Check if this error is potentially recoverable.
    ///
    /// Recoverable errors include temporary failures, resource contention,
    /// and issues that might succeed on retry or with different parameters.
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            Error::Hardware(HardwareErrorKind::Busy)
                | Error::Hardware(HardwareErrorKind::Timeout)
                | Error::Hardware(HardwareErrorKind::CommunicationError)
                | Error::Storage(StorageErrorKind::LockContention)
                | Error::RngFailed
                | Error::InsufficientEntropy
                | Error::InsufficientShares { .. }
        )
    }

    /// Get a suggestion for how to resolve this error, if available.
    ///
    /// Returns actionable advice for common errors to help users recover.
    ///
    /// # Example
    ///
    /// ```rust
    /// use arcanum_core::error::Error;
    ///
    /// let err = Error::InvalidKeyLength { expected: 32, actual: 16 };
    /// if let Some(suggestion) = err.suggestion() {
    ///     println!("Hint: {}", suggestion);
    /// }
    /// ```
    pub fn suggestion(&self) -> Option<&'static str> {
        match self {
            // Key errors
            Error::InvalidKeyLength { expected, .. } => match *expected {
                16 => Some("Use a 128-bit (16-byte) key for AES-128"),
                24 => Some("Use a 192-bit (24-byte) key for AES-192"),
                32 => Some("Use a 256-bit (32-byte) key for AES-256 or ChaCha20"),
                _ => Some("Check the algorithm's key size requirements"),
            },
            Error::KeyExpired => Some("Generate a new key pair or request key renewal"),
            Error::KeyRevoked => Some("This key can no longer be used; generate a new key pair"),
            Error::KeyNotYetValid => Some("Wait until the key's validity period begins"),
            Error::KeyNotFound(_) | Error::KeyNotFoundByName(_) => {
                Some("Ensure the key exists in the keystore or import it first")
            }
            Error::KeyDerivationFailed => {
                Some("Check password/salt parameters and ensure sufficient memory for Argon2")
            }

            // Nonce errors
            Error::InvalidNonceLength { expected, .. } => match *expected {
                12 => Some("Use a 96-bit (12-byte) nonce for AES-GCM"),
                24 => Some("Use a 192-bit (24-byte) nonce for XChaCha20"),
                _ => Some("Check the algorithm's nonce size requirements"),
            },
            Error::NonceReuse => {
                Some("CRITICAL: Never reuse nonces with the same key; regenerate both key and nonce")
            }
            Error::NonceExhausted => Some("Rotate to a new key; current key has exceeded safe nonce usage"),

            // Authentication failures
            Error::DecryptionFailed | Error::DecryptionFailedWith { .. } => {
                Some("Verify the correct key is used and data hasn't been tampered with")
            }
            Error::SignatureVerificationFailed => {
                Some("Verify the correct public key is used and message hasn't been modified")
            }
            Error::MacVerificationFailed => {
                Some("Verify the correct key is used and message hasn't been modified")
            }

            // Threshold/secret sharing
            Error::InsufficientShares { threshold, .. } => {
                if *threshold <= 3 {
                    Some("Collect more shares from other shareholders")
                } else {
                    Some("Collect more shares; consider lowering threshold for future secrets")
                }
            }
            Error::DuplicateShare => Some("Each share must be unique; remove duplicate shares"),

            // Hardware
            Error::Hardware(HardwareErrorKind::NotAvailable) => {
                Some("Ensure the hardware device is connected and drivers are installed")
            }
            Error::Hardware(HardwareErrorKind::NotInitialized) => {
                Some("Initialize the hardware device before use")
            }
            Error::Hardware(HardwareErrorKind::Busy) => {
                Some("Wait and retry; the hardware device is processing another request")
            }
            Error::Hardware(HardwareErrorKind::Timeout) => {
                Some("Check device connection and retry the operation")
            }

            // Storage
            Error::Storage(StorageErrorKind::StorageFull) => {
                Some("Free up storage space or archive old keys")
            }
            Error::Storage(StorageErrorKind::PermissionDenied) => {
                Some("Check file/directory permissions and user privileges")
            }
            Error::Storage(StorageErrorKind::LockContention) => {
                Some("Wait and retry; another process is accessing the storage")
            }

            // Certificate
            Error::CertificateValidation(CertificateErrorKind::Expired) => {
                Some("Renew the certificate or obtain a new one from the CA")
            }
            Error::CertificateValidation(CertificateErrorKind::NotYetValid) => {
                Some("Wait until the certificate's validity period begins or check system clock")
            }
            Error::CertificateValidation(CertificateErrorKind::UntrustedRoot) => {
                Some("Add the root certificate to your trust store")
            }
            Error::CertificateValidation(CertificateErrorKind::Revoked) => {
                Some("This certificate has been revoked; obtain a new certificate")
            }

            // Algorithms
            Error::WeakAlgorithm(_) | Error::WeakAlgorithmKind(_) => {
                Some("Use a modern algorithm: AES-256-GCM, ChaCha20-Poly1305, or Ed25519")
            }
            Error::UnsupportedAlgorithm(_) | Error::UnsupportedAlgorithmKind(_) => {
                Some("Check supported algorithms in documentation")
            }

            // RNG
            Error::RngFailed | Error::InsufficientEntropy => {
                Some("Retry the operation; ensure system entropy sources are available")
            }

            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_categories() {
        let err = Error::DecryptionFailed;
        assert!(err.is_authentication_failure());
        assert!(!err.is_key_error());

        let err = Error::KeyExpired;
        assert!(err.is_key_error());
        assert!(!err.is_authentication_failure());

        let err = Error::NonceReuse;
        assert!(err.is_security_violation());
    }

    #[test]
    fn test_error_display() {
        let err = Error::InvalidKeyLength {
            expected: 32,
            actual: 16,
        };
        assert_eq!(
            err.to_string(),
            "invalid key length: expected 32, got 16"
        );
    }

    #[test]
    fn test_typed_encoding_error() {
        let err = Error::Encoding(EncodingErrorKind::InvalidBase64);
        assert!(err.is_format_error());
        assert_eq!(err.to_string(), "encoding error: invalid Base64");

        let err = Error::Encoding(EncodingErrorKind::LengthMismatch {
            expected: 32,
            actual: 16,
        });
        assert_eq!(err.to_string(), "encoding error: length mismatch: expected 32, got 16");
    }

    #[test]
    fn test_typed_parse_error() {
        let err = Error::Parse(ParseErrorKind::InvalidUuid);
        assert!(err.is_format_error());
        assert_eq!(err.to_string(), "parse error: invalid UUID");

        let err = Error::Parse(ParseErrorKind::MissingField("algorithm".to_string()));
        assert_eq!(err.to_string(), "parse error: missing field: algorithm");
    }

    #[test]
    fn test_typed_protocol_error() {
        let err = Error::Protocol(ProtocolErrorKind::InvalidSequence {
            expected: 5,
            actual: 3,
        });
        assert!(err.is_protocol_error());
        assert_eq!(err.to_string(), "protocol error: invalid sequence: expected 5, got 3");
    }

    #[test]
    fn test_typed_storage_error() {
        let err = Error::Storage(StorageErrorKind::NotFound);
        assert!(err.is_storage_error());
        assert_eq!(err.to_string(), "storage error: not found");

        let err = Error::Storage(StorageErrorKind::PermissionDenied);
        assert_eq!(err.to_string(), "storage error: permission denied");
    }

    #[test]
    fn test_typed_hardware_error() {
        let err = Error::Hardware(HardwareErrorKind::NotAvailable);
        assert!(err.is_hardware_error());
        assert_eq!(err.to_string(), "hardware error: hardware not available");

        let err = Error::Hardware(HardwareErrorKind::Timeout);
        assert_eq!(err.to_string(), "hardware error: operation timeout");
    }

    #[test]
    fn test_typed_certificate_error() {
        let err = Error::CertificateValidation(CertificateErrorKind::Expired);
        assert_eq!(err.to_string(), "certificate validation failed: expired");

        let err = Error::CertificateValidation(CertificateErrorKind::UntrustedRoot);
        assert_eq!(err.to_string(), "certificate validation failed: untrusted root");
    }

    #[test]
    fn test_invalid_parameter_context() {
        let err = Error::InvalidParameterContext {
            name: "iterations".to_string(),
            reason: "must be at least 1".to_string(),
        };
        assert_eq!(err.to_string(), "invalid parameter 'iterations': must be at least 1");
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // SUGGESTION TESTS
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_suggestion_key_length() {
        let err = Error::InvalidKeyLength { expected: 32, actual: 16 };
        assert!(err.suggestion().is_some());
        assert!(err.suggestion().unwrap().contains("256-bit"));

        let err = Error::InvalidKeyLength { expected: 16, actual: 8 };
        assert!(err.suggestion().unwrap().contains("128-bit"));
    }

    #[test]
    fn test_suggestion_nonce_length() {
        let err = Error::InvalidNonceLength { expected: 12, actual: 8 };
        assert!(err.suggestion().unwrap().contains("AES-GCM"));

        let err = Error::InvalidNonceLength { expected: 24, actual: 12 };
        assert!(err.suggestion().unwrap().contains("XChaCha20"));
    }

    #[test]
    fn test_suggestion_nonce_reuse() {
        let err = Error::NonceReuse;
        let suggestion = err.suggestion().unwrap();
        assert!(suggestion.contains("CRITICAL"));
        assert!(suggestion.contains("Never reuse"));
    }

    #[test]
    fn test_suggestion_decryption_failed() {
        let err = Error::DecryptionFailed;
        assert!(err.suggestion().unwrap().contains("correct key"));

        let err = Error::DecryptionFailedWith { algorithm: "AES-256-GCM".to_string() };
        assert!(err.suggestion().unwrap().contains("correct key"));
    }

    #[test]
    fn test_suggestion_hardware_errors() {
        let err = Error::Hardware(HardwareErrorKind::Busy);
        assert!(err.suggestion().unwrap().contains("retry"));

        let err = Error::Hardware(HardwareErrorKind::NotAvailable);
        assert!(err.suggestion().unwrap().contains("connected"));
    }

    #[test]
    fn test_suggestion_certificate_errors() {
        let err = Error::CertificateValidation(CertificateErrorKind::Expired);
        assert!(err.suggestion().unwrap().contains("Renew"));

        let err = Error::CertificateValidation(CertificateErrorKind::UntrustedRoot);
        assert!(err.suggestion().unwrap().contains("trust store"));
    }

    #[test]
    fn test_suggestion_returns_none_for_internal_errors() {
        let err = Error::InternalError("something went wrong".to_string());
        assert!(err.suggestion().is_none());
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // RECOVERABLE TESTS
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_is_recoverable() {
        // Recoverable errors
        assert!(Error::Hardware(HardwareErrorKind::Busy).is_recoverable());
        assert!(Error::Hardware(HardwareErrorKind::Timeout).is_recoverable());
        assert!(Error::Storage(StorageErrorKind::LockContention).is_recoverable());
        assert!(Error::RngFailed.is_recoverable());
        assert!(Error::InsufficientEntropy.is_recoverable());
        assert!(Error::InsufficientShares { threshold: 3, provided: 2 }.is_recoverable());

        // Non-recoverable errors
        assert!(!Error::DecryptionFailed.is_recoverable());
        assert!(!Error::KeyRevoked.is_recoverable());
        assert!(!Error::NonceReuse.is_recoverable());
        assert!(!Error::DataCorruption.is_recoverable());
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // CONTEXTUAL ERROR VARIANT TESTS
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_encryption_failed_with_context() {
        let err = Error::EncryptionFailedWith { algorithm: "AES-256-GCM".to_string() };
        assert_eq!(err.to_string(), "encryption failed using AES-256-GCM");
    }

    #[test]
    fn test_decryption_failed_with_context() {
        let err = Error::DecryptionFailedWith { algorithm: "ChaCha20-Poly1305".to_string() };
        assert!(err.to_string().contains("ChaCha20-Poly1305"));
        assert!(err.to_string().contains("authentication"));
    }

    #[test]
    fn test_signing_failed_with_context() {
        let err = Error::SigningFailedWith { algorithm: "Ed25519".to_string() };
        assert_eq!(err.to_string(), "signing failed using Ed25519");
    }
}
