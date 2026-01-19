//! Error types for threshold cryptography operations.

use thiserror::Error;

/// Errors that can occur during threshold cryptographic operations.
#[derive(Debug, Error)]
pub enum ThresholdError {
    /// Threshold must be at least 1.
    #[error("Threshold must be at least 1, got {threshold}")]
    ThresholdTooLow { threshold: usize },

    /// Threshold cannot exceed total number of shares.
    #[error("Threshold ({threshold}) cannot exceed total shares ({total})")]
    ThresholdExceedsTotal { threshold: usize, total: usize },

    /// Not enough shares provided to reconstruct the secret.
    #[error("Need at least {required} shares to reconstruct, got {provided}")]
    InsufficientShares { required: usize, provided: usize },

    /// Share indices must be unique for reconstruction.
    #[error("Duplicate share index {index} - all share indices must be unique")]
    DuplicateShareIndex { index: usize },

    /// Share failed verification against commitments.
    #[error("Share {index} failed verification - possible tampering detected")]
    ShareVerificationFailed { index: usize },

    /// Invalid share format or corrupted data.
    #[error("Invalid share data: {reason}")]
    InvalidShare { reason: String },

    /// DKG round error.
    #[error("DKG round {round} failed: {reason}")]
    DkgRoundError { round: usize, reason: String },

    /// Participant sent invalid commitment.
    #[error("Participant {participant} sent invalid commitment")]
    InvalidCommitment { participant: usize },

    /// Signing round error.
    #[error("Signing round {round} failed: {reason}")]
    SigningRoundError { round: usize, reason: String },

    /// Not enough signers for threshold.
    #[error("Need at least {required} signers, got {provided}")]
    InsufficientSigners { required: usize, provided: usize },

    /// Invalid signature share.
    #[error("Signature share from participant {participant} is invalid")]
    InvalidSignatureShare { participant: usize },

    /// Aggregated signature verification failed.
    #[error("Aggregated signature verification failed")]
    SignatureVerificationFailed,

    /// Secret has already been reconstructed (for proactive schemes).
    #[error("Secret already reconstructed - shares may have been exposed")]
    SecretAlreadyReconstructed,

    /// Polynomial evaluation error.
    #[error("Polynomial evaluation failed: {reason}")]
    PolynomialError { reason: String },

    /// Serialization error.
    #[error("Serialization error: {0}")]
    SerializationError(String),
}

/// Result type for threshold operations.
pub type ThresholdResult<T> = Result<T, ThresholdError>;
