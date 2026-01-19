//! Core traits for threshold cryptography.

use crate::errors::ThresholdResult;

/// Trait for secret sharing schemes.
pub trait SecretSharing {
    /// The type of individual shares.
    type Share;

    /// Split a secret into shares.
    ///
    /// # Arguments
    /// * `secret` - The secret to split
    /// * `threshold` - Minimum shares needed to reconstruct (k)
    /// * `total` - Total number of shares to generate (n)
    ///
    /// # Returns
    /// A vector of `total` shares, any `threshold` of which can reconstruct the secret.
    fn split(secret: &[u8], threshold: usize, total: usize) -> ThresholdResult<Vec<Self::Share>>;

    /// Reconstruct a secret from shares.
    ///
    /// # Arguments
    /// * `shares` - At least `threshold` shares
    ///
    /// # Returns
    /// The reconstructed secret, or an error if insufficient shares provided.
    fn reconstruct(shares: &[Self::Share]) -> ThresholdResult<Vec<u8>>;
}

/// Trait for verifiable secret sharing schemes.
pub trait VerifiableSecretSharing: SecretSharing {
    /// The type of public commitments to the polynomial.
    type Commitment;

    /// Split a secret and generate public commitments.
    fn split_with_commitments(
        secret: &[u8],
        threshold: usize,
        total: usize,
    ) -> ThresholdResult<(Vec<Self::Share>, Vec<Self::Commitment>)>;

    /// Verify a share against the public commitments.
    fn verify_share(share: &Self::Share, commitments: &[Self::Commitment]) -> bool;
}

/// Trait for threshold signature schemes.
pub trait ThresholdSignature {
    /// Key package for a single participant.
    type KeyPackage;

    /// Signature share from a single participant.
    type SignatureShare;

    /// Aggregated signature.
    type Signature;

    /// Public key for signature verification.
    type PublicKey;

    /// Generate a signature share for a message.
    fn sign_share(
        key_package: &Self::KeyPackage,
        message: &[u8],
    ) -> ThresholdResult<Self::SignatureShare>;

    /// Aggregate signature shares into a complete signature.
    fn aggregate(
        shares: &[Self::SignatureShare],
        message: &[u8],
    ) -> ThresholdResult<Self::Signature>;

    /// Verify an aggregated signature.
    fn verify(
        public_key: &Self::PublicKey,
        message: &[u8],
        signature: &Self::Signature,
    ) -> ThresholdResult<()>;
}

/// Trait for distributed key generation protocols.
pub trait DistributedKeyGeneration {
    /// State maintained by each participant.
    type ParticipantState;

    /// Round 1 broadcast message.
    type Round1Message;

    /// Round 2 message (sent to specific participant).
    type Round2Message;

    /// Final key package after DKG completes.
    type KeyPackage;

    /// Initialize a participant's state.
    fn new_participant(
        participant_index: usize,
        threshold: usize,
        total_participants: usize,
    ) -> ThresholdResult<Self::ParticipantState>;

    /// Generate round 1 message (commitment).
    fn round1_generate(state: &mut Self::ParticipantState) -> ThresholdResult<Self::Round1Message>;

    /// Process received round 1 messages.
    fn round1_receive(
        state: &mut Self::ParticipantState,
        message: &Self::Round1Message,
    ) -> ThresholdResult<()>;

    /// Generate round 2 messages (secret shares).
    fn round2_generate(state: &mut Self::ParticipantState) -> ThresholdResult<Vec<Self::Round2Message>>;

    /// Process received round 2 message.
    fn round2_receive(
        state: &mut Self::ParticipantState,
        message: &Self::Round2Message,
    ) -> ThresholdResult<()>;

    /// Finalize DKG and produce key package.
    fn finalize(state: Self::ParticipantState) -> ThresholdResult<Self::KeyPackage>;
}
