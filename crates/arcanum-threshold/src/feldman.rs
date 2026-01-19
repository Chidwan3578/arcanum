//! Feldman's Verifiable Secret Sharing implementation.
//!
//! Extends Shamir's scheme with public commitments for share verification.
//!
//! ## Security Properties
//!
//! - **Verifiability**: Shareholders can verify their shares are consistent
//! - **Soundness**: Cannot create invalid shares that pass verification
//! - **Computational hiding**: Commitments reveal nothing about secret
//!   (assuming discrete log is hard)
//!
//! ## Construction
//!
//! Given a polynomial P(x) = a_0 + a_1*x + ... + a_{k-1}*x^{k-1} where a_0 = secret:
//!
//! - Commitments: C_i = g^{a_i} for each coefficient
//! - Share: (j, y_j) where y_j = P(j)
//! - Verification: g^{y_j} = ∏_{i=0}^{k-1} C_i^{j^i}
//!
//! ## Note on Secret Size
//!
//! This implementation works with scalar secrets (≤32 bytes).
//! For larger secrets, use the scalar as a symmetric key and
//! encrypt the actual data with that key.

use crate::errors::{ThresholdError, ThresholdResult};
use crate::traits::{SecretSharing, VerifiableSecretSharing};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A single share from Feldman VSS.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct VerifiableShare {
    /// The participant index (1-based)
    pub index: u8,
    /// The share value as a scalar (32 bytes)
    #[zeroize(skip)] // Scalar doesn't implement Zeroize trait directly
    value: [u8; 32],
}

impl VerifiableShare {
    /// Create a new share.
    pub fn new(index: u8, scalar: Scalar) -> Self {
        Self {
            index,
            value: scalar.to_bytes(),
        }
    }

    /// Get the share value as a scalar.
    pub fn scalar(&self) -> Scalar {
        Scalar::from_canonical_bytes(self.value)
            .into_option()
            .unwrap_or(Scalar::ZERO)
    }

    /// Get the share index.
    pub fn index(&self) -> u8 {
        self.index
    }

    /// Verify this share against public commitments.
    ///
    /// Checks: g^{share_value} = ∏_{i=0}^{k-1} C_i^{j^i}
    pub fn verify(&self, commitments: &[ShareCommitment]) -> bool {
        if commitments.is_empty() {
            return false;
        }

        // Left side: g^{share_value}
        let lhs = self.scalar() * RISTRETTO_BASEPOINT_POINT;

        // Right side: ∏_{i=0}^{k-1} C_i^{j^i}
        let j = Scalar::from(self.index as u64);
        let mut rhs = RistrettoPoint::default();
        let mut j_power = Scalar::ONE;

        for commitment in commitments {
            let c_i = match commitment.point() {
                Some(p) => p,
                None => return false, // Invalid commitment
            };
            rhs += j_power * c_i;
            j_power *= j;
        }

        lhs == rhs
    }
}

impl std::fmt::Debug for VerifiableShare {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "VerifiableShare {{ index: {} }}", self.index)
    }
}

/// Public commitment to a polynomial coefficient.
///
/// C_i = g^{a_i} where a_i is the i-th coefficient of the secret polynomial.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ShareCommitment {
    /// The compressed Ristretto point (32 bytes)
    value: [u8; 32],
}

impl ShareCommitment {
    /// Create a commitment from a scalar coefficient.
    pub fn from_scalar(coef: &Scalar) -> Self {
        let point = coef * RISTRETTO_BASEPOINT_POINT;
        Self {
            value: point.compress().to_bytes(),
        }
    }

    /// Get the commitment as a point.
    pub fn point(&self) -> Option<RistrettoPoint> {
        CompressedRistretto::from_slice(&self.value)
            .ok()?
            .decompress()
    }

    /// Get the raw bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.value
    }

    /// Create from raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { value: bytes }
    }
}

impl PartialEq for ShareCommitment {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}

impl Eq for ShareCommitment {}

/// Feldman's Verifiable Secret Sharing scheme.
///
/// Provides verifiable splitting and reconstruction of scalar secrets.
pub struct FeldmanVSS;

impl FeldmanVSS {
    /// Generate random polynomial coefficients.
    ///
    /// Returns (k-1) random scalars for a threshold-k scheme.
    fn generate_coefficients(threshold: usize) -> Vec<Scalar> {
        (0..threshold - 1)
            .map(|_| {
                let mut bytes = [0u8; 64];
                rand::rngs::OsRng.fill_bytes(&mut bytes);
                Scalar::from_bytes_mod_order_wide(&bytes)
            })
            .collect()
    }

    /// Evaluate polynomial at point x.
    ///
    /// P(x) = a_0 + a_1*x + a_2*x^2 + ... + a_{k-1}*x^{k-1}
    fn evaluate_polynomial(secret: &Scalar, coefficients: &[Scalar], x: u8) -> Scalar {
        let x_scalar = Scalar::from(x as u64);
        let mut result = *secret;
        let mut x_power = x_scalar;

        for coef in coefficients {
            result += coef * x_power;
            x_power *= x_scalar;
        }

        result
    }

    /// Lagrange interpolation to recover the secret.
    ///
    /// Given shares (x_i, y_i), computes P(0) = secret.
    fn interpolate(shares: &[VerifiableShare]) -> Scalar {
        let mut result = Scalar::ZERO;

        for (i, share_i) in shares.iter().enumerate() {
            let x_i = Scalar::from(share_i.index as u64);
            let y_i = share_i.scalar();

            // Compute Lagrange basis polynomial L_i(0)
            let mut numerator = Scalar::ONE;
            let mut denominator = Scalar::ONE;

            for (j, share_j) in shares.iter().enumerate() {
                if i != j {
                    let x_j = Scalar::from(share_j.index as u64);
                    // L_i(0) = product of (0 - x_j) / (x_i - x_j)
                    numerator *= -x_j;
                    denominator *= x_i - x_j;
                }
            }

            // L_i(0) * y_i
            result += y_i * numerator * denominator.invert();
        }

        result
    }

    /// Split a scalar secret into verifiable shares.
    pub fn split_scalar(
        secret: &Scalar,
        threshold: usize,
        total: usize,
    ) -> ThresholdResult<(Vec<VerifiableShare>, Vec<ShareCommitment>)> {
        // Validate parameters
        if threshold < 1 {
            return Err(ThresholdError::ThresholdTooLow { threshold });
        }
        if threshold > total {
            return Err(ThresholdError::ThresholdExceedsTotal { threshold, total });
        }
        if total > 255 {
            return Err(ThresholdError::InvalidShare {
                reason: "Maximum 255 shares supported".into(),
            });
        }

        // Generate random coefficients
        let coefficients = Self::generate_coefficients(threshold);

        // Generate commitments: C_i = g^{a_i}
        let mut commitments = Vec::with_capacity(threshold);
        commitments.push(ShareCommitment::from_scalar(secret)); // C_0 = g^{secret}
        for coef in &coefficients {
            commitments.push(ShareCommitment::from_scalar(coef));
        }

        // Generate shares: (j, P(j)) for j = 1, 2, ..., n
        let shares: Vec<VerifiableShare> = (1..=total)
            .map(|j| {
                let y_j = Self::evaluate_polynomial(secret, &coefficients, j as u8);
                VerifiableShare::new(j as u8, y_j)
            })
            .collect();

        Ok((shares, commitments))
    }

    /// Reconstruct a scalar secret from shares.
    pub fn reconstruct_scalar(shares: &[VerifiableShare]) -> ThresholdResult<Scalar> {
        if shares.is_empty() {
            return Err(ThresholdError::InsufficientShares {
                required: 1,
                provided: 0,
            });
        }

        // Check for duplicate indices
        let mut seen = std::collections::HashSet::new();
        for share in shares {
            if !seen.insert(share.index) {
                return Err(ThresholdError::DuplicateShareIndex {
                    index: share.index as usize,
                });
            }
        }

        Ok(Self::interpolate(shares))
    }

    /// Split a byte secret into verifiable shares.
    ///
    /// The secret must be ≤32 bytes. For larger secrets,
    /// use the returned scalar as a symmetric encryption key.
    pub fn split(
        secret: &[u8],
        threshold: usize,
        total: usize,
    ) -> ThresholdResult<(Vec<VerifiableShare>, Vec<ShareCommitment>)> {
        if secret.len() > 32 {
            return Err(ThresholdError::InvalidShare {
                reason: "Secret must be ≤32 bytes for Feldman VSS. Use as encryption key for larger data.".into(),
            });
        }

        let mut padded = [0u8; 32];
        padded[..secret.len()].copy_from_slice(secret);

        // Convert to scalar (this may reduce modulo the curve order)
        let scalar = Scalar::from_bytes_mod_order(padded);

        Self::split_scalar(&scalar, threshold, total)
    }

    /// Verify a share against commitments.
    pub fn verify_share(share: &VerifiableShare, commitments: &[ShareCommitment]) -> bool {
        share.verify(commitments)
    }

    /// Reconstruct secret from verified shares.
    pub fn reconstruct(shares: &[VerifiableShare]) -> ThresholdResult<[u8; 32]> {
        let scalar = Self::reconstruct_scalar(shares)?;
        Ok(scalar.to_bytes())
    }

    /// Verify all shares and reconstruct if valid.
    pub fn verify_and_reconstruct(
        shares: &[VerifiableShare],
        commitments: &[ShareCommitment],
    ) -> ThresholdResult<[u8; 32]> {
        // Verify each share
        for share in shares {
            if !share.verify(commitments) {
                return Err(ThresholdError::InvalidShare {
                    reason: format!("Share {} failed verification", share.index),
                });
            }
        }

        Self::reconstruct(shares)
    }
}

impl SecretSharing for FeldmanVSS {
    type Share = VerifiableShare;

    fn split(secret: &[u8], threshold: usize, total: usize) -> ThresholdResult<Vec<Self::Share>> {
        let (shares, _commitments) = FeldmanVSS::split(secret, threshold, total)?;
        Ok(shares)
    }

    fn reconstruct(shares: &[Self::Share]) -> ThresholdResult<Vec<u8>> {
        let bytes = FeldmanVSS::reconstruct(shares)?;
        Ok(bytes.to_vec())
    }
}

impl VerifiableSecretSharing for FeldmanVSS {
    type Commitment = ShareCommitment;

    fn split_with_commitments(
        secret: &[u8],
        threshold: usize,
        total: usize,
    ) -> ThresholdResult<(Vec<Self::Share>, Vec<Self::Commitment>)> {
        FeldmanVSS::split(secret, threshold, total)
    }

    fn verify_share(share: &Self::Share, commitments: &[Self::Commitment]) -> bool {
        share.verify(commitments)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_and_reconstruct() {
        let secret = Scalar::from(42u64);
        let (shares, commitments) = FeldmanVSS::split_scalar(&secret, 3, 5).unwrap();

        assert_eq!(shares.len(), 5);
        assert_eq!(commitments.len(), 3);

        // All shares should verify
        for share in &shares {
            assert!(share.verify(&commitments), "Share {} failed verification", share.index);
        }

        // Reconstruct with threshold shares
        let reconstructed = FeldmanVSS::reconstruct_scalar(&shares[0..3]).unwrap();
        assert_eq!(reconstructed, secret);
    }

    #[test]
    fn test_different_share_combinations() {
        let secret = Scalar::from(1234567890u64);
        let (shares, commitments) = FeldmanVSS::split_scalar(&secret, 3, 5).unwrap();

        // Test different combinations
        use itertools::Itertools;
        for combo in (0..5usize).combinations(3) {
            let subset: Vec<_> = combo.iter().map(|&i| shares[i].clone()).collect();

            // All should verify
            for share in &subset {
                assert!(share.verify(&commitments));
            }

            // All should reconstruct correctly
            let reconstructed = FeldmanVSS::reconstruct_scalar(&subset).unwrap();
            assert_eq!(reconstructed, secret, "Failed for combination {:?}", combo);
        }
    }

    #[test]
    fn test_2_of_3() {
        let secret = Scalar::from(999u64);
        let (shares, commitments) = FeldmanVSS::split_scalar(&secret, 2, 3).unwrap();

        assert_eq!(shares.len(), 3);
        assert_eq!(commitments.len(), 2);

        for share in &shares {
            assert!(share.verify(&commitments));
        }

        // Any 2 shares should work
        let r1 = FeldmanVSS::reconstruct_scalar(&[shares[0].clone(), shares[1].clone()]).unwrap();
        let r2 = FeldmanVSS::reconstruct_scalar(&[shares[1].clone(), shares[2].clone()]).unwrap();
        let r3 = FeldmanVSS::reconstruct_scalar(&[shares[0].clone(), shares[2].clone()]).unwrap();

        assert_eq!(r1, secret);
        assert_eq!(r2, secret);
        assert_eq!(r3, secret);
    }

    #[test]
    fn test_byte_secret() {
        let secret = b"my secret key!!!"; // 16 bytes
        let (shares, commitments) = FeldmanVSS::split(secret, 3, 5).unwrap();

        // Verify
        for share in &shares {
            assert!(share.verify(&commitments));
        }

        // Reconstruct
        let reconstructed = FeldmanVSS::reconstruct(&shares[1..4]).unwrap();
        assert_eq!(&reconstructed[..secret.len()], secret);
    }

    #[test]
    fn test_verify_and_reconstruct() {
        let secret = Scalar::from(12345u64);
        let (shares, commitments) = FeldmanVSS::split_scalar(&secret, 2, 3).unwrap();

        let result = FeldmanVSS::verify_and_reconstruct(&shares, &commitments).unwrap();
        assert_eq!(Scalar::from_bytes_mod_order(result), secret);
    }

    #[test]
    fn test_tampered_share_fails_verification() {
        let secret = Scalar::from(42u64);
        let (mut shares, commitments) = FeldmanVSS::split_scalar(&secret, 2, 3).unwrap();

        // Tamper with a share
        shares[0] = VerifiableShare::new(shares[0].index, Scalar::from(9999u64));

        // Tampered share should fail verification
        assert!(!shares[0].verify(&commitments));

        // Original shares should still verify
        assert!(shares[1].verify(&commitments));
        assert!(shares[2].verify(&commitments));
    }

    #[test]
    fn test_commitment_serialization() {
        let secret = Scalar::from(42u64);
        let (_, commitments) = FeldmanVSS::split_scalar(&secret, 2, 3).unwrap();

        let json = serde_json::to_string(&commitments[0]).unwrap();
        let restored: ShareCommitment = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, commitments[0]);
    }

    #[test]
    fn test_threshold_validation() {
        let secret = Scalar::from(1u64);

        assert!(matches!(
            FeldmanVSS::split_scalar(&secret, 0, 5),
            Err(ThresholdError::ThresholdTooLow { .. })
        ));

        assert!(matches!(
            FeldmanVSS::split_scalar(&secret, 6, 5),
            Err(ThresholdError::ThresholdExceedsTotal { .. })
        ));
    }

    #[test]
    fn test_secret_too_large() {
        let secret = [0u8; 64]; // 64 bytes - too large
        assert!(matches!(
            FeldmanVSS::split(&secret, 2, 3),
            Err(ThresholdError::InvalidShare { .. })
        ));
    }

    #[test]
    fn test_random_scalar_secret() {
        let mut bytes = [0u8; 64];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        let secret = Scalar::from_bytes_mod_order_wide(&bytes);

        let (shares, commitments) = FeldmanVSS::split_scalar(&secret, 5, 10).unwrap();

        // All shares should verify
        for share in &shares {
            assert!(share.verify(&commitments));
        }

        // Reconstruct with different subsets
        let r1 = FeldmanVSS::reconstruct_scalar(&shares[0..5]).unwrap();
        let r2 = FeldmanVSS::reconstruct_scalar(&shares[5..10]).unwrap();
        let r3 = FeldmanVSS::reconstruct_scalar(&shares[2..7]).unwrap();

        assert_eq!(r1, secret);
        assert_eq!(r2, secret);
        assert_eq!(r3, secret);
    }

    #[test]
    fn test_commitment_consistency() {
        // The first commitment should be g^secret
        let secret = Scalar::from(42u64);
        let (_, commitments) = FeldmanVSS::split_scalar(&secret, 2, 3).unwrap();

        let expected_c0 = secret * RISTRETTO_BASEPOINT_POINT;
        assert_eq!(commitments[0].point(), Some(expected_c0));
    }
}
