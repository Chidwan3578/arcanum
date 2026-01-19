//! Versioned ciphertext containers for cryptographic agility.
//!
//! Self-describing containers that include algorithm metadata.

use crate::errors::{AgileError, AgileResult};
use crate::registry::AlgorithmId;
use serde::{Deserialize, Serialize};

/// Magic bytes identifying an Arcanum container.
pub const CONTAINER_MAGIC: [u8; 4] = *b"ARCN";

/// Current container format version.
pub const CONTAINER_VERSION: u8 = 1;

/// Header for a versioned container.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerHeader {
    /// Magic bytes for identification
    pub magic: [u8; 4],
    /// Container format version
    pub format_version: u8,
    /// Algorithm used for encryption
    pub algorithm: AlgorithmId,
    /// Algorithm-specific version
    pub alg_version: u8,
    /// Nonce/IV length
    pub nonce_len: u8,
    /// Reserved for future use
    pub reserved: [u8; 2],
}

impl ContainerHeader {
    /// Create a new container header.
    pub fn new(algorithm: AlgorithmId) -> Self {
        Self {
            magic: CONTAINER_MAGIC,
            format_version: CONTAINER_VERSION,
            algorithm,
            alg_version: 1,
            nonce_len: 12,
            reserved: [0; 2],
        }
    }

    /// Parse a header from bytes.
    pub fn from_bytes(bytes: &[u8]) -> AgileResult<Self> {
        if bytes.len() < 10 {
            return Err(AgileError::ParseError {
                reason: "Header too short".into(),
            });
        }

        if &bytes[0..4] != &CONTAINER_MAGIC {
            return Err(AgileError::ParseError {
                reason: "Invalid magic bytes".into(),
            });
        }

        let format_version = bytes[4];
        if format_version > CONTAINER_VERSION {
            return Err(AgileError::UnsupportedVersion { version: format_version });
        }

        // Parse algorithm ID
        let alg_id = u16::from_le_bytes([bytes[5], bytes[6]]);
        let algorithm = AlgorithmId::from_u16(alg_id)
            .ok_or(AgileError::UnknownAlgorithm(alg_id))?;

        Ok(Self {
            magic: CONTAINER_MAGIC,
            format_version,
            algorithm,
            alg_version: bytes[7],
            nonce_len: bytes[8],
            reserved: [bytes[9], bytes.get(10).copied().unwrap_or(0)],
        })
    }

    /// Serialize the header to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(11);
        bytes.extend_from_slice(&self.magic);
        bytes.push(self.format_version);
        bytes.extend_from_slice(&(self.algorithm as u16).to_le_bytes());
        bytes.push(self.alg_version);
        bytes.push(self.nonce_len);
        bytes.extend_from_slice(&self.reserved);
        bytes
    }
}

/// A self-describing encrypted container.
#[derive(Debug, Clone)]
pub struct AgileCiphertext {
    /// Container header
    pub header: ContainerHeader,
    /// Nonce/IV
    pub nonce: Vec<u8>,
    /// Encrypted data (including authentication tag)
    pub ciphertext: Vec<u8>,
}

impl AgileCiphertext {
    /// Get the algorithm used.
    pub fn algorithm(&self) -> AlgorithmId {
        self.header.algorithm
    }

    /// Get the format version.
    pub fn version(&self) -> u8 {
        self.header.format_version
    }

    /// Check if this container can be decrypted with current algorithms.
    pub fn can_decrypt(&self) -> bool {
        crate::registry::AlgorithmRegistry::get(self.header.algorithm).is_some()
    }

    /// Get migration recommendation if the algorithm is deprecated.
    pub fn migration_recommendation(&self) -> Option<MigrationRecommendation> {
        let info = crate::registry::AlgorithmRegistry::get(self.header.algorithm)?;

        if info.is_deprecated() {
            Some(MigrationRecommendation {
                source: self.header.algorithm,
                target: AlgorithmId::Aes256Gcm, // Default recommendation
                reason: info.deprecation_reason().unwrap_or("Algorithm deprecated").into(),
            })
        } else {
            None
        }
    }

    /// Encrypt data into a container.
    pub fn encrypt(
        algorithm: AlgorithmId,
        _key: &[u8],
        _plaintext: &[u8],
    ) -> AgileResult<Self> {
        // TODO: Implement actual encryption
        Ok(Self {
            header: ContainerHeader::new(algorithm),
            nonce: vec![0u8; 12],
            ciphertext: Vec::new(),
        })
    }

    /// Decrypt a container.
    pub fn decrypt(&self, _key: &[u8]) -> AgileResult<Vec<u8>> {
        // TODO: Implement actual decryption
        Err(AgileError::CryptoError {
            reason: "Not yet implemented".into(),
        })
    }

    /// Parse a container from bytes.
    pub fn parse(bytes: &[u8]) -> AgileResult<Self> {
        let header = ContainerHeader::from_bytes(bytes)?;
        let nonce_start = 11;
        let nonce_end = nonce_start + header.nonce_len as usize;

        if bytes.len() < nonce_end {
            return Err(AgileError::ParseError {
                reason: "Container too short for nonce".into(),
            });
        }

        Ok(Self {
            header,
            nonce: bytes[nonce_start..nonce_end].to_vec(),
            ciphertext: bytes[nonce_end..].to_vec(),
        })
    }

    /// Serialize the container to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.header.to_bytes();
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&self.ciphertext);
        bytes
    }
}

/// Recommendation for migrating to a newer algorithm.
#[derive(Debug, Clone)]
pub struct MigrationRecommendation {
    /// Current algorithm
    pub source: AlgorithmId,
    /// Recommended target algorithm
    pub target: AlgorithmId,
    /// Reason for migration
    pub reason: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_roundtrip() {
        let header = ContainerHeader::new(AlgorithmId::Aes256Gcm);
        let bytes = header.to_bytes();
        let parsed = ContainerHeader::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.algorithm, AlgorithmId::Aes256Gcm);
        assert_eq!(parsed.format_version, CONTAINER_VERSION);
    }

    #[test]
    fn test_migration_recommendation() {
        let container = AgileCiphertext::encrypt(
            AlgorithmId::TripleDes,
            &[0u8; 24],
            b"test",
        ).unwrap();

        let recommendation = container.migration_recommendation();
        assert!(recommendation.is_some());
        assert_eq!(recommendation.unwrap().target, AlgorithmId::Aes256Gcm);
    }
}
