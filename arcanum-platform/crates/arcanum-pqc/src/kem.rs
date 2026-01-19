//! ML-KEM (Module-Lattice Key Encapsulation Mechanism).
//!
//! Formerly known as CRYSTALS-Kyber, ML-KEM is the NIST-standardized
//! post-quantum key encapsulation mechanism (FIPS 203).
//!
//! ## Security Levels
//!
//! - **ML-KEM-512**: NIST Level 1 (128-bit security)
//! - **ML-KEM-768**: NIST Level 3 (192-bit security) - **Recommended**
//! - **ML-KEM-1024**: NIST Level 5 (256-bit security)

use arcanum_core::error::{Error, Result};
use ml_kem::{
    MlKem512 as MlKem512Impl, MlKem768 as MlKem768Impl, MlKem1024 as MlKem1024Impl,
    KemCore, EncodedSizeUser,
};
use kem::{Decapsulate, Encapsulate};
use rand::rngs::OsRng;

// ═══════════════════════════════════════════════════════════════════════════════
// ML-KEM-768 (Recommended)
// ═══════════════════════════════════════════════════════════════════════════════

/// ML-KEM-768: NIST Level 3 security (192-bit).
///
/// The recommended variant for most applications.
pub struct MlKem768;

impl MlKem768 {
    /// Algorithm identifier.
    pub const ALGORITHM: &'static str = "ML-KEM-768";
    /// Security level in bits.
    pub const SECURITY_LEVEL: usize = 192;

    /// Generate a key pair, returning (decapsulation_key_bytes, encapsulation_key_bytes).
    pub fn generate_keypair() -> Result<(Vec<u8>, Vec<u8>)> {
        let (dk, ek) = MlKem768Impl::generate(&mut OsRng);
        Ok((dk.as_bytes().to_vec(), ek.as_bytes().to_vec()))
    }

    /// Encapsulate to produce ciphertext and shared secret.
    pub fn encapsulate(ek_bytes: &[u8]) -> Result<(Vec<u8>, [u8; 32])> {
        let ek = <MlKem768Impl as KemCore>::EncapsulationKey::from_bytes(
            ek_bytes.try_into().map_err(|_| Error::InvalidKeyFormat)?
        );
        let (ct, ss) = ek.encapsulate(&mut OsRng).map_err(|_| Error::EncryptionFailed)?;
        Ok((ct.to_vec(), ss.into()))
    }

    /// Decapsulate to recover shared secret.
    pub fn decapsulate(dk_bytes: &[u8], ct_bytes: &[u8]) -> Result<[u8; 32]> {
        let dk = <MlKem768Impl as KemCore>::DecapsulationKey::from_bytes(
            dk_bytes.try_into().map_err(|_| Error::InvalidKeyFormat)?
        );
        let ct = ct_bytes.try_into().map_err(|_| Error::InvalidCiphertext)?;
        let ss = dk.decapsulate(&ct).map_err(|_| Error::DecryptionFailed)?;
        Ok(ss.into())
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// ML-KEM-512 (Level 1)
// ═══════════════════════════════════════════════════════════════════════════════

/// ML-KEM-512: NIST Level 1 security (128-bit).
pub struct MlKem512;

impl MlKem512 {
    /// Algorithm identifier.
    pub const ALGORITHM: &'static str = "ML-KEM-512";
    /// Security level in bits.
    pub const SECURITY_LEVEL: usize = 128;

    /// Generate a key pair.
    pub fn generate_keypair() -> Result<(Vec<u8>, Vec<u8>)> {
        let (dk, ek) = MlKem512Impl::generate(&mut OsRng);
        Ok((dk.as_bytes().to_vec(), ek.as_bytes().to_vec()))
    }

    /// Encapsulate to produce ciphertext and shared secret.
    pub fn encapsulate(ek_bytes: &[u8]) -> Result<(Vec<u8>, [u8; 32])> {
        let ek = <MlKem512Impl as KemCore>::EncapsulationKey::from_bytes(
            ek_bytes.try_into().map_err(|_| Error::InvalidKeyFormat)?
        );
        let (ct, ss) = ek.encapsulate(&mut OsRng).map_err(|_| Error::EncryptionFailed)?;
        Ok((ct.to_vec(), ss.into()))
    }

    /// Decapsulate to recover shared secret.
    pub fn decapsulate(dk_bytes: &[u8], ct_bytes: &[u8]) -> Result<[u8; 32]> {
        let dk = <MlKem512Impl as KemCore>::DecapsulationKey::from_bytes(
            dk_bytes.try_into().map_err(|_| Error::InvalidKeyFormat)?
        );
        let ct = ct_bytes.try_into().map_err(|_| Error::InvalidCiphertext)?;
        let ss = dk.decapsulate(&ct).map_err(|_| Error::DecryptionFailed)?;
        Ok(ss.into())
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// ML-KEM-1024 (Level 5)
// ═══════════════════════════════════════════════════════════════════════════════

/// ML-KEM-1024: NIST Level 5 security (256-bit).
pub struct MlKem1024;

impl MlKem1024 {
    /// Algorithm identifier.
    pub const ALGORITHM: &'static str = "ML-KEM-1024";
    /// Security level in bits.
    pub const SECURITY_LEVEL: usize = 256;

    /// Generate a key pair.
    pub fn generate_keypair() -> Result<(Vec<u8>, Vec<u8>)> {
        let (dk, ek) = MlKem1024Impl::generate(&mut OsRng);
        Ok((dk.as_bytes().to_vec(), ek.as_bytes().to_vec()))
    }

    /// Encapsulate to produce ciphertext and shared secret.
    pub fn encapsulate(ek_bytes: &[u8]) -> Result<(Vec<u8>, [u8; 32])> {
        let ek = <MlKem1024Impl as KemCore>::EncapsulationKey::from_bytes(
            ek_bytes.try_into().map_err(|_| Error::InvalidKeyFormat)?
        );
        let (ct, ss) = ek.encapsulate(&mut OsRng).map_err(|_| Error::EncryptionFailed)?;
        Ok((ct.to_vec(), ss.into()))
    }

    /// Decapsulate to recover shared secret.
    pub fn decapsulate(dk_bytes: &[u8], ct_bytes: &[u8]) -> Result<[u8; 32]> {
        let dk = <MlKem1024Impl as KemCore>::DecapsulationKey::from_bytes(
            dk_bytes.try_into().map_err(|_| Error::InvalidKeyFormat)?
        );
        let ct = ct_bytes.try_into().map_err(|_| Error::InvalidCiphertext)?;
        let ss = dk.decapsulate(&ct).map_err(|_| Error::DecryptionFailed)?;
        Ok(ss.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ml_kem_768_roundtrip() {
        let (dk, ek) = MlKem768::generate_keypair().unwrap();
        let (ct, ss1) = MlKem768::encapsulate(&ek).unwrap();
        let ss2 = MlKem768::decapsulate(&dk, &ct).unwrap();
        assert_eq!(ss1, ss2);
    }

    #[test]
    fn test_ml_kem_512_roundtrip() {
        let (dk, ek) = MlKem512::generate_keypair().unwrap();
        let (ct, ss1) = MlKem512::encapsulate(&ek).unwrap();
        let ss2 = MlKem512::decapsulate(&dk, &ct).unwrap();
        assert_eq!(ss1, ss2);
    }

    #[test]
    fn test_ml_kem_1024_roundtrip() {
        let (dk, ek) = MlKem1024::generate_keypair().unwrap();
        let (ct, ss1) = MlKem1024::encapsulate(&ek).unwrap();
        let ss2 = MlKem1024::decapsulate(&dk, &ct).unwrap();
        assert_eq!(ss1, ss2);
    }
}
