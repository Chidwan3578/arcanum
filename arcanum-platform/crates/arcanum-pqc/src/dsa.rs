//! ML-DSA (Module-Lattice Digital Signature Algorithm).
//!
//! Formerly known as CRYSTALS-Dilithium, ML-DSA is the NIST-standardized
//! post-quantum digital signature algorithm (FIPS 204).
//!
//! ## Security Levels
//!
//! - **ML-DSA-44**: NIST Level 2 (128-bit security)
//! - **ML-DSA-65**: NIST Level 3 (192-bit security) - **Recommended**
//! - **ML-DSA-87**: NIST Level 5 (256-bit security)

use arcanum_core::error::{Error, Result};
use ml_dsa::{
    MlDsa44 as MlDsa44Param, MlDsa65 as MlDsa65Param, MlDsa87 as MlDsa87Param,
    MlDsaParams, SigningKey as MlDsaSigningKey,
    VerifyingKey as MlDsaVerifyingKey, Signature as MlDsaSignature,
    KeyGen, EncodedSigningKey, EncodedVerifyingKey,
};
use ml_dsa::signature::{Signer, Verifier};
use rand::RngCore;
use rand::rngs::OsRng;
use std::convert::TryFrom;

// ═══════════════════════════════════════════════════════════════════════════════
// ML-DSA-65 (Recommended)
// ═══════════════════════════════════════════════════════════════════════════════

/// ML-DSA-65: NIST Level 3 security (192-bit).
///
/// The recommended variant for most applications.
pub struct MlDsa65;

impl MlDsa65 {
    /// Algorithm identifier.
    pub const ALGORITHM: &'static str = "ML-DSA-65";
    /// Security level in bits.
    pub const SECURITY_LEVEL: usize = 192;

    /// Generate a key pair, returning (signing_key_bytes, verifying_key_bytes).
    pub fn generate_keypair() -> Result<(Vec<u8>, Vec<u8>)> {
        // Generate a random seed
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);

        // Use the seed to generate keys
        let kp = MlDsa65Param::from_seed(&seed.into());
        let sk_bytes = kp.signing_key().encode().to_vec();
        let vk_bytes = kp.verifying_key().encode().to_vec();

        // Zeroize seed
        seed.fill(0);

        Ok((sk_bytes, vk_bytes))
    }

    /// Sign a message.
    pub fn sign(sk_bytes: &[u8], message: &[u8]) -> Result<Vec<u8>> {
        let sk = decode_signing_key::<MlDsa65Param>(sk_bytes)?;
        let sig = sk.sign(message);
        Ok(sig.encode().to_vec())
    }

    /// Verify a signature.
    pub fn verify(vk_bytes: &[u8], message: &[u8], sig_bytes: &[u8]) -> Result<()> {
        let vk = decode_verifying_key::<MlDsa65Param>(vk_bytes)?;
        let sig = decode_signature::<MlDsa65Param>(sig_bytes)?;
        vk.verify(message, &sig)
            .map_err(|_| Error::SignatureVerificationFailed)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// ML-DSA-44 (Level 2)
// ═══════════════════════════════════════════════════════════════════════════════

/// ML-DSA-44: NIST Level 2 security (128-bit).
pub struct MlDsa44;

impl MlDsa44 {
    /// Algorithm identifier.
    pub const ALGORITHM: &'static str = "ML-DSA-44";
    /// Security level in bits.
    pub const SECURITY_LEVEL: usize = 128;

    /// Generate a key pair.
    pub fn generate_keypair() -> Result<(Vec<u8>, Vec<u8>)> {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);

        let kp = MlDsa44Param::from_seed(&seed.into());
        let sk_bytes = kp.signing_key().encode().to_vec();
        let vk_bytes = kp.verifying_key().encode().to_vec();

        seed.fill(0);
        Ok((sk_bytes, vk_bytes))
    }

    /// Sign a message.
    pub fn sign(sk_bytes: &[u8], message: &[u8]) -> Result<Vec<u8>> {
        let sk = decode_signing_key::<MlDsa44Param>(sk_bytes)?;
        let sig = sk.sign(message);
        Ok(sig.encode().to_vec())
    }

    /// Verify a signature.
    pub fn verify(vk_bytes: &[u8], message: &[u8], sig_bytes: &[u8]) -> Result<()> {
        let vk = decode_verifying_key::<MlDsa44Param>(vk_bytes)?;
        let sig = decode_signature::<MlDsa44Param>(sig_bytes)?;
        vk.verify(message, &sig)
            .map_err(|_| Error::SignatureVerificationFailed)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// ML-DSA-87 (Level 5)
// ═══════════════════════════════════════════════════════════════════════════════

/// ML-DSA-87: NIST Level 5 security (256-bit).
pub struct MlDsa87;

impl MlDsa87 {
    /// Algorithm identifier.
    pub const ALGORITHM: &'static str = "ML-DSA-87";
    /// Security level in bits.
    pub const SECURITY_LEVEL: usize = 256;

    /// Generate a key pair.
    pub fn generate_keypair() -> Result<(Vec<u8>, Vec<u8>)> {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);

        let kp = MlDsa87Param::from_seed(&seed.into());
        let sk_bytes = kp.signing_key().encode().to_vec();
        let vk_bytes = kp.verifying_key().encode().to_vec();

        seed.fill(0);
        Ok((sk_bytes, vk_bytes))
    }

    /// Sign a message.
    pub fn sign(sk_bytes: &[u8], message: &[u8]) -> Result<Vec<u8>> {
        let sk = decode_signing_key::<MlDsa87Param>(sk_bytes)?;
        let sig = sk.sign(message);
        Ok(sig.encode().to_vec())
    }

    /// Verify a signature.
    pub fn verify(vk_bytes: &[u8], message: &[u8], sig_bytes: &[u8]) -> Result<()> {
        let vk = decode_verifying_key::<MlDsa87Param>(vk_bytes)?;
        let sig = decode_signature::<MlDsa87Param>(sig_bytes)?;
        vk.verify(message, &sig)
            .map_err(|_| Error::SignatureVerificationFailed)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Helper functions
// ═══════════════════════════════════════════════════════════════════════════════

fn decode_signing_key<P: MlDsaParams>(bytes: &[u8]) -> Result<MlDsaSigningKey<P>> {
    let enc = EncodedSigningKey::<P>::try_from(bytes)
        .map_err(|_| Error::InvalidKeyFormat)?;
    Ok(MlDsaSigningKey::<P>::decode(&enc))
}

fn decode_verifying_key<P: MlDsaParams>(bytes: &[u8]) -> Result<MlDsaVerifyingKey<P>> {
    let enc = EncodedVerifyingKey::<P>::try_from(bytes)
        .map_err(|_| Error::InvalidKeyFormat)?;
    Ok(MlDsaVerifyingKey::<P>::decode(&enc))
}

fn decode_signature<P: MlDsaParams>(bytes: &[u8]) -> Result<MlDsaSignature<P>> {
    MlDsaSignature::<P>::try_from(bytes)
        .map_err(|_| Error::InvalidSignature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ml_dsa_65_roundtrip() {
        let (sk, vk) = MlDsa65::generate_keypair().unwrap();
        let message = b"Hello, post-quantum world!";

        let sig = MlDsa65::sign(&sk, message).unwrap();
        assert!(MlDsa65::verify(&vk, message, &sig).is_ok());
    }

    #[test]
    fn test_ml_dsa_65_wrong_message() {
        let (sk, vk) = MlDsa65::generate_keypair().unwrap();
        let message = b"Hello!";
        let wrong_message = b"Wrong!";

        let sig = MlDsa65::sign(&sk, message).unwrap();
        assert!(MlDsa65::verify(&vk, wrong_message, &sig).is_err());
    }

    #[test]
    fn test_ml_dsa_44_roundtrip() {
        let (sk, vk) = MlDsa44::generate_keypair().unwrap();
        let message = b"Test message";

        let sig = MlDsa44::sign(&sk, message).unwrap();
        assert!(MlDsa44::verify(&vk, message, &sig).is_ok());
    }

    #[test]
    fn test_ml_dsa_87_roundtrip() {
        let (sk, vk) = MlDsa87::generate_keypair().unwrap();
        let message = b"Test message";

        let sig = MlDsa87::sign(&sk, message).unwrap();
        assert!(MlDsa87::verify(&vk, message, &sig).is_ok());
    }
}
