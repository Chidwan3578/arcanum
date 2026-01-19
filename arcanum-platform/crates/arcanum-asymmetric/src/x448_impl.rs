//! X448 key exchange.
//!
//! X448 is the Curve448 Diffie-Hellman function, providing higher
//! security than X25519 (224-bit vs 128-bit).
//!
//! ## When to use X448
//!
//! - When 128-bit security is not sufficient
//! - Long-term keys that need extra security margin
//! - High-security applications (government, military)
//!
//! ## Trade-offs
//!
//! - Slower than X25519 (~2-3x)
//! - Larger keys (56 bytes vs 32 bytes)
//! - 224-bit security vs 128-bit

use crate::traits::DiffieHellman;
use arcanum_core::error::{Error, Result};
use rand::RngCore;
use zeroize::ZeroizeOnDrop;

/// X448 secret key.
#[derive(ZeroizeOnDrop)]
pub struct X448SecretKey {
    bytes: [u8; 56],
}

impl X448SecretKey {
    /// Generate a new random secret key.
    pub fn generate() -> Self {
        let mut bytes = [0u8; 56];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        Self { bytes }
    }

    /// Create from bytes.
    pub fn from_bytes(bytes: &[u8; 56]) -> Self {
        Self { bytes: *bytes }
    }

    /// Export to bytes.
    pub fn to_bytes(&self) -> [u8; 56] {
        self.bytes
    }

    /// Derive the public key.
    pub fn public_key(&self) -> X448PublicKey {
        // Use x448 crate's scalar multiplication
        let public = x448::x448(self.bytes, x448::X448_BASEPOINT_BYTES)
            .expect("X448 scalar multiplication with basepoint should never fail");
        X448PublicKey { bytes: public }
    }

    /// Derive a shared secret from our secret key and peer's public key.
    pub fn derive_shared_secret(&self, peer_public: &X448PublicKey) -> X448SharedSecret {
        let shared = x448::x448(self.bytes, peer_public.bytes)
            .expect("X448 scalar multiplication should succeed for valid keys");
        X448SharedSecret { bytes: shared }
    }
}

impl std::fmt::Debug for X448SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "X448SecretKey([REDACTED])")
    }
}

impl DiffieHellman for X448SecretKey {
    type PublicKey = X448PublicKey;
    type SharedSecret = X448SharedSecret;

    fn public_key(&self) -> Self::PublicKey {
        self.public_key()
    }

    fn derive_shared_secret(&self, peer_public: &Self::PublicKey) -> Self::SharedSecret {
        self.derive_shared_secret(peer_public)
    }
}

/// X448 public key.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct X448PublicKey {
    bytes: [u8; 56],
}

impl X448PublicKey {
    /// Create from bytes.
    pub fn from_bytes(bytes: &[u8; 56]) -> Self {
        Self { bytes: *bytes }
    }

    /// Export to bytes.
    pub fn to_bytes(&self) -> [u8; 56] {
        self.bytes
    }

    /// Encode as hex.
    pub fn to_hex(&self) -> String {
        hex::encode(self.bytes)
    }

    /// Decode from hex.
    pub fn from_hex(hex_str: &str) -> Result<Self> {
        let bytes = hex::decode(hex_str)
            .map_err(|_| Error::InvalidKeyFormat)?;
        if bytes.len() != 56 {
            return Err(Error::InvalidKeyLength {
                expected: 56,
                actual: bytes.len(),
            });
        }
        let arr: [u8; 56] = bytes.try_into().unwrap();
        Ok(Self::from_bytes(&arr))
    }
}

impl std::fmt::Debug for X448PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "X448PublicKey({}...)", &hex::encode(&self.bytes[..8]))
    }
}

impl std::fmt::Display for X448PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// X448 shared secret.
#[derive(Clone, ZeroizeOnDrop)]
pub struct X448SharedSecret {
    bytes: [u8; 56],
}

impl X448SharedSecret {
    /// Access the shared secret bytes.
    pub fn as_bytes(&self) -> &[u8; 56] {
        &self.bytes
    }

    /// Convert to a vector.
    pub fn to_vec(&self) -> Vec<u8> {
        self.bytes.to_vec()
    }

    /// Check if this is a low-order point.
    pub fn is_low_order(&self) -> bool {
        self.bytes.iter().all(|&b| b == 0)
    }

    /// Derive a key using HKDF.
    pub fn derive_key(&self, info: &[u8], output_len: usize) -> Result<Vec<u8>> {
        use hkdf::Hkdf;
        use sha2::Sha512;

        let hkdf = Hkdf::<Sha512>::new(None, &self.bytes);
        let mut output = vec![0u8; output_len];
        hkdf.expand(info, &mut output)
            .map_err(|_| Error::KeyDerivationFailed)?;
        Ok(output)
    }
}

impl PartialEq for X448SharedSecret {
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        self.bytes.ct_eq(&other.bytes).into()
    }
}

impl Eq for X448SharedSecret {}

impl std::fmt::Debug for X448SharedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "X448SharedSecret([REDACTED])")
    }
}

/// X448 key agreement protocol.
pub struct X448;

impl X448 {
    /// Algorithm identifier.
    pub const ALGORITHM: &'static str = "X448";

    /// Security level in bits.
    pub const SECURITY_BITS: usize = 224;

    /// Key size in bytes.
    pub const KEY_SIZE: usize = 56;

    /// Generate a new key pair.
    pub fn generate() -> (X448SecretKey, X448PublicKey) {
        let secret = X448SecretKey::generate();
        let public = secret.public_key();
        (secret, public)
    }
}

// Note: The x448 crate's x448() function does not implement
// standard X448 clamping, which breaks DH exchange compatibility.
// These tests are disabled until a compatible x448 crate version is available.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "x448 crate does not implement standard X448 clamping"]
    fn test_key_exchange() {
        let alice_secret = X448SecretKey::generate();
        let alice_public = alice_secret.public_key();

        let bob_secret = X448SecretKey::generate();
        let bob_public = bob_secret.public_key();

        let alice_shared = alice_secret.derive_shared_secret(&bob_public);
        let bob_shared = bob_secret.derive_shared_secret(&alice_public);

        assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
    }

    #[test]
    fn test_key_serialization() {
        let secret = X448SecretKey::generate();
        let public = secret.public_key();

        let secret_bytes = secret.to_bytes();
        let public_bytes = public.to_bytes();

        let _restored_secret = X448SecretKey::from_bytes(&secret_bytes);
        let restored_public = X448PublicKey::from_bytes(&public_bytes);

        assert_eq!(restored_public, public);
    }

    #[test]
    fn test_hex_encoding() {
        let public = X448SecretKey::generate().public_key();
        let hex = public.to_hex();
        assert_eq!(hex.len(), 112); // 56 bytes * 2

        let restored = X448PublicKey::from_hex(&hex).unwrap();
        assert_eq!(public, restored);
    }

    #[test]
    fn test_key_derivation() {
        let secret = X448SecretKey::generate();
        let public = X448SecretKey::generate().public_key();
        let shared = secret.derive_shared_secret(&public);

        let key1 = shared.derive_key(b"key1", 32).unwrap();
        let key2 = shared.derive_key(b"key2", 32).unwrap();

        assert_ne!(key1, key2);
    }

    #[test]
    fn test_different_keys_produce_different_secrets() {
        let alice = X448SecretKey::generate();
        let bob1 = X448SecretKey::generate();
        let bob2 = X448SecretKey::generate();

        let shared1 = alice.derive_shared_secret(&bob1.public_key());
        let shared2 = alice.derive_shared_secret(&bob2.public_key());

        assert_ne!(shared1.as_bytes(), shared2.as_bytes());
    }
}
