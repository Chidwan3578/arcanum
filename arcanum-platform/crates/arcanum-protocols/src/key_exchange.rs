//! Key exchange protocol using X25519.
//!
//! Provides a high-level interface for elliptic curve Diffie-Hellman
//! key exchange using Curve25519.

use crate::error::{ProtocolError, Result};
use arcanum_asymmetric::prelude::*;
use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;

/// Secret key for key exchange (private).
///
/// Secret keys intentionally do not implement Clone to prevent
/// accidental copying of sensitive key material.
#[derive(ZeroizeOnDrop)]
pub struct ExchangeSecretKey {
    inner: X25519SecretKey,
}

/// Public key for key exchange (can be shared).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExchangePublicKey {
    bytes: Vec<u8>,
}

impl ExchangePublicKey {
    /// Create from raw bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 {
            return Err(ProtocolError::InvalidKey(format!(
                "expected 32 bytes, got {}",
                bytes.len()
            )));
        }
        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }

    /// Export to bytes.
    pub fn to_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Encode as hex string.
    pub fn to_hex(&self) -> String {
        hex::encode(&self.bytes)
    }

    /// Decode from hex string.
    pub fn from_hex(s: &str) -> Result<Self> {
        let bytes = hex::decode(s)
            .map_err(|e| ProtocolError::InvalidKey(e.to_string()))?;
        Self::from_bytes(&bytes)
    }
}

impl std::fmt::Debug for ExchangePublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ExchangePublicKey({})", self.to_hex())
    }
}

/// Shared secret derived from key exchange.
#[derive(Clone, ZeroizeOnDrop)]
pub struct SharedSecret {
    bytes: Vec<u8>,
}

impl std::fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SharedSecret([REDACTED, {} bytes])", self.bytes.len())
    }
}

impl SharedSecret {
    /// Access the raw shared secret bytes.
    ///
    /// # Warning
    ///
    /// Handle with care. This is sensitive cryptographic material.
    pub fn expose(&self) -> &[u8] {
        &self.bytes
    }

    /// Get the length of the shared secret.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl PartialEq for SharedSecret {
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        self.bytes.ct_eq(&other.bytes).into()
    }
}

impl Eq for SharedSecret {}

/// X25519 key exchange protocol.
///
/// Provides elliptic curve Diffie-Hellman key exchange using Curve25519.
///
/// # Example
///
/// ```rust,no_run
/// use arcanum_protocols::KeyExchangeProtocol;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// // Alice generates her keypair
/// let (alice_secret, alice_public) = KeyExchangeProtocol::generate_keypair();
///
/// // Bob generates his keypair
/// let (bob_secret, bob_public) = KeyExchangeProtocol::generate_keypair();
///
/// // Alice computes shared secret with Bob's public key
/// let alice_shared = KeyExchangeProtocol::derive_shared_secret(&alice_secret, &bob_public)?;
///
/// // Bob computes shared secret with Alice's public key
/// let bob_shared = KeyExchangeProtocol::derive_shared_secret(&bob_secret, &alice_public)?;
///
/// // Both arrive at the same shared secret
/// assert_eq!(alice_shared, bob_shared);
/// # Ok(())
/// # }
/// ```
///
/// ## Key Serialization
///
/// ```rust,no_run
/// use arcanum_protocols::KeyExchangeProtocol;
///
/// let (secret, public) = KeyExchangeProtocol::generate_keypair();
///
/// // Public keys can be serialized and shared
/// let public_hex = public.to_hex();
/// let public_json = serde_json::to_string(&public).unwrap();
///
/// // Reconstruct public key
/// let restored = arcanum_protocols::prelude::ExchangePublicKey::from_hex(&public_hex).unwrap();
/// ```
pub struct KeyExchangeProtocol;

impl KeyExchangeProtocol {
    /// Generate a new key exchange keypair.
    ///
    /// # Returns
    ///
    /// A tuple of (secret_key, public_key).
    pub fn generate_keypair() -> (ExchangeSecretKey, ExchangePublicKey) {
        let secret = X25519SecretKey::generate();
        let public = secret.public_key();

        let exchange_secret = ExchangeSecretKey { inner: secret };
        let exchange_public = ExchangePublicKey {
            bytes: public.to_bytes().to_vec(),
        };

        (exchange_secret, exchange_public)
    }

    /// Derive a shared secret from your secret key and peer's public key.
    ///
    /// # Arguments
    ///
    /// * `secret_key` - Your secret key
    /// * `peer_public_key` - The other party's public key
    ///
    /// # Returns
    ///
    /// A shared secret that both parties will derive identically.
    pub fn derive_shared_secret(
        secret_key: &ExchangeSecretKey,
        peer_public_key: &ExchangePublicKey,
    ) -> Result<SharedSecret> {
        // Convert Vec<u8> to [u8; 32]
        if peer_public_key.bytes.len() != 32 {
            return Err(ProtocolError::InvalidKey("public key must be 32 bytes".to_string()));
        }
        let bytes: [u8; 32] = peer_public_key.bytes.as_slice().try_into()
            .map_err(|_| ProtocolError::InvalidKey("invalid key length".to_string()))?;
        let peer_pk = X25519PublicKey::from_bytes(&bytes);

        let shared = secret_key.inner.derive_shared_secret(&peer_pk);

        Ok(SharedSecret {
            bytes: shared.as_bytes().to_vec(),
        })
    }

    /// Create a secret key from raw bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - 32 bytes of secret key material
    pub fn secret_key_from_bytes(bytes: &[u8]) -> Result<ExchangeSecretKey> {
        if bytes.len() != 32 {
            return Err(ProtocolError::InvalidKey("secret key must be 32 bytes".to_string()));
        }
        let arr: [u8; 32] = bytes.try_into()
            .map_err(|_| ProtocolError::InvalidKey("invalid key length".to_string()))?;
        let inner = X25519SecretKey::from_bytes(&arr);
        Ok(ExchangeSecretKey { inner })
    }

    /// Export a secret key to bytes.
    ///
    /// # Warning
    ///
    /// Handle the returned bytes with extreme care.
    pub fn secret_key_to_bytes(secret_key: &ExchangeSecretKey) -> Vec<u8> {
        secret_key.inner.to_bytes().to_vec()
    }

    /// Get the public key corresponding to a secret key.
    pub fn public_key_from_secret(secret_key: &ExchangeSecretKey) -> ExchangePublicKey {
        let public = secret_key.inner.public_key();
        ExchangePublicKey {
            bytes: public.to_bytes().to_vec(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_exchange() {
        let (alice_secret, alice_public) = KeyExchangeProtocol::generate_keypair();
        let (bob_secret, bob_public) = KeyExchangeProtocol::generate_keypair();

        let alice_shared = KeyExchangeProtocol::derive_shared_secret(&alice_secret, &bob_public).unwrap();
        let bob_shared = KeyExchangeProtocol::derive_shared_secret(&bob_secret, &alice_public).unwrap();

        assert_eq!(alice_shared, bob_shared);
    }

    #[test]
    fn test_different_keys_different_secrets() {
        let (alice_secret, alice_public) = KeyExchangeProtocol::generate_keypair();
        let (bob_secret, bob_public) = KeyExchangeProtocol::generate_keypair();
        let (charlie_secret, _charlie_public) = KeyExchangeProtocol::generate_keypair();

        let alice_bob = KeyExchangeProtocol::derive_shared_secret(&alice_secret, &bob_public).unwrap();
        let alice_charlie = KeyExchangeProtocol::derive_shared_secret(&alice_secret, &KeyExchangeProtocol::public_key_from_secret(&charlie_secret)).unwrap();

        assert_ne!(alice_bob.expose(), alice_charlie.expose());
    }

    #[test]
    fn test_public_key_serialization() {
        let (_secret, public) = KeyExchangeProtocol::generate_keypair();

        // Hex
        let hex = public.to_hex();
        let restored = ExchangePublicKey::from_hex(&hex).unwrap();
        assert_eq!(public, restored);

        // JSON
        let json = serde_json::to_string(&public).unwrap();
        let restored: ExchangePublicKey = serde_json::from_str(&json).unwrap();
        assert_eq!(public, restored);
    }

    #[test]
    fn test_secret_key_roundtrip() {
        let (secret, public) = KeyExchangeProtocol::generate_keypair();

        let bytes = KeyExchangeProtocol::secret_key_to_bytes(&secret);
        let restored = KeyExchangeProtocol::secret_key_from_bytes(&bytes).unwrap();

        let restored_public = KeyExchangeProtocol::public_key_from_secret(&restored);
        assert_eq!(public, restored_public);
    }

    #[test]
    fn test_invalid_key_length() {
        let result = ExchangePublicKey::from_bytes(&[0u8; 16]);
        assert!(result.is_err());

        let result = ExchangePublicKey::from_bytes(&[0u8; 32]);
        assert!(result.is_ok());
    }
}
