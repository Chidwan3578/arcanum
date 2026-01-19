//! Session key management.
//!
//! Derives encryption and authentication keys from shared secrets.

use crate::error::{ProtocolError, Result};
use crate::key_exchange::SharedSecret;
use arcanum_hash::{Hkdf, KeyDerivation, sha2_types::Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Session keys derived from a shared secret.
///
/// Contains separate keys for:
/// - Encryption (sending)
/// - Decryption (receiving)
/// - Authentication
///
/// # Example
///
/// ```rust,no_run
/// use arcanum_protocols::prelude::*;
///
/// # fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
/// let (alice_sk, alice_pk) = KeyExchangeProtocol::generate_keypair();
/// let (bob_sk, bob_pk) = KeyExchangeProtocol::generate_keypair();
///
/// let alice_shared = KeyExchangeProtocol::derive_shared_secret(&alice_sk, &bob_pk)?;
/// let bob_shared = KeyExchangeProtocol::derive_shared_secret(&bob_sk, &alice_pk)?;
///
/// // Derive session keys with a context string
/// let alice_keys = SessionKeys::derive(&alice_shared, b"my-app-v1")?;
/// let bob_keys = SessionKeys::derive(&bob_shared, b"my-app-v1")?;
///
/// // Keys are identical when derived from same shared secret and context
/// assert_eq!(alice_keys.encryption_key(), bob_keys.encryption_key());
/// # Ok(())
/// # }
/// ```
#[derive(Clone, ZeroizeOnDrop)]
pub struct SessionKeys {
    /// Key for encrypting outbound messages
    encryption_key: Vec<u8>,
    /// Key for decrypting inbound messages
    decryption_key: Vec<u8>,
    /// Key for message authentication
    auth_key: Vec<u8>,
}

impl SessionKeys {
    /// Derive session keys from a shared secret.
    ///
    /// Uses HKDF-SHA256 to derive multiple keys from the shared secret.
    ///
    /// # Arguments
    ///
    /// * `shared_secret` - The shared secret from key exchange
    /// * `context` - Application-specific context (e.g., protocol version)
    ///
    /// # Returns
    ///
    /// Session keys for encryption, decryption, and authentication.
    pub fn derive(shared_secret: &SharedSecret, context: &[u8]) -> Result<Self> {
        // Use HKDF to derive multiple keys
        let encryption_key = Hkdf::<Sha256>::derive(
            shared_secret.expose(),
            Some(context),
            Some(b"encryption"),
            32,
        ).map_err(|e| ProtocolError::KeyDerivationFailed(e.to_string()))?;

        let decryption_key = Hkdf::<Sha256>::derive(
            shared_secret.expose(),
            Some(context),
            Some(b"decryption"),
            32,
        ).map_err(|e| ProtocolError::KeyDerivationFailed(e.to_string()))?;

        let auth_key = Hkdf::<Sha256>::derive(
            shared_secret.expose(),
            Some(context),
            Some(b"authentication"),
            32,
        ).map_err(|e| ProtocolError::KeyDerivationFailed(e.to_string()))?;

        Ok(Self {
            encryption_key,
            decryption_key,
            auth_key,
        })
    }

    /// Derive session keys with separate roles (initiator vs responder).
    ///
    /// This ensures that each party uses different keys for sending vs receiving,
    /// preventing reflection attacks.
    ///
    /// # Arguments
    ///
    /// * `shared_secret` - The shared secret from key exchange
    /// * `context` - Application-specific context
    /// * `is_initiator` - Whether this party initiated the exchange
    pub fn derive_with_roles(
        shared_secret: &SharedSecret,
        context: &[u8],
        is_initiator: bool,
    ) -> Result<Self> {
        let (send_label, recv_label) = if is_initiator {
            (b"initiator-send".as_slice(), b"responder-send".as_slice())
        } else {
            (b"responder-send".as_slice(), b"initiator-send".as_slice())
        };

        let encryption_key = Hkdf::<Sha256>::derive(
            shared_secret.expose(),
            Some(context),
            Some(send_label),
            32,
        ).map_err(|e| ProtocolError::KeyDerivationFailed(e.to_string()))?;

        let decryption_key = Hkdf::<Sha256>::derive(
            shared_secret.expose(),
            Some(context),
            Some(recv_label),
            32,
        ).map_err(|e| ProtocolError::KeyDerivationFailed(e.to_string()))?;

        let auth_key = Hkdf::<Sha256>::derive(
            shared_secret.expose(),
            Some(context),
            Some(b"authentication"),
            32,
        ).map_err(|e| ProtocolError::KeyDerivationFailed(e.to_string()))?;

        Ok(Self {
            encryption_key,
            decryption_key,
            auth_key,
        })
    }

    /// Derive new session keys for key rotation.
    ///
    /// Uses the current keys as input to derive fresh keys.
    ///
    /// # Arguments
    ///
    /// * `rotation_context` - Additional context for this rotation (e.g., counter)
    pub fn rotate(&self, rotation_context: &[u8]) -> Result<Self> {
        // Combine current keys as input in a canonical order
        // Sort encryption and decryption keys to ensure both parties get the same
        // combined material regardless of their role (initiator/responder)
        let enc_is_smaller = self.encryption_key <= self.decryption_key;
        let mut combined = Vec::new();
        if enc_is_smaller {
            combined.extend_from_slice(&self.encryption_key);
            combined.extend_from_slice(&self.decryption_key);
        } else {
            combined.extend_from_slice(&self.decryption_key);
            combined.extend_from_slice(&self.encryption_key);
        }
        combined.extend_from_slice(&self.auth_key);

        // Derive two keys with role-neutral names
        let key_a = Hkdf::<Sha256>::derive(
            &combined,
            Some(rotation_context),
            Some(b"rotated-key-a"),
            32,
        ).map_err(|e| ProtocolError::KeyDerivationFailed(e.to_string()))?;

        let key_b = Hkdf::<Sha256>::derive(
            &combined,
            Some(rotation_context),
            Some(b"rotated-key-b"),
            32,
        ).map_err(|e| ProtocolError::KeyDerivationFailed(e.to_string()))?;

        let auth_key = Hkdf::<Sha256>::derive(
            &combined,
            Some(rotation_context),
            Some(b"rotated-authentication"),
            32,
        ).map_err(|e| ProtocolError::KeyDerivationFailed(e.to_string()))?;

        // Zeroize combined
        let mut combined = combined;
        combined.zeroize();

        // Assign keys based on original role to maintain the invariant:
        // Alice's encryption = Bob's decryption
        let (encryption_key, decryption_key) = if enc_is_smaller {
            (key_a, key_b)
        } else {
            (key_b, key_a)
        };

        Ok(Self {
            encryption_key,
            decryption_key,
            auth_key,
        })
    }

    /// Get the encryption key.
    pub fn encryption_key(&self) -> &[u8] {
        &self.encryption_key
    }

    /// Get the decryption key.
    pub fn decryption_key(&self) -> &[u8] {
        &self.decryption_key
    }

    /// Get the authentication key.
    pub fn auth_key(&self) -> &[u8] {
        &self.auth_key
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_exchange::KeyExchangeProtocol;

    #[test]
    fn test_derive_session_keys() {
        let (alice_sk, alice_pk) = KeyExchangeProtocol::generate_keypair();
        let (bob_sk, bob_pk) = KeyExchangeProtocol::generate_keypair();

        let alice_shared = KeyExchangeProtocol::derive_shared_secret(&alice_sk, &bob_pk).unwrap();
        let bob_shared = KeyExchangeProtocol::derive_shared_secret(&bob_sk, &alice_pk).unwrap();

        let alice_keys = SessionKeys::derive(&alice_shared, b"test").unwrap();
        let bob_keys = SessionKeys::derive(&bob_shared, b"test").unwrap();

        // Same shared secret + context = same keys
        assert_eq!(alice_keys.encryption_key(), bob_keys.encryption_key());
        assert_eq!(alice_keys.decryption_key(), bob_keys.decryption_key());
        assert_eq!(alice_keys.auth_key(), bob_keys.auth_key());
    }

    #[test]
    fn test_different_context_different_keys() {
        let (alice_sk, alice_pk) = KeyExchangeProtocol::generate_keypair();
        let (bob_sk, bob_pk) = KeyExchangeProtocol::generate_keypair();

        let shared = KeyExchangeProtocol::derive_shared_secret(&alice_sk, &bob_pk).unwrap();

        let keys1 = SessionKeys::derive(&shared, b"context-1").unwrap();
        let keys2 = SessionKeys::derive(&shared, b"context-2").unwrap();

        assert_ne!(keys1.encryption_key(), keys2.encryption_key());
    }

    #[test]
    fn test_role_based_keys() {
        let (alice_sk, alice_pk) = KeyExchangeProtocol::generate_keypair();
        let (bob_sk, bob_pk) = KeyExchangeProtocol::generate_keypair();

        let alice_shared = KeyExchangeProtocol::derive_shared_secret(&alice_sk, &bob_pk).unwrap();
        let bob_shared = KeyExchangeProtocol::derive_shared_secret(&bob_sk, &alice_pk).unwrap();

        // Alice is initiator
        let alice_keys = SessionKeys::derive_with_roles(&alice_shared, b"test", true).unwrap();
        // Bob is responder
        let bob_keys = SessionKeys::derive_with_roles(&bob_shared, b"test", false).unwrap();

        // Alice's encryption = Bob's decryption (for initiator->responder messages)
        assert_eq!(alice_keys.encryption_key(), bob_keys.decryption_key());
        // Alice's decryption = Bob's encryption (for responder->initiator messages)
        assert_eq!(alice_keys.decryption_key(), bob_keys.encryption_key());
    }

    #[test]
    fn test_key_rotation() {
        let (alice_sk, alice_pk) = KeyExchangeProtocol::generate_keypair();
        let (bob_sk, _) = KeyExchangeProtocol::generate_keypair();

        let shared = KeyExchangeProtocol::derive_shared_secret(&bob_sk, &alice_pk).unwrap();
        let keys = SessionKeys::derive(&shared, b"test").unwrap();

        let rotated = keys.rotate(b"rotation-1").unwrap();

        // Rotated keys should be different
        assert_ne!(keys.encryption_key(), rotated.encryption_key());
        assert_ne!(keys.decryption_key(), rotated.decryption_key());

        // Same rotation context = same rotated keys
        let rotated2 = keys.rotate(b"rotation-1").unwrap();
        assert_eq!(rotated.encryption_key(), rotated2.encryption_key());

        // Different rotation context = different keys
        let rotated3 = keys.rotate(b"rotation-2").unwrap();
        assert_ne!(rotated.encryption_key(), rotated3.encryption_key());
    }

    #[test]
    fn test_key_length() {
        let (alice_sk, alice_pk) = KeyExchangeProtocol::generate_keypair();
        let (bob_sk, _) = KeyExchangeProtocol::generate_keypair();

        let shared = KeyExchangeProtocol::derive_shared_secret(&bob_sk, &alice_pk).unwrap();
        let keys = SessionKeys::derive(&shared, b"test").unwrap();

        // All keys should be 32 bytes (256 bits)
        assert_eq!(keys.encryption_key().len(), 32);
        assert_eq!(keys.decryption_key().len(), 32);
        assert_eq!(keys.auth_key().len(), 32);
    }
}
