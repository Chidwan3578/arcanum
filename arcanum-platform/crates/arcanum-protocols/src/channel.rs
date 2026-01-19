//! Secure bidirectional communication channel.
//!
//! Provides encrypted message exchange with replay protection.

use crate::error::{ProtocolError, Result};
use crate::session::SessionKeys;
use arcanum_symmetric::prelude::*;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use zeroize::Zeroize;

/// Maximum allowed gap in sequence numbers (for out-of-order tolerance).
const MAX_SEQUENCE_GAP: u64 = 1000;

/// Encrypted message format.
#[derive(Serialize, Deserialize)]
pub struct EncryptedMessage {
    /// Message sequence number (for replay protection)
    pub sequence: u64,
    /// Nonce used for encryption
    pub nonce: Vec<u8>,
    /// Encrypted ciphertext
    pub ciphertext: Vec<u8>,
}

impl EncryptedMessage {
    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| ProtocolError::SerializationError(e.to_string()))
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bincode::deserialize(bytes).map_err(|e| ProtocolError::SerializationError(e.to_string()))
    }
}

/// Secure bidirectional communication channel.
///
/// Features:
/// - AES-256-GCM encryption
/// - Sequence numbers for replay protection
/// - Automatic nonce generation
///
/// # Example
///
/// ```rust,no_run
/// use arcanum_protocols::prelude::*;
///
/// # fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
/// // Setup keys (normally from key exchange)
/// let (alice_sk, alice_pk) = KeyExchangeProtocol::generate_keypair();
/// let (bob_sk, bob_pk) = KeyExchangeProtocol::generate_keypair();
///
/// let alice_shared = KeyExchangeProtocol::derive_shared_secret(&alice_sk, &bob_pk)?;
/// let bob_shared = KeyExchangeProtocol::derive_shared_secret(&bob_sk, &alice_pk)?;
///
/// let alice_keys = SessionKeys::derive_with_roles(&alice_shared, b"chat-v1", true)?;
/// let bob_keys = SessionKeys::derive_with_roles(&bob_shared, b"chat-v1", false)?;
///
/// let mut alice_channel = SecureChannel::new(alice_keys);
/// let mut bob_channel = SecureChannel::new(bob_keys);
///
/// // Alice sends to Bob
/// let encrypted = alice_channel.encrypt(b"Hello Bob!")?;
/// let plaintext = bob_channel.decrypt(&encrypted)?;
/// assert_eq!(plaintext, b"Hello Bob!");
///
/// // Bob responds to Alice
/// let encrypted = bob_channel.encrypt(b"Hi Alice!")?;
/// let plaintext = alice_channel.decrypt(&encrypted)?;
/// assert_eq!(plaintext, b"Hi Alice!");
/// # Ok(())
/// # }
/// ```
pub struct SecureChannel {
    /// Keys for this channel
    keys: SessionKeys,
    /// Next sequence number for sending
    send_sequence: AtomicU64,
    /// Highest received sequence number
    recv_sequence: AtomicU64,
    /// Bitmap of recently received sequences (for replay detection)
    recv_bitmap: parking_lot::Mutex<u128>,
}

impl SecureChannel {
    /// Create a new secure channel with the given session keys.
    pub fn new(keys: SessionKeys) -> Self {
        Self {
            keys,
            send_sequence: AtomicU64::new(0),
            recv_sequence: AtomicU64::new(0),
            recv_bitmap: parking_lot::Mutex::new(0),
        }
    }

    /// Encrypt a message for sending.
    ///
    /// # Arguments
    ///
    /// * `plaintext` - The message to encrypt
    ///
    /// # Returns
    ///
    /// An encrypted message that can be sent to the peer.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<EncryptedMessage> {
        let sequence = self.send_sequence.fetch_add(1, Ordering::SeqCst);

        // Check for counter overflow
        if sequence == u64::MAX {
            return Err(ProtocolError::CounterOverflow);
        }

        let nonce = Aes256Gcm::generate_nonce();

        // Include sequence in AAD for binding
        let aad = sequence.to_le_bytes();

        let ciphertext = Aes256Gcm::encrypt(
            self.keys.encryption_key(),
            &nonce,
            plaintext,
            Some(&aad),
        ).map_err(|e| ProtocolError::EncryptionFailed(e.to_string()))?;

        Ok(EncryptedMessage {
            sequence,
            nonce,
            ciphertext,
        })
    }

    /// Decrypt a received message.
    ///
    /// # Arguments
    ///
    /// * `message` - The encrypted message from the peer
    ///
    /// # Returns
    ///
    /// The decrypted plaintext.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Decryption fails (wrong key, tampered message)
    /// - Replay attack detected
    pub fn decrypt(&self, message: &EncryptedMessage) -> Result<Vec<u8>> {
        // Check for replay
        self.check_replay(message.sequence)?;

        // Include sequence in AAD
        let aad = message.sequence.to_le_bytes();

        let mut plaintext = Aes256Gcm::decrypt(
            self.keys.decryption_key(),
            &message.nonce,
            &message.ciphertext,
            Some(&aad),
        ).map_err(|e| ProtocolError::DecryptionFailed(e.to_string()))?;

        // Mark sequence as received
        self.mark_received(message.sequence);

        let result = plaintext.clone();
        plaintext.zeroize();

        Ok(result)
    }

    /// Encrypt a message and serialize to bytes.
    pub fn encrypt_to_bytes(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let message = self.encrypt(plaintext)?;
        message.to_bytes()
    }

    /// Decrypt a message from serialized bytes.
    pub fn decrypt_from_bytes(&self, bytes: &[u8]) -> Result<Vec<u8>> {
        let message = EncryptedMessage::from_bytes(bytes)?;
        self.decrypt(&message)
    }

    /// Check if a sequence number indicates a replay attack.
    fn check_replay(&self, sequence: u64) -> Result<()> {
        let current_max = self.recv_sequence.load(Ordering::SeqCst);

        // If sequence is too old
        if sequence + MAX_SEQUENCE_GAP < current_max {
            return Err(ProtocolError::ReplayDetected);
        }

        // If sequence is within the sliding window (including current_max), check bitmap
        if sequence <= current_max {
            let offset = current_max - sequence;
            if offset < 128 {
                let bitmap = self.recv_bitmap.lock();
                if (*bitmap >> offset) & 1 == 1 {
                    return Err(ProtocolError::ReplayDetected);
                }
            }
        }

        Ok(())
    }

    /// Mark a sequence number as received.
    fn mark_received(&self, sequence: u64) {
        let current_max = self.recv_sequence.load(Ordering::SeqCst);

        if sequence > current_max {
            // Update max and shift bitmap
            let shift = sequence - current_max;
            let mut bitmap = self.recv_bitmap.lock();

            if shift >= 128 {
                *bitmap = 1; // Reset with just the new sequence
            } else {
                *bitmap = (*bitmap << shift) | 1;
            }

            self.recv_sequence.store(sequence, Ordering::SeqCst);
        } else {
            // Mark in bitmap
            let offset = current_max - sequence;
            if offset < 128 {
                let mut bitmap = self.recv_bitmap.lock();
                *bitmap |= 1 << offset;
            }
        }
    }

    /// Get the current send sequence number.
    pub fn send_sequence(&self) -> u64 {
        self.send_sequence.load(Ordering::SeqCst)
    }

    /// Get the highest received sequence number.
    pub fn recv_sequence(&self) -> u64 {
        self.recv_sequence.load(Ordering::SeqCst)
    }

    /// Rotate the channel keys.
    ///
    /// # Arguments
    ///
    /// * `rotation_context` - Context for key derivation (e.g., counter)
    pub fn rotate_keys(&mut self, rotation_context: &[u8]) -> Result<()> {
        let new_keys = self.keys.rotate(rotation_context)?;
        self.keys = new_keys;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_exchange::KeyExchangeProtocol;

    fn create_channel_pair() -> (SecureChannel, SecureChannel) {
        let (alice_sk, alice_pk) = KeyExchangeProtocol::generate_keypair();
        let (bob_sk, bob_pk) = KeyExchangeProtocol::generate_keypair();

        let alice_shared = KeyExchangeProtocol::derive_shared_secret(&alice_sk, &bob_pk).unwrap();
        let bob_shared = KeyExchangeProtocol::derive_shared_secret(&bob_sk, &alice_pk).unwrap();

        let alice_keys = SessionKeys::derive_with_roles(&alice_shared, b"test", true).unwrap();
        let bob_keys = SessionKeys::derive_with_roles(&bob_shared, b"test", false).unwrap();

        (SecureChannel::new(alice_keys), SecureChannel::new(bob_keys))
    }

    #[test]
    fn test_encrypt_decrypt() {
        let (alice, bob) = create_channel_pair();

        let plaintext = b"Hello, Bob!";
        let encrypted = alice.encrypt(plaintext).unwrap();
        let decrypted = bob.decrypt(&encrypted).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_bidirectional() {
        let (alice, bob) = create_channel_pair();

        // Alice -> Bob
        let msg = alice.encrypt(b"Hello Bob").unwrap();
        assert_eq!(bob.decrypt(&msg).unwrap(), b"Hello Bob");

        // Bob -> Alice
        let msg = bob.encrypt(b"Hi Alice").unwrap();
        assert_eq!(alice.decrypt(&msg).unwrap(), b"Hi Alice");
    }

    #[test]
    fn test_sequence_numbers() {
        let (alice, bob) = create_channel_pair();

        let msg1 = alice.encrypt(b"First").unwrap();
        let msg2 = alice.encrypt(b"Second").unwrap();
        let msg3 = alice.encrypt(b"Third").unwrap();

        assert_eq!(msg1.sequence, 0);
        assert_eq!(msg2.sequence, 1);
        assert_eq!(msg3.sequence, 2);

        // Out of order delivery should work
        bob.decrypt(&msg3).unwrap();
        bob.decrypt(&msg1).unwrap();
        bob.decrypt(&msg2).unwrap();
    }

    #[test]
    fn test_replay_detection() {
        let (alice, bob) = create_channel_pair();

        let msg = alice.encrypt(b"Test").unwrap();

        // First decryption succeeds
        bob.decrypt(&msg).unwrap();

        // Replay attempt fails
        let result = bob.decrypt(&msg);
        assert!(matches!(result, Err(ProtocolError::ReplayDetected)));
    }

    #[test]
    fn test_tampered_message_fails() {
        let (alice, bob) = create_channel_pair();

        let mut msg = alice.encrypt(b"Test").unwrap();

        // Tamper with ciphertext
        if !msg.ciphertext.is_empty() {
            msg.ciphertext[0] ^= 0xFF;
        }

        let result = bob.decrypt(&msg);
        assert!(matches!(result, Err(ProtocolError::DecryptionFailed(_))));
    }

    #[test]
    fn test_wrong_sequence_fails() {
        let (alice, bob) = create_channel_pair();

        let mut msg = alice.encrypt(b"Test").unwrap();

        // Change sequence number (AAD mismatch)
        msg.sequence = 999;

        let result = bob.decrypt(&msg);
        assert!(result.is_err());
    }

    #[test]
    fn test_bytes_roundtrip() {
        let (alice, bob) = create_channel_pair();

        let encrypted = alice.encrypt_to_bytes(b"Hello!").unwrap();
        let decrypted = bob.decrypt_from_bytes(&encrypted).unwrap();

        assert_eq!(decrypted, b"Hello!");
    }

    #[test]
    fn test_key_rotation() {
        let (mut alice, mut bob) = create_channel_pair();

        // Exchange message with original keys
        let msg = alice.encrypt(b"Before rotation").unwrap();
        bob.decrypt(&msg).unwrap();

        // Rotate keys on both sides
        alice.rotate_keys(b"rotation-1").unwrap();
        bob.rotate_keys(b"rotation-1").unwrap();

        // Exchange message with rotated keys
        let msg = alice.encrypt(b"After rotation").unwrap();
        let decrypted = bob.decrypt(&msg).unwrap();
        assert_eq!(decrypted, b"After rotation");
    }

    #[test]
    fn test_different_rotation_context_fails() {
        let (mut alice, mut bob) = create_channel_pair();

        // Rotate with different contexts
        alice.rotate_keys(b"context-a").unwrap();
        bob.rotate_keys(b"context-b").unwrap();

        // Messages should fail to decrypt
        let msg = alice.encrypt(b"Test").unwrap();
        let result = bob.decrypt(&msg);
        assert!(result.is_err());
    }
}
