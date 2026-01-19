//! ChaCha20-based encryption algorithms.

use crate::traits::{Cipher, StreamCipher};
use aead::{Aead, AeadInPlace, KeyInit, Payload};
use arcanum_core::error::{Error, Result};
use rand::RngCore;

// ═══════════════════════════════════════════════════════════════════════════════
// ChaCha20-Poly1305
// ═══════════════════════════════════════════════════════════════════════════════

/// ChaCha20-Poly1305 authenticated encryption.
///
/// An excellent choice for software implementations:
/// - Constant-time by design (no table lookups)
/// - Fast on platforms without AES hardware acceleration
/// - Widely used (TLS 1.3, WireGuard, Signal)
///
/// Uses 96-bit nonces (same as AES-GCM).
pub struct ChaCha20Poly1305Cipher;

impl Cipher for ChaCha20Poly1305Cipher {
    const KEY_SIZE: usize = 32;
    const NONCE_SIZE: usize = 12;
    const TAG_SIZE: usize = 16;
    const ALGORITHM: &'static str = "ChaCha20-Poly1305";

    fn generate_key() -> Vec<u8> {
        let mut key = vec![0u8; Self::KEY_SIZE];
        rand::thread_rng().fill_bytes(&mut key);
        key
    }

    fn generate_nonce() -> Vec<u8> {
        let mut nonce = vec![0u8; Self::NONCE_SIZE];
        rand::thread_rng().fill_bytes(&mut nonce);
        nonce
    }

    fn encrypt(
        key: &[u8],
        nonce: &[u8],
        plaintext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        validate_key_nonce::<Self>(key, nonce)?;

        let cipher = chacha20poly1305::ChaCha20Poly1305::new_from_slice(key)
            .map_err(|_| Error::InvalidKeyLength {
                expected: Self::KEY_SIZE,
                actual: key.len(),
            })?;

        let nonce = chacha20poly1305::Nonce::from_slice(nonce);

        let ciphertext = match associated_data {
            Some(aad) => cipher
                .encrypt(nonce, Payload { msg: plaintext, aad })
                .map_err(|_| Error::EncryptionFailed)?,
            None => cipher
                .encrypt(nonce, plaintext)
                .map_err(|_| Error::EncryptionFailed)?,
        };

        Ok(ciphertext)
    }

    fn decrypt(
        key: &[u8],
        nonce: &[u8],
        ciphertext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        validate_key_nonce::<Self>(key, nonce)?;

        if ciphertext.len() < Self::TAG_SIZE {
            return Err(Error::CiphertextTooShort {
                minimum: Self::TAG_SIZE,
            });
        }

        let cipher = chacha20poly1305::ChaCha20Poly1305::new_from_slice(key)
            .map_err(|_| Error::InvalidKeyLength {
                expected: Self::KEY_SIZE,
                actual: key.len(),
            })?;

        let nonce = chacha20poly1305::Nonce::from_slice(nonce);

        let plaintext = match associated_data {
            Some(aad) => cipher
                .decrypt(nonce, Payload { msg: ciphertext, aad })
                .map_err(|_| Error::DecryptionFailed)?,
            None => cipher
                .decrypt(nonce, ciphertext)
                .map_err(|_| Error::DecryptionFailed)?,
        };

        Ok(plaintext)
    }

    fn encrypt_in_place(
        key: &[u8],
        nonce: &[u8],
        associated_data: &[u8],
        buffer: &mut Vec<u8>,
    ) -> Result<()> {
        validate_key_nonce::<Self>(key, nonce)?;

        let cipher = chacha20poly1305::ChaCha20Poly1305::new_from_slice(key)
            .map_err(|_| Error::InvalidKeyLength {
                expected: Self::KEY_SIZE,
                actual: key.len(),
            })?;

        let nonce = chacha20poly1305::Nonce::from_slice(nonce);

        cipher
            .encrypt_in_place(nonce, associated_data, buffer)
            .map_err(|_| Error::EncryptionFailed)
    }

    fn decrypt_in_place(
        key: &[u8],
        nonce: &[u8],
        associated_data: &[u8],
        buffer: &mut Vec<u8>,
    ) -> Result<()> {
        validate_key_nonce::<Self>(key, nonce)?;

        let cipher = chacha20poly1305::ChaCha20Poly1305::new_from_slice(key)
            .map_err(|_| Error::InvalidKeyLength {
                expected: Self::KEY_SIZE,
                actual: key.len(),
            })?;

        let nonce = chacha20poly1305::Nonce::from_slice(nonce);

        cipher
            .decrypt_in_place(nonce, associated_data, buffer)
            .map_err(|_| Error::DecryptionFailed)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// XChaCha20-Poly1305
// ═══════════════════════════════════════════════════════════════════════════════

/// XChaCha20-Poly1305 authenticated encryption with extended nonce.
///
/// The "X" variant uses 192-bit (24 byte) nonces, which allows:
/// - Safe random nonce generation (collision probability negligible)
/// - No need for nonce counters or careful nonce management
///
/// **Recommended when**: You want simple, safe nonce handling.
pub struct XChaCha20Poly1305Cipher;

impl Cipher for XChaCha20Poly1305Cipher {
    const KEY_SIZE: usize = 32;
    const NONCE_SIZE: usize = 24; // Extended nonce!
    const TAG_SIZE: usize = 16;
    const ALGORITHM: &'static str = "XChaCha20-Poly1305";

    fn generate_key() -> Vec<u8> {
        let mut key = vec![0u8; Self::KEY_SIZE];
        rand::thread_rng().fill_bytes(&mut key);
        key
    }

    fn generate_nonce() -> Vec<u8> {
        let mut nonce = vec![0u8; Self::NONCE_SIZE];
        rand::thread_rng().fill_bytes(&mut nonce);
        nonce
    }

    fn encrypt(
        key: &[u8],
        nonce: &[u8],
        plaintext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        validate_key_nonce::<Self>(key, nonce)?;

        let cipher = chacha20poly1305::XChaCha20Poly1305::new_from_slice(key)
            .map_err(|_| Error::InvalidKeyLength {
                expected: Self::KEY_SIZE,
                actual: key.len(),
            })?;

        let nonce = chacha20poly1305::XNonce::from_slice(nonce);

        let ciphertext = match associated_data {
            Some(aad) => cipher
                .encrypt(nonce, Payload { msg: plaintext, aad })
                .map_err(|_| Error::EncryptionFailed)?,
            None => cipher
                .encrypt(nonce, plaintext)
                .map_err(|_| Error::EncryptionFailed)?,
        };

        Ok(ciphertext)
    }

    fn decrypt(
        key: &[u8],
        nonce: &[u8],
        ciphertext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        validate_key_nonce::<Self>(key, nonce)?;

        if ciphertext.len() < Self::TAG_SIZE {
            return Err(Error::CiphertextTooShort {
                minimum: Self::TAG_SIZE,
            });
        }

        let cipher = chacha20poly1305::XChaCha20Poly1305::new_from_slice(key)
            .map_err(|_| Error::InvalidKeyLength {
                expected: Self::KEY_SIZE,
                actual: key.len(),
            })?;

        let nonce = chacha20poly1305::XNonce::from_slice(nonce);

        let plaintext = match associated_data {
            Some(aad) => cipher
                .decrypt(nonce, Payload { msg: ciphertext, aad })
                .map_err(|_| Error::DecryptionFailed)?,
            None => cipher
                .decrypt(nonce, ciphertext)
                .map_err(|_| Error::DecryptionFailed)?,
        };

        Ok(plaintext)
    }

    fn encrypt_in_place(
        key: &[u8],
        nonce: &[u8],
        associated_data: &[u8],
        buffer: &mut Vec<u8>,
    ) -> Result<()> {
        validate_key_nonce::<Self>(key, nonce)?;

        let cipher = chacha20poly1305::XChaCha20Poly1305::new_from_slice(key)
            .map_err(|_| Error::InvalidKeyLength {
                expected: Self::KEY_SIZE,
                actual: key.len(),
            })?;

        let nonce = chacha20poly1305::XNonce::from_slice(nonce);

        cipher
            .encrypt_in_place(nonce, associated_data, buffer)
            .map_err(|_| Error::EncryptionFailed)
    }

    fn decrypt_in_place(
        key: &[u8],
        nonce: &[u8],
        associated_data: &[u8],
        buffer: &mut Vec<u8>,
    ) -> Result<()> {
        validate_key_nonce::<Self>(key, nonce)?;

        let cipher = chacha20poly1305::XChaCha20Poly1305::new_from_slice(key)
            .map_err(|_| Error::InvalidKeyLength {
                expected: Self::KEY_SIZE,
                actual: key.len(),
            })?;

        let nonce = chacha20poly1305::XNonce::from_slice(nonce);

        cipher
            .decrypt_in_place(nonce, associated_data, buffer)
            .map_err(|_| Error::DecryptionFailed)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// ChaCha20 Stream Cipher
// ═══════════════════════════════════════════════════════════════════════════════

/// ChaCha20 stream cipher (without authentication).
///
/// **Warning**: This does NOT provide authentication. Only use when you have
/// external integrity protection (e.g., in a larger protocol that adds a MAC).
///
/// For most applications, use ChaCha20-Poly1305 instead.
pub struct ChaCha20Stream {
    cipher: chacha20::ChaCha20,
    position: u64,
}

impl StreamCipher for ChaCha20Stream {
    const KEY_SIZE: usize = 32;
    const NONCE_SIZE: usize = 12;
    const ALGORITHM: &'static str = "ChaCha20";

    fn new(key: &[u8], nonce: &[u8]) -> Result<Self> {
        if key.len() != Self::KEY_SIZE {
            return Err(Error::InvalidKeyLength {
                expected: Self::KEY_SIZE,
                actual: key.len(),
            });
        }

        if nonce.len() != Self::NONCE_SIZE {
            return Err(Error::InvalidNonceLength {
                expected: Self::NONCE_SIZE,
                actual: nonce.len(),
            });
        }

        use cipher::KeyIvInit;
        let cipher = chacha20::ChaCha20::new_from_slices(key, nonce)
            .map_err(|_| Error::InvalidKeyLength {
                expected: Self::KEY_SIZE,
                actual: key.len(),
            })?;

        Ok(Self { cipher, position: 0 })
    }

    fn apply_keystream(&mut self, data: &mut [u8]) {
        use cipher::StreamCipher;
        self.cipher.apply_keystream(data);
        self.position += data.len() as u64;
    }

    fn seek(&mut self, position: u64) -> Result<()> {
        use cipher::StreamCipherSeek;
        self.cipher.seek(position);
        self.position = position;
        Ok(())
    }

    fn position(&self) -> u64 {
        self.position
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

fn validate_key_nonce<C: Cipher>(key: &[u8], nonce: &[u8]) -> Result<()> {
    if key.len() != C::KEY_SIZE {
        return Err(Error::InvalidKeyLength {
            expected: C::KEY_SIZE,
            actual: key.len(),
        });
    }

    if nonce.len() != C::NONCE_SIZE {
        return Err(Error::InvalidNonceLength {
            expected: C::NONCE_SIZE,
            actual: nonce.len(),
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_cipher_roundtrip<C: Cipher>() {
        let key = C::generate_key();
        let nonce = C::generate_nonce();
        let plaintext = b"Hello, Arcanum! Testing ChaCha ciphers.";

        let ciphertext = C::encrypt(&key, &nonce, plaintext, None).unwrap();
        let decrypted = C::decrypt(&key, &nonce, &ciphertext, None).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    fn test_cipher_with_aad<C: Cipher>() {
        let key = C::generate_key();
        let nonce = C::generate_nonce();
        let plaintext = b"Secret data";
        let aad = b"Additional authenticated data";

        let ciphertext = C::encrypt(&key, &nonce, plaintext, Some(aad)).unwrap();
        let decrypted = C::decrypt(&key, &nonce, &ciphertext, Some(aad)).unwrap();

        assert_eq!(decrypted, plaintext);

        // Wrong AAD should fail
        let wrong_aad = b"Wrong AAD";
        assert!(C::decrypt(&key, &nonce, &ciphertext, Some(wrong_aad)).is_err());
    }

    #[test]
    fn test_chacha20_poly1305() {
        test_cipher_roundtrip::<ChaCha20Poly1305Cipher>();
        test_cipher_with_aad::<ChaCha20Poly1305Cipher>();
    }

    #[test]
    fn test_xchacha20_poly1305() {
        test_cipher_roundtrip::<XChaCha20Poly1305Cipher>();
        test_cipher_with_aad::<XChaCha20Poly1305Cipher>();
    }

    #[test]
    fn test_chacha20_stream() {
        let key = vec![0u8; 32];
        let nonce = vec![0u8; 12];

        let mut cipher = ChaCha20Stream::new(&key, &nonce).unwrap();
        let mut data = b"Hello, World!".to_vec();
        let original = data.clone();

        cipher.apply_keystream(&mut data);
        assert_ne!(data, original);

        // Decrypt by re-applying keystream
        let mut cipher = ChaCha20Stream::new(&key, &nonce).unwrap();
        cipher.apply_keystream(&mut data);
        assert_eq!(data, original);
    }

    #[test]
    fn test_chacha20_stream_seek() {
        let key = vec![0u8; 32];
        let nonce = vec![0u8; 12];

        let mut cipher1 = ChaCha20Stream::new(&key, &nonce).unwrap();
        let mut cipher2 = ChaCha20Stream::new(&key, &nonce).unwrap();

        // Advance cipher1 by 100 bytes
        let mut buf = vec![0u8; 100];
        cipher1.apply_keystream(&mut buf);

        // Seek cipher2 to position 100
        cipher2.seek(100).unwrap();

        // Both should produce the same keystream from here
        let mut data1 = vec![0u8; 32];
        let mut data2 = vec![0u8; 32];

        cipher1.apply_keystream(&mut data1);
        cipher2.apply_keystream(&mut data2);

        assert_eq!(data1, data2);
    }

    #[test]
    fn test_xchacha_nonce_size() {
        // XChaCha20 should use 24-byte nonces
        assert_eq!(XChaCha20Poly1305Cipher::NONCE_SIZE, 24);

        let key = XChaCha20Poly1305Cipher::generate_key();
        let nonce = XChaCha20Poly1305Cipher::generate_nonce();

        assert_eq!(key.len(), 32);
        assert_eq!(nonce.len(), 24);
    }

    #[test]
    fn test_wrong_key_fails() {
        let key = ChaCha20Poly1305Cipher::generate_key();
        let wrong_key = ChaCha20Poly1305Cipher::generate_key();
        let nonce = ChaCha20Poly1305Cipher::generate_nonce();
        let plaintext = b"Secret";

        let ciphertext = ChaCha20Poly1305Cipher::encrypt(&key, &nonce, plaintext, None).unwrap();
        assert!(ChaCha20Poly1305Cipher::decrypt(&wrong_key, &nonce, &ciphertext, None).is_err());
    }
}
