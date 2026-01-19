//! Property-based tests for symmetric encryption.
//!
//! These tests use proptest to verify cryptographic properties hold
//! for arbitrary inputs.

use proptest::prelude::*;

use crate::prelude::*;

// ═══════════════════════════════════════════════════════════════════════════════
// STRATEGIES
// ═══════════════════════════════════════════════════════════════════════════════

/// Strategy for generating arbitrary plaintext of various sizes.
fn plaintext_strategy() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..4096)
}

/// Strategy for generating associated data.
fn aad_strategy() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..256)
}

// ═══════════════════════════════════════════════════════════════════════════════
// ROUNDTRIP PROPERTIES
// ═══════════════════════════════════════════════════════════════════════════════

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Property: Encrypt then decrypt returns original plaintext (AES-256-GCM)
    #[test]
    fn aes256gcm_roundtrip(plaintext in plaintext_strategy()) {
        let key = Aes256Gcm::generate_key();
        let nonce = Aes256Gcm::generate_nonce();

        let ciphertext = Aes256Gcm::encrypt(&key, &nonce, &plaintext, None)
            .expect("encryption should succeed");
        let decrypted = Aes256Gcm::decrypt(&key, &nonce, &ciphertext, None)
            .expect("decryption should succeed");

        prop_assert_eq!(decrypted, plaintext);
    }

    /// Property: Encrypt then decrypt returns original plaintext (AES-128-GCM)
    #[test]
    fn aes128gcm_roundtrip(plaintext in plaintext_strategy()) {
        let key = Aes128Gcm::generate_key();
        let nonce = Aes128Gcm::generate_nonce();

        let ciphertext = Aes128Gcm::encrypt(&key, &nonce, &plaintext, None)
            .expect("encryption should succeed");
        let decrypted = Aes128Gcm::decrypt(&key, &nonce, &ciphertext, None)
            .expect("decryption should succeed");

        prop_assert_eq!(decrypted, plaintext);
    }

    /// Property: Encrypt then decrypt returns original plaintext (AES-256-GCM-SIV)
    #[test]
    fn aes256gcmsiv_roundtrip(plaintext in plaintext_strategy()) {
        let key = Aes256GcmSiv::generate_key();
        let nonce = Aes256GcmSiv::generate_nonce();

        let ciphertext = Aes256GcmSiv::encrypt(&key, &nonce, &plaintext, None)
            .expect("encryption should succeed");
        let decrypted = Aes256GcmSiv::decrypt(&key, &nonce, &ciphertext, None)
            .expect("decryption should succeed");

        prop_assert_eq!(decrypted, plaintext);
    }

    /// Property: Encrypt then decrypt returns original plaintext (ChaCha20-Poly1305)
    #[test]
    fn chacha20poly1305_roundtrip(plaintext in plaintext_strategy()) {
        let key = ChaCha20Poly1305Cipher::generate_key();
        let nonce = ChaCha20Poly1305Cipher::generate_nonce();

        let ciphertext = ChaCha20Poly1305Cipher::encrypt(&key, &nonce, &plaintext, None)
            .expect("encryption should succeed");
        let decrypted = ChaCha20Poly1305Cipher::decrypt(&key, &nonce, &ciphertext, None)
            .expect("decryption should succeed");

        prop_assert_eq!(decrypted, plaintext);
    }

    /// Property: Encrypt then decrypt returns original plaintext (XChaCha20-Poly1305)
    #[test]
    fn xchacha20poly1305_roundtrip(plaintext in plaintext_strategy()) {
        let key = XChaCha20Poly1305Cipher::generate_key();
        let nonce = XChaCha20Poly1305Cipher::generate_nonce();

        let ciphertext = XChaCha20Poly1305Cipher::encrypt(&key, &nonce, &plaintext, None)
            .expect("encryption should succeed");
        let decrypted = XChaCha20Poly1305Cipher::decrypt(&key, &nonce, &ciphertext, None)
            .expect("decryption should succeed");

        prop_assert_eq!(decrypted, plaintext);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // SEAL/OPEN PROPERTIES
    // ═══════════════════════════════════════════════════════════════════════════

    /// Property: Seal then open returns original plaintext
    #[test]
    fn seal_open_roundtrip(plaintext in plaintext_strategy()) {
        let key = Aes256Gcm::generate_key();

        let sealed = Aes256Gcm::seal(&key, &plaintext)
            .expect("seal should succeed");
        let opened = Aes256Gcm::open(&key, &sealed)
            .expect("open should succeed");

        prop_assert_eq!(opened, plaintext);
    }

    /// Property: Seal with AAD then open with same AAD returns original plaintext
    #[test]
    fn seal_open_with_aad_roundtrip(
        plaintext in plaintext_strategy(),
        aad in aad_strategy()
    ) {
        let key = Aes256Gcm::generate_key();

        let sealed = Aes256Gcm::seal_with_aad(&key, &plaintext, &aad)
            .expect("seal should succeed");
        let opened = Aes256Gcm::open_with_aad(&key, &sealed, &aad)
            .expect("open should succeed");

        prop_assert_eq!(opened, plaintext);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // CIPHER INSTANCE PROPERTIES
    // ═══════════════════════════════════════════════════════════════════════════

    /// Property: CipherInstance encrypt/decrypt roundtrip
    #[test]
    fn cipher_instance_roundtrip(plaintext in plaintext_strategy()) {
        let key = Aes256Gcm::generate_key();
        let cipher = CipherInstance::<Aes256Gcm>::new(&key)
            .expect("cipher creation should succeed");

        let ciphertext = cipher.encrypt(&plaintext)
            .expect("encryption should succeed");
        let decrypted = cipher.decrypt(&ciphertext)
            .expect("decryption should succeed");

        prop_assert_eq!(decrypted, plaintext);
    }

    /// Property: CipherInstance with counter nonce produces unique nonces
    #[test]
    fn cipher_instance_counter_unique_nonces(plaintext in plaintext_strategy()) {
        let key = Aes256Gcm::generate_key();
        let cipher = CipherInstance::<Aes256Gcm>::builder()
            .key(&key)
            .nonce_strategy(NonceStrategy::Counter)
            .build()
            .expect("cipher creation should succeed");

        let ct1 = cipher.encrypt(&plaintext).expect("encrypt 1");
        let ct2 = cipher.encrypt(&plaintext).expect("encrypt 2");
        let ct3 = cipher.encrypt(&plaintext).expect("encrypt 3");

        // Extract nonces (first 12 bytes)
        let nonce1 = &ct1[..12];
        let nonce2 = &ct2[..12];
        let nonce3 = &ct3[..12];

        // All nonces should be unique
        prop_assert_ne!(nonce1, nonce2);
        prop_assert_ne!(nonce2, nonce3);
        prop_assert_ne!(nonce1, nonce3);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // CIPHERTEXT PROPERTIES
    // ═══════════════════════════════════════════════════════════════════════════

    /// Property: Ciphertext length is predictable (plaintext + tag)
    #[test]
    fn ciphertext_length_predictable(plaintext in plaintext_strategy()) {
        let key = Aes256Gcm::generate_key();
        let nonce = Aes256Gcm::generate_nonce();

        let ciphertext = Aes256Gcm::encrypt(&key, &nonce, &plaintext, None)
            .expect("encryption should succeed");

        // Ciphertext = plaintext + 16-byte tag
        prop_assert_eq!(ciphertext.len(), plaintext.len() + 16);
    }

    /// Property: Sealed data length is nonce + plaintext + tag
    #[test]
    fn sealed_length_predictable(plaintext in plaintext_strategy()) {
        let key = Aes256Gcm::generate_key();

        let sealed = Aes256Gcm::seal(&key, &plaintext)
            .expect("seal should succeed");

        // Sealed = 12-byte nonce + plaintext + 16-byte tag
        prop_assert_eq!(sealed.len(), 12 + plaintext.len() + 16);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // TAMPERING DETECTION
    // ═══════════════════════════════════════════════════════════════════════════

    /// Property: Modifying any byte of ciphertext causes decryption failure
    #[test]
    fn tampering_detected(
        plaintext in prop::collection::vec(any::<u8>(), 1..256),
        flip_position in 0usize..1000usize
    ) {
        let key = Aes256Gcm::generate_key();
        let nonce = Aes256Gcm::generate_nonce();

        let ciphertext = Aes256Gcm::encrypt(&key, &nonce, &plaintext, None)
            .expect("encryption should succeed");

        // Flip a bit at a position within the ciphertext
        let pos = flip_position % ciphertext.len();
        let mut tampered = ciphertext.clone();
        tampered[pos] ^= 0x01;

        // Decryption should fail
        let result = Aes256Gcm::decrypt(&key, &nonce, &tampered, None);
        prop_assert!(result.is_err(), "tampered ciphertext should not decrypt");
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // AAD VERIFICATION
    // ═══════════════════════════════════════════════════════════════════════════

    /// Property: Wrong AAD causes decryption failure
    #[test]
    fn wrong_aad_fails(
        plaintext in plaintext_strategy(),
        aad1 in aad_strategy(),
        aad2 in aad_strategy()
    ) {
        // Only test when AADs are actually different
        prop_assume!(aad1 != aad2);

        let key = Aes256Gcm::generate_key();
        let nonce = Aes256Gcm::generate_nonce();

        let ciphertext = Aes256Gcm::encrypt(&key, &nonce, &plaintext, Some(&aad1))
            .expect("encryption should succeed");

        // Decryption with wrong AAD should fail
        let result = Aes256Gcm::decrypt(&key, &nonce, &ciphertext, Some(&aad2));
        prop_assert!(result.is_err(), "wrong AAD should cause decryption failure");
    }
}
