#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use arcanum_symmetric::{Aes256Gcm, ChaCha20Poly1305Cipher, Cipher};

#[derive(Arbitrary, Debug)]
struct AeadInput {
    key: [u8; 32],
    nonce: [u8; 12],
    plaintext: Vec<u8>,
    aad: Vec<u8>,
}

fuzz_target!(|input: AeadInput| {
    // Limit plaintext size to avoid OOM
    if input.plaintext.len() > 1024 * 1024 {
        return;
    }

    // Test AES-256-GCM using the trait's static methods
    if let Ok(ciphertext) = Aes256Gcm::encrypt(&input.key, &input.nonce, &input.plaintext, Some(&input.aad)) {
        // Decrypt should succeed with correct parameters
        if let Ok(decrypted) = Aes256Gcm::decrypt(&input.key, &input.nonce, &ciphertext, Some(&input.aad)) {
            assert_eq!(input.plaintext, decrypted, "AES-GCM round-trip failed");
        }

        // Decrypt with wrong AAD should fail
        let wrong_aad = [&input.aad[..], b"tampered"].concat();
        let result = Aes256Gcm::decrypt(&input.key, &input.nonce, &ciphertext, Some(&wrong_aad));
        assert!(result.is_err(), "Wrong AAD should fail");

        // Tampered ciphertext should fail
        if !ciphertext.is_empty() {
            let mut tampered = ciphertext.clone();
            tampered[0] ^= 0xFF;
            let result = Aes256Gcm::decrypt(&input.key, &input.nonce, &tampered, Some(&input.aad));
            assert!(result.is_err(), "Tampered ciphertext should fail");
        }
    }

    // Test ChaCha20-Poly1305
    if let Ok(ciphertext) = ChaCha20Poly1305Cipher::encrypt(&input.key, &input.nonce, &input.plaintext, Some(&input.aad)) {
        if let Ok(decrypted) = ChaCha20Poly1305Cipher::decrypt(&input.key, &input.nonce, &ciphertext, Some(&input.aad)) {
            assert_eq!(input.plaintext, decrypted, "ChaCha20-Poly1305 round-trip failed");
        }
    }
});
