#![no_main]

use arcanum_symmetric::{ChaCha20Poly1305Cipher, Cipher};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 32 + 12 + 1 {
        return;
    }

    // Split input into key, nonce, and plaintext
    let key = &data[..32];
    let nonce = &data[32..44];
    let plaintext = &data[44..];

    // Test encrypt/decrypt roundtrip
    if let Ok(ciphertext) = ChaCha20Poly1305Cipher::encrypt(key, nonce, plaintext, None) {
        let decrypted = ChaCha20Poly1305Cipher::decrypt(key, nonce, &ciphertext, None);
        assert!(decrypted.is_ok());
        assert_eq!(decrypted.unwrap(), plaintext);
    }

    // Test decryption of arbitrary ciphertext (should fail gracefully)
    if plaintext.len() >= 16 {
        let _ = ChaCha20Poly1305Cipher::decrypt(key, nonce, plaintext, None);
    }

    // Test with associated data
    if data.len() >= 32 + 12 + 16 + 1 {
        let aad = &data[44..60];
        let plaintext = &data[60..];
        if let Ok(ciphertext) = ChaCha20Poly1305Cipher::encrypt(key, nonce, plaintext, Some(aad)) {
            let decrypted = ChaCha20Poly1305Cipher::decrypt(key, nonce, &ciphertext, Some(aad));
            assert!(decrypted.is_ok());

            // Wrong AAD should fail
            let wrong_aad = [0u8; 16];
            let result = ChaCha20Poly1305Cipher::decrypt(key, nonce, &ciphertext, Some(&wrong_aad));
            assert!(result.is_err());
        }
    }
});
