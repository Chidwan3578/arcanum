#![no_main]

use arcanum_symmetric::{Aes256Gcm, Cipher};
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
    if let Ok(ciphertext) = Aes256Gcm::encrypt(key, nonce, plaintext, None) {
        let decrypted = Aes256Gcm::decrypt(key, nonce, &ciphertext, None);
        assert!(decrypted.is_ok());
        assert_eq!(decrypted.unwrap(), plaintext);
    }

    // Test decryption of arbitrary ciphertext (should fail gracefully)
    if plaintext.len() >= 16 {
        let _ = Aes256Gcm::decrypt(key, nonce, plaintext, None);
    }

    // Test with associated data
    if data.len() >= 32 + 12 + 16 + 1 {
        let aad = &data[44..60];
        let plaintext = &data[60..];
        if let Ok(ciphertext) = Aes256Gcm::encrypt(key, nonce, plaintext, Some(aad)) {
            let decrypted = Aes256Gcm::decrypt(key, nonce, &ciphertext, Some(aad));
            assert!(decrypted.is_ok());

            // Wrong AAD should fail - XOR with 0xFF to guarantee it's different
            let mut wrong_aad = [0u8; 16];
            for (i, &b) in aad.iter().enumerate() {
                wrong_aad[i] = b ^ 0xFF;
            }
            let result = Aes256Gcm::decrypt(key, nonce, &ciphertext, Some(&wrong_aad));
            assert!(result.is_err());
        }
    }
});
