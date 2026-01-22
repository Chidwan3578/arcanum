#![no_main]

use arcanum_signatures::ed25519::{Ed25519SigningKey, Ed25519VerifyingKey};
use arcanum_signatures::{SigningKey, VerifyingKey};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Test signing with generated keypair
    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();

    // Sign the fuzzed data
    let signature = signing_key.sign(data);

    // Verify should succeed
    assert!(verifying_key.verify(data, &signature).is_ok());

    // Verify with wrong message should fail
    if !data.is_empty() {
        let mut wrong_message = data.to_vec();
        wrong_message[0] ^= 0xff;
        assert!(verifying_key.verify(&wrong_message, &signature).is_err());
    }

    // Test verifying key parsing (should handle all inputs gracefully)
    if data.len() >= 32 {
        let key_bytes: [u8; 32] = data[..32].try_into().unwrap();
        let _ = Ed25519VerifyingKey::from_bytes(&key_bytes);
    }

    // Test signing key from bytes
    if data.len() >= 32 {
        let key_bytes: [u8; 32] = data[..32].try_into().unwrap();
        if let Ok(sk) = Ed25519SigningKey::from_bytes(&key_bytes) {
            let message = if data.len() > 32 { &data[32..] } else { &[] };
            let _ = sk.sign(message);
        }
    }
});
