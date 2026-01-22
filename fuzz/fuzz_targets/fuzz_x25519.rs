#![no_main]

use arcanum_asymmetric::x25519::{X25519SecretKey, X25519PublicKey, X25519};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Test key derivation from arbitrary bytes
    if data.len() >= 32 {
        let secret_bytes: [u8; 32] = data[..32].try_into().unwrap();
        let secret_key = X25519SecretKey::from_bytes(&secret_bytes);
        let public_key = secret_key.public_key();

        // Verify public key is deterministic
        let public_key2 = secret_key.public_key();
        assert_eq!(public_key.to_bytes(), public_key2.to_bytes());

        // Test DH with another keypair from remaining data
        if data.len() >= 64 {
            let secret_bytes2: [u8; 32] = data[32..64].try_into().unwrap();
            let secret_key2 = X25519SecretKey::from_bytes(&secret_bytes2);
            let public_key2 = secret_key2.public_key();

            // DH should be commutative
            let shared1 = secret_key.diffie_hellman(&public_key2);
            let shared2 = secret_key2.diffie_hellman(&public_key);
            assert_eq!(shared1.as_bytes(), shared2.as_bytes());
        }
    }

    // Test public key from bytes (should handle all inputs)
    if data.len() >= 32 {
        let pk_bytes: [u8; 32] = data[..32].try_into().unwrap();
        let _ = X25519PublicKey::from_bytes(&pk_bytes);
    }

    // Test key generation
    let (secret, public) = X25519::generate();
    let _ = secret.diffie_hellman(&public);
});
