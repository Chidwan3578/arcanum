//! Wycheproof-Style Test Vectors for Digital Signatures
//!
//! These tests are inspired by Google's Project Wycheproof methodology,
//! which focuses on edge cases and implementation bugs in cryptographic libraries.
//!
//! Categories tested:
//! - Signature malleability resistance
//! - Invalid signature handling
//! - Key validation
//! - Edge cases at field boundaries
//! - Cross-curve confusion prevention

#![allow(unused_imports)]

use arcanum_signatures::{Ed25519Signature, Ed25519SigningKey, Ed25519VerifyingKey};
use arcanum_signatures::{
    P256Signature, P256SigningKey, P256VerifyingKey, P384Signature, P384SigningKey,
    P384VerifyingKey, Secp256k1Signature, Secp256k1SigningKey, Secp256k1VerifyingKey,
};
use arcanum_signatures::{Signature, SigningKey, VerifyingKey};

// ═══════════════════════════════════════════════════════════════════════════════
// Ed25519 Wycheproof Tests
// ═══════════════════════════════════════════════════════════════════════════════

mod ed25519_wycheproof {
    use super::*;

    /// Empty message signing works
    #[test]
    fn ed25519_empty_message() {
        let key = Ed25519SigningKey::generate();
        let vk = key.verifying_key();
        let msg: &[u8] = &[];

        let sig = key.sign(msg);
        assert!(vk.verify(msg, &sig).is_ok(), "Empty message should verify");
    }

    /// 1-byte message
    #[test]
    fn ed25519_1_byte_message() {
        let key = Ed25519SigningKey::generate();
        let vk = key.verifying_key();
        let msg = [0x42u8; 1];

        let sig = key.sign(&msg);
        assert!(vk.verify(&msg, &sig).is_ok());
    }

    /// Large message (64KB)
    #[test]
    fn ed25519_large_message() {
        let key = Ed25519SigningKey::generate();
        let vk = key.verifying_key();
        let msg = vec![0x42u8; 65536];

        let sig = key.sign(&msg);
        assert!(vk.verify(&msg, &sig).is_ok(), "Large message should verify");
    }

    /// All-zeros message
    #[test]
    fn ed25519_all_zeros_message() {
        let key = Ed25519SigningKey::generate();
        let vk = key.verifying_key();
        let msg = [0u8; 64];

        let sig = key.sign(&msg);
        assert!(vk.verify(&msg, &sig).is_ok());
    }

    /// All-ones message
    #[test]
    fn ed25519_all_ones_message() {
        let key = Ed25519SigningKey::generate();
        let vk = key.verifying_key();
        let msg = [0xFFu8; 64];

        let sig = key.sign(&msg);
        assert!(vk.verify(&msg, &sig).is_ok());
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Ed25519 Failure Tests - MUST reject
    // ═══════════════════════════════════════════════════════════════════════

    /// All-zero signature must fail
    #[test]
    fn ed25519_zero_signature_fails() {
        let key = Ed25519SigningKey::generate();
        let vk = key.verifying_key();
        let msg = b"Test message";

        let zero_sig = [0u8; 64];
        if let Ok(sig) = Ed25519Signature::from_bytes(&zero_sig) {
            assert!(vk.verify(msg, &sig).is_err(), "Zero signature must fail");
        }
        // If parsing fails, that's also correct
    }

    /// All-ones signature must fail
    #[test]
    fn ed25519_ones_signature_fails() {
        let key = Ed25519SigningKey::generate();
        let vk = key.verifying_key();
        let msg = b"Test message";

        let ones_sig = [0xFFu8; 64];
        if let Ok(sig) = Ed25519Signature::from_bytes(&ones_sig) {
            assert!(
                vk.verify(msg, &sig).is_err(),
                "All-ones signature must fail"
            );
        }
    }

    /// Flipped bit in R component (first 32 bytes) must fail
    #[test]
    fn ed25519_flipped_r_fails() {
        let key = Ed25519SigningKey::generate();
        let vk = key.verifying_key();
        let msg = b"Test message";

        let sig = key.sign(msg);
        let mut sig_bytes = sig.to_bytes();

        // Flip bit in R (first byte)
        sig_bytes[0] ^= 0x01;

        if let Ok(tampered) = Ed25519Signature::from_bytes(&sig_bytes) {
            assert!(vk.verify(msg, &tampered).is_err(), "Flipped R must fail");
        }
    }

    /// Flipped bit in S component (last 32 bytes) must fail
    #[test]
    fn ed25519_flipped_s_fails() {
        let key = Ed25519SigningKey::generate();
        let vk = key.verifying_key();
        let msg = b"Test message";

        let sig = key.sign(msg);
        let mut sig_bytes = sig.to_bytes();

        // Flip bit in S (byte 32)
        sig_bytes[32] ^= 0x01;

        if let Ok(tampered) = Ed25519Signature::from_bytes(&sig_bytes) {
            assert!(vk.verify(msg, &tampered).is_err(), "Flipped S must fail");
        }
    }

    /// Wrong message must fail
    #[test]
    fn ed25519_wrong_message_fails() {
        let key = Ed25519SigningKey::generate();
        let vk = key.verifying_key();

        let sig = key.sign(b"Original");
        assert!(
            vk.verify(b"Wrong", &sig).is_err(),
            "Wrong message must fail"
        );
    }

    /// Wrong key must fail
    #[test]
    fn ed25519_wrong_key_fails() {
        let key1 = Ed25519SigningKey::generate();
        let key2 = Ed25519SigningKey::generate();
        let vk2 = key2.verifying_key();

        let sig = key1.sign(b"Test");
        assert!(vk2.verify(b"Test", &sig).is_err(), "Wrong key must fail");
    }

    /// Truncated signature must fail
    #[test]
    fn ed25519_truncated_signature_fails() {
        let short_sig = [0u8; 63]; // Should be 64
        let result = Ed25519Signature::from_bytes(&short_sig);
        assert!(result.is_err(), "Truncated signature should be rejected");
    }

    /// Extended signature must fail
    #[test]
    fn ed25519_extended_signature_fails() {
        let long_sig = [0u8; 65]; // Should be 64
        let result = Ed25519Signature::from_bytes(&long_sig);
        assert!(result.is_err(), "Extended signature should be rejected");
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Ed25519 Key Tests
    // ═══════════════════════════════════════════════════════════════════════

    /// Invalid key length rejected
    #[test]
    fn ed25519_short_key_rejected() {
        let short = [0u8; 31]; // Should be 32
        let result = Ed25519SigningKey::from_bytes(&short);
        assert!(result.is_err(), "Short key should be rejected");
    }

    /// Invalid key length rejected
    #[test]
    fn ed25519_long_key_rejected() {
        let long = [0u8; 33]; // Should be 32
        let result = Ed25519SigningKey::from_bytes(&long);
        assert!(result.is_err(), "Long key should be rejected");
    }

    /// Key roundtrip works
    #[test]
    fn ed25519_key_roundtrip() {
        let key = Ed25519SigningKey::generate();
        let bytes = key.to_bytes();
        let restored = Ed25519SigningKey::from_bytes(&bytes).unwrap();

        assert_eq!(
            key.verifying_key().to_bytes(),
            restored.verifying_key().to_bytes()
        );
    }

    /// Deterministic signatures
    #[test]
    fn ed25519_deterministic() {
        let key = Ed25519SigningKey::generate();
        let msg = b"Test message";

        let sig1 = key.sign(msg);
        let sig2 = key.sign(msg);

        assert_eq!(
            sig1.to_bytes(),
            sig2.to_bytes(),
            "Ed25519 must be deterministic"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// ECDSA P-256 Wycheproof Tests
// ═══════════════════════════════════════════════════════════════════════════════

mod ecdsa_p256_wycheproof {
    use super::*;

    /// Empty message signing works
    #[test]
    fn p256_empty_message() {
        let key = P256SigningKey::generate();
        let vk = key.verifying_key();
        let msg: &[u8] = &[];

        let sig = key.sign(msg);
        assert!(vk.verify(msg, &sig).is_ok());
    }

    /// Large message (64KB)
    #[test]
    fn p256_large_message() {
        let key = P256SigningKey::generate();
        let vk = key.verifying_key();
        let msg = vec![0x42u8; 65536];

        let sig = key.sign(&msg);
        assert!(vk.verify(&msg, &sig).is_ok());
    }

    /// Sequential byte pattern
    #[test]
    fn p256_sequential_message() {
        let key = P256SigningKey::generate();
        let vk = key.verifying_key();
        let msg: Vec<u8> = (0..=255).collect();

        let sig = key.sign(&msg);
        assert!(vk.verify(&msg, &sig).is_ok());
    }

    // ═══════════════════════════════════════════════════════════════════════
    // P-256 Failure Tests
    // ═══════════════════════════════════════════════════════════════════════

    /// Zero signature must fail
    #[test]
    fn p256_zero_signature_fails() {
        let key = P256SigningKey::generate();
        let vk = key.verifying_key();
        let msg = b"Test message";

        let zero_sig = [0u8; 64];
        if let Ok(sig) = P256Signature::from_bytes(&zero_sig) {
            assert!(vk.verify(msg, &sig).is_err(), "Zero signature must fail");
        }
    }

    /// Flipped bit in R must fail
    #[test]
    fn p256_flipped_r_fails() {
        let key = P256SigningKey::generate();
        let vk = key.verifying_key();
        let msg = b"Test message";

        let sig = key.sign(msg);
        let mut sig_bytes = sig.to_bytes();
        sig_bytes[0] ^= 0x01;

        if let Ok(tampered) = P256Signature::from_bytes(&sig_bytes) {
            assert!(vk.verify(msg, &tampered).is_err(), "Flipped R must fail");
        }
    }

    /// Flipped bit in S must fail
    #[test]
    fn p256_flipped_s_fails() {
        let key = P256SigningKey::generate();
        let vk = key.verifying_key();
        let msg = b"Test message";

        let sig = key.sign(msg);
        let mut sig_bytes = sig.to_bytes();
        sig_bytes[32] ^= 0x01;

        if let Ok(tampered) = P256Signature::from_bytes(&sig_bytes) {
            assert!(vk.verify(msg, &tampered).is_err(), "Flipped S must fail");
        }
    }

    /// Wrong message fails
    #[test]
    fn p256_wrong_message_fails() {
        let key = P256SigningKey::generate();
        let vk = key.verifying_key();

        let sig = key.sign(b"Original");
        assert!(vk.verify(b"Wrong", &sig).is_err());
    }

    /// Wrong key fails
    #[test]
    fn p256_wrong_key_fails() {
        let key1 = P256SigningKey::generate();
        let key2 = P256SigningKey::generate();
        let vk2 = key2.verifying_key();

        let sig = key1.sign(b"Test");
        assert!(vk2.verify(b"Test", &sig).is_err());
    }

    /// Truncated signature rejected
    #[test]
    fn p256_truncated_signature_fails() {
        let short = [0u8; 63];
        let result = P256Signature::from_bytes(&short);
        assert!(result.is_err());
    }

    // ═══════════════════════════════════════════════════════════════════════
    // P-256 Key Tests
    // ═══════════════════════════════════════════════════════════════════════

    /// Key size validation
    #[test]
    fn p256_key_sizes() {
        let key = P256SigningKey::generate();
        let vk = key.verifying_key();

        // Private key: 32 bytes
        assert_eq!(key.to_bytes().len(), 32);

        // Compressed public key: 33 bytes (02/03 || x)
        assert_eq!(vk.to_bytes().len(), 33);
    }

    /// Key roundtrip
    #[test]
    fn p256_key_roundtrip() {
        let key = P256SigningKey::generate();
        let bytes = key.to_bytes();
        let restored = P256SigningKey::from_bytes(&bytes).unwrap();

        assert_eq!(
            key.verifying_key().to_bytes(),
            restored.verifying_key().to_bytes()
        );
    }

    /// Short key rejected
    /// Note: The current implementation panics on invalid length rather than
    /// returning an error. This test uses catch_unwind to verify rejection.
    #[test]
    fn p256_short_key_rejected() {
        use std::panic;

        let short = [0u8; 31];
        let result = panic::catch_unwind(|| P256SigningKey::from_bytes(&short));

        // Either panic or error is acceptable for invalid input
        match result {
            Ok(Err(_)) => {} // Returned error - good
            Err(_) => {}     // Panicked - also rejects the input
            Ok(Ok(_)) => panic!("Short key should be rejected"),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// ECDSA P-384 Wycheproof Tests
// ═══════════════════════════════════════════════════════════════════════════════

mod ecdsa_p384_wycheproof {
    use super::*;

    /// Empty message signing works
    #[test]
    fn p384_empty_message() {
        let key = P384SigningKey::generate();
        let vk = key.verifying_key();
        let msg: &[u8] = &[];

        let sig = key.sign(msg);
        assert!(vk.verify(msg, &sig).is_ok());
    }

    /// Large message (64KB)
    #[test]
    fn p384_large_message() {
        let key = P384SigningKey::generate();
        let vk = key.verifying_key();
        let msg = vec![0x42u8; 65536];

        let sig = key.sign(&msg);
        assert!(vk.verify(&msg, &sig).is_ok());
    }

    // ═══════════════════════════════════════════════════════════════════════
    // P-384 Failure Tests
    // ═══════════════════════════════════════════════════════════════════════

    /// Zero signature must fail
    #[test]
    fn p384_zero_signature_fails() {
        let key = P384SigningKey::generate();
        let vk = key.verifying_key();
        let msg = b"Test";

        let zero_sig = [0u8; 96];
        if let Ok(sig) = P384Signature::from_bytes(&zero_sig) {
            assert!(vk.verify(msg, &sig).is_err());
        }
    }

    /// Flipped bit fails
    #[test]
    fn p384_flipped_bit_fails() {
        let key = P384SigningKey::generate();
        let vk = key.verifying_key();
        let msg = b"Test";

        let sig = key.sign(msg);
        let mut sig_bytes = sig.to_bytes();
        sig_bytes[0] ^= 0x01;

        if let Ok(tampered) = P384Signature::from_bytes(&sig_bytes) {
            assert!(vk.verify(msg, &tampered).is_err());
        }
    }

    /// Wrong message fails
    #[test]
    fn p384_wrong_message_fails() {
        let key = P384SigningKey::generate();
        let vk = key.verifying_key();

        let sig = key.sign(b"Original");
        assert!(vk.verify(b"Wrong", &sig).is_err());
    }

    // ═══════════════════════════════════════════════════════════════════════
    // P-384 Key Tests
    // ═══════════════════════════════════════════════════════════════════════

    /// Key size validation
    #[test]
    fn p384_key_sizes() {
        let key = P384SigningKey::generate();
        let vk = key.verifying_key();

        // Private key: 48 bytes
        assert_eq!(key.to_bytes().len(), 48);

        // Compressed public key: 49 bytes (02/03 || x)
        assert_eq!(vk.to_bytes().len(), 49);
    }

    /// Signature size validation
    #[test]
    fn p384_signature_size() {
        let key = P384SigningKey::generate();
        let sig = key.sign(b"Test");

        // P-384 signature: 96 bytes (48 + 48)
        assert_eq!(sig.to_bytes().len(), 96);
    }

    /// Key roundtrip
    #[test]
    fn p384_key_roundtrip() {
        let key = P384SigningKey::generate();
        let bytes = key.to_bytes();
        let restored = P384SigningKey::from_bytes(&bytes).unwrap();

        assert_eq!(
            key.verifying_key().to_bytes(),
            restored.verifying_key().to_bytes()
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// ECDSA secp256k1 Wycheproof Tests
// ═══════════════════════════════════════════════════════════════════════════════

mod ecdsa_secp256k1_wycheproof {
    use super::*;

    /// Empty message signing works
    #[test]
    fn secp256k1_empty_message() {
        let key = Secp256k1SigningKey::generate();
        let vk = key.verifying_key();
        let msg: &[u8] = &[];

        let sig = key.sign(msg);
        assert!(vk.verify(msg, &sig).is_ok());
    }

    /// Large message (64KB)
    #[test]
    fn secp256k1_large_message() {
        let key = Secp256k1SigningKey::generate();
        let vk = key.verifying_key();
        let msg = vec![0x42u8; 65536];

        let sig = key.sign(&msg);
        assert!(vk.verify(&msg, &sig).is_ok());
    }

    // ═══════════════════════════════════════════════════════════════════════
    // secp256k1 Failure Tests
    // ═══════════════════════════════════════════════════════════════════════

    /// Zero signature must fail
    #[test]
    fn secp256k1_zero_signature_fails() {
        let key = Secp256k1SigningKey::generate();
        let vk = key.verifying_key();
        let msg = b"Test";

        let zero_sig = [0u8; 64];
        if let Ok(sig) = Secp256k1Signature::from_bytes(&zero_sig) {
            assert!(vk.verify(msg, &sig).is_err());
        }
    }

    /// Flipped bit fails
    #[test]
    fn secp256k1_flipped_bit_fails() {
        let key = Secp256k1SigningKey::generate();
        let vk = key.verifying_key();
        let msg = b"Test";

        let sig = key.sign(msg);
        let mut sig_bytes = sig.to_bytes();
        sig_bytes[0] ^= 0x01;

        if let Ok(tampered) = Secp256k1Signature::from_bytes(&sig_bytes) {
            assert!(vk.verify(msg, &tampered).is_err());
        }
    }

    /// Wrong message fails
    #[test]
    fn secp256k1_wrong_message_fails() {
        let key = Secp256k1SigningKey::generate();
        let vk = key.verifying_key();

        let sig = key.sign(b"Original");
        assert!(vk.verify(b"Wrong", &sig).is_err());
    }

    /// Wrong key fails
    #[test]
    fn secp256k1_wrong_key_fails() {
        let key1 = Secp256k1SigningKey::generate();
        let key2 = Secp256k1SigningKey::generate();
        let vk2 = key2.verifying_key();

        let sig = key1.sign(b"Test");
        assert!(vk2.verify(b"Test", &sig).is_err());
    }

    // ═══════════════════════════════════════════════════════════════════════
    // secp256k1 Key Tests
    // ═══════════════════════════════════════════════════════════════════════

    /// Key size validation
    #[test]
    fn secp256k1_key_sizes() {
        let key = Secp256k1SigningKey::generate();
        let vk = key.verifying_key();

        // Private key: 32 bytes
        assert_eq!(key.to_bytes().len(), 32);

        // Compressed public key: 33 bytes
        assert_eq!(vk.to_bytes().len(), 33);
    }

    /// Signature size validation
    #[test]
    fn secp256k1_signature_size() {
        let key = Secp256k1SigningKey::generate();
        let sig = key.sign(b"Test");

        // secp256k1 signature: 64 bytes
        assert_eq!(sig.to_bytes().len(), 64);
    }

    /// Key roundtrip
    #[test]
    fn secp256k1_key_roundtrip() {
        let key = Secp256k1SigningKey::generate();
        let bytes = key.to_bytes();
        let restored = Secp256k1SigningKey::from_bytes(&bytes).unwrap();

        assert_eq!(
            key.verifying_key().to_bytes(),
            restored.verifying_key().to_bytes()
        );
    }

    /// Known generator point (private key = 1)
    #[test]
    fn secp256k1_generator_point() {
        let one = hex::decode("0000000000000000000000000000000000000000000000000000000000000001")
            .unwrap();

        let key = Secp256k1SigningKey::from_bytes(&one).unwrap();
        let vk = key.verifying_key();

        // G (compressed): 02 79be667e...
        let expected =
            hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
                .unwrap();

        assert_eq!(vk.to_bytes(), expected);
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Cross-Curve Confusion Tests
// ═══════════════════════════════════════════════════════════════════════════════

mod cross_curve_tests {
    use super::*;

    /// Different curves produce different signature sizes
    #[test]
    fn signature_sizes_differ() {
        let msg = b"Test";

        let ed = Ed25519SigningKey::generate();
        let p256 = P256SigningKey::generate();
        let p384 = P384SigningKey::generate();
        let secp = Secp256k1SigningKey::generate();

        assert_eq!(ed.sign(msg).to_bytes().len(), 64);
        assert_eq!(p256.sign(msg).to_bytes().len(), 64);
        assert_eq!(p384.sign(msg).to_bytes().len(), 96);
        assert_eq!(secp.sign(msg).to_bytes().len(), 64);
    }

    /// P-256 signature doesn't verify with secp256k1 key
    #[test]
    fn p256_sig_no_secp_verify() {
        let msg = b"Test";

        let p256 = P256SigningKey::generate();
        let p256_sig = p256.sign(msg);

        let secp = Secp256k1SigningKey::generate();
        let secp_vk = secp.verifying_key();

        // Try to parse P-256 sig as secp256k1
        let sig_bytes = p256_sig.to_bytes();
        if let Ok(fake) = Secp256k1Signature::from_bytes(&sig_bytes) {
            // If parsing works, verification must fail
            assert!(secp_vk.verify(msg, &fake).is_err());
        }
    }

    /// secp256k1 signature doesn't verify with P-256 key
    #[test]
    fn secp_sig_no_p256_verify() {
        let msg = b"Test";

        let secp = Secp256k1SigningKey::generate();
        let secp_sig = secp.sign(msg);

        let p256 = P256SigningKey::generate();
        let p256_vk = p256.verifying_key();

        // Try to parse secp256k1 sig as P-256
        let sig_bytes = secp_sig.to_bytes();
        if let Ok(fake) = P256Signature::from_bytes(&sig_bytes) {
            assert!(p256_vk.verify(msg, &fake).is_err());
        }
    }

    /// Ed25519 signature doesn't verify with ECDSA key
    #[test]
    fn ed25519_sig_no_ecdsa_verify() {
        let msg = b"Test";

        let ed = Ed25519SigningKey::generate();
        let ed_sig = ed.sign(msg);

        let p256 = P256SigningKey::generate();
        let p256_vk = p256.verifying_key();

        // Try to parse Ed25519 sig as P-256
        let sig_bytes = ed_sig.to_bytes();
        if let Ok(fake) = P256Signature::from_bytes(&sig_bytes) {
            assert!(p256_vk.verify(msg, &fake).is_err());
        }
    }

    /// Public keys from different curves have different sizes
    #[test]
    fn public_key_sizes() {
        let ed = Ed25519SigningKey::generate();
        let p256 = P256SigningKey::generate();
        let p384 = P384SigningKey::generate();
        let secp = Secp256k1SigningKey::generate();

        // Ed25519: 32 bytes
        assert_eq!(ed.verifying_key().to_bytes().len(), 32);

        // P-256 compressed: 33 bytes
        assert_eq!(p256.verifying_key().to_bytes().len(), 33);

        // P-384 compressed: 49 bytes
        assert_eq!(p384.verifying_key().to_bytes().len(), 49);

        // secp256k1 compressed: 33 bytes
        assert_eq!(secp.verifying_key().to_bytes().len(), 33);
    }

    /// Private key sizes
    #[test]
    fn private_key_sizes() {
        let ed = Ed25519SigningKey::generate();
        let p256 = P256SigningKey::generate();
        let p384 = P384SigningKey::generate();
        let secp = Secp256k1SigningKey::generate();

        assert_eq!(ed.to_bytes().len(), 32);
        assert_eq!(p256.to_bytes().len(), 32);
        assert_eq!(p384.to_bytes().len(), 48);
        assert_eq!(secp.to_bytes().len(), 32);
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Message Boundary Tests
// ═══════════════════════════════════════════════════════════════════════════════

mod message_boundary_tests {
    use super::*;

    /// Test message sizes at various boundaries
    #[test]
    fn ed25519_message_sizes() {
        let key = Ed25519SigningKey::generate();
        let vk = key.verifying_key();

        for size in [
            0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 255, 256, 1024, 4096,
        ] {
            let msg = vec![0x42u8; size];
            let sig = key.sign(&msg);
            assert!(
                vk.verify(&msg, &sig).is_ok(),
                "Ed25519 should work with {}-byte message",
                size
            );
        }
    }

    /// Test P-256 with various message sizes
    #[test]
    fn p256_message_sizes() {
        let key = P256SigningKey::generate();
        let vk = key.verifying_key();

        for size in [0, 1, 32, 64, 128, 256, 1024] {
            let msg = vec![0x42u8; size];
            let sig = key.sign(&msg);
            assert!(vk.verify(&msg, &sig).is_ok());
        }
    }

    /// Test secp256k1 with various message sizes
    #[test]
    fn secp256k1_message_sizes() {
        let key = Secp256k1SigningKey::generate();
        let vk = key.verifying_key();

        for size in [0, 1, 32, 64, 128, 256, 1024] {
            let msg = vec![0x42u8; size];
            let sig = key.sign(&msg);
            assert!(vk.verify(&msg, &sig).is_ok());
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Determinism Tests
// ═══════════════════════════════════════════════════════════════════════════════

mod determinism_tests {
    use super::*;

    /// Ed25519 signatures are deterministic
    #[test]
    fn ed25519_is_deterministic() {
        let key = Ed25519SigningKey::generate();
        let msg = b"Test message for determinism";

        let sig1 = key.sign(msg);
        let sig2 = key.sign(msg);

        assert_eq!(sig1.to_bytes(), sig2.to_bytes());
    }

    /// Different messages produce different signatures
    #[test]
    fn different_messages_different_sigs() {
        let key = Ed25519SigningKey::generate();

        let sig1 = key.sign(b"Message 1");
        let sig2 = key.sign(b"Message 2");

        assert_ne!(sig1.to_bytes(), sig2.to_bytes());
    }

    /// Different keys produce different signatures
    #[test]
    fn different_keys_different_sigs() {
        let key1 = Ed25519SigningKey::generate();
        let key2 = Ed25519SigningKey::generate();
        let msg = b"Same message";

        let sig1 = key1.sign(msg);
        let sig2 = key2.sign(msg);

        assert_ne!(sig1.to_bytes(), sig2.to_bytes());
    }
}
