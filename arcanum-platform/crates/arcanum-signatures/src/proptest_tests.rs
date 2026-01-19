//! Property-based tests for digital signatures.
//!
//! These tests use proptest to verify signature properties hold
//! for arbitrary messages.

use proptest::prelude::*;

use crate::prelude::*;

// ═══════════════════════════════════════════════════════════════════════════════
// STRATEGIES
// ═══════════════════════════════════════════════════════════════════════════════

/// Strategy for generating arbitrary messages.
fn message_strategy() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..4096)
}

// ═══════════════════════════════════════════════════════════════════════════════
// ED25519 PROPERTIES
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(feature = "ed25519")]
proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Property: Ed25519 sign then verify succeeds
    #[test]
    fn ed25519_sign_verify_roundtrip(message in message_strategy()) {
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        let signature = signing_key.sign(&message);
        let result = verifying_key.verify(&message, &signature);

        prop_assert!(result.is_ok(), "valid signature should verify");
    }

    /// Property: Ed25519 wrong message fails verification
    #[test]
    fn ed25519_wrong_message_fails(
        message1 in message_strategy(),
        message2 in message_strategy()
    ) {
        prop_assume!(message1 != message2);

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        let signature = signing_key.sign(&message1);
        let result = verifying_key.verify(&message2, &signature);

        prop_assert!(result.is_err(), "wrong message should fail verification");
    }

    /// Property: Ed25519 wrong key fails verification
    #[test]
    fn ed25519_wrong_key_fails(message in message_strategy()) {
        let signing_key = Ed25519SigningKey::generate();
        let wrong_signing_key = Ed25519SigningKey::generate();
        let wrong_verifying_key = wrong_signing_key.verifying_key();

        let signature = signing_key.sign(&message);
        let result = wrong_verifying_key.verify(&message, &signature);

        prop_assert!(result.is_err(), "wrong key should fail verification");
    }

    /// Property: Ed25519 signatures are deterministic
    #[test]
    fn ed25519_deterministic_signatures(message in message_strategy()) {
        let signing_key = Ed25519SigningKey::generate();

        let sig1 = signing_key.sign(&message);
        let sig2 = signing_key.sign(&message);

        prop_assert_eq!(sig1.to_bytes(), sig2.to_bytes());
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// ECDSA P256 PROPERTIES
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(feature = "ecdsa")]
proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))] // ECDSA is slower

    /// Property: ECDSA P256 sign then verify succeeds
    #[test]
    fn p256_sign_verify_roundtrip(message in message_strategy()) {
        let signing_key = P256SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        let signature = signing_key.sign(&message);
        let result = verifying_key.verify(&message, &signature);

        prop_assert!(result.is_ok(), "valid signature should verify");
    }

    /// Property: ECDSA P256 wrong message fails verification
    #[test]
    fn p256_wrong_message_fails(
        message1 in message_strategy(),
        message2 in message_strategy()
    ) {
        prop_assume!(message1 != message2);

        let signing_key = P256SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        let signature = signing_key.sign(&message1);
        let result = verifying_key.verify(&message2, &signature);

        prop_assert!(result.is_err(), "wrong message should fail verification");
    }

    /// Property: ECDSA secp256k1 sign then verify succeeds
    #[test]
    fn secp256k1_sign_verify_roundtrip(message in message_strategy()) {
        let signing_key = Secp256k1SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        let signature = signing_key.sign(&message);
        let result = verifying_key.verify(&message, &signature);

        prop_assert!(result.is_ok(), "valid signature should verify");
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// SCHNORR PROPERTIES
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(feature = "schnorr")]
proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))]

    /// Property: Schnorr sign then verify succeeds
    #[test]
    fn schnorr_sign_verify_roundtrip(message in message_strategy()) {
        let signing_key = SchnorrSigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        let signature = signing_key.sign(&message);
        let result = verifying_key.verify(&message, &signature);

        prop_assert!(result.is_ok(), "valid signature should verify");
    }

    /// Property: Schnorr wrong message fails verification
    #[test]
    fn schnorr_wrong_message_fails(
        message1 in message_strategy(),
        message2 in message_strategy()
    ) {
        prop_assume!(message1 != message2);

        let signing_key = SchnorrSigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        let signature = signing_key.sign(&message1);
        let result = verifying_key.verify(&message2, &signature);

        prop_assert!(result.is_err(), "wrong message should fail verification");
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// CROSS-CUTTING PROPERTIES
// ═══════════════════════════════════════════════════════════════════════════════

proptest! {
    #![proptest_config(ProptestConfig::with_cases(20))]

    /// Property: Different keys produce different signatures
    #[cfg(feature = "ed25519")]
    #[test]
    fn different_keys_different_signatures(message in message_strategy()) {
        let key1 = Ed25519SigningKey::generate();
        let key2 = Ed25519SigningKey::generate();

        let sig1 = key1.sign(&message);
        let sig2 = key2.sign(&message);

        prop_assert_ne!(sig1.to_bytes(), sig2.to_bytes());
    }

    /// Property: Key serialization roundtrip preserves functionality
    #[cfg(feature = "ed25519")]
    #[test]
    fn ed25519_key_serialization_roundtrip(message in message_strategy()) {
        let original_key = Ed25519SigningKey::generate();
        let verifying_key = original_key.verifying_key();

        // Serialize and deserialize verifying key
        let hex = verifying_key.to_hex();
        let restored_key = Ed25519VerifyingKey::from_hex(&hex)
            .expect("deserialization should succeed");

        // Sign with original, verify with restored
        let signature = original_key.sign(&message);
        let result = restored_key.verify(&message, &signature);

        prop_assert!(result.is_ok(), "restored key should verify signature");
    }
}
