//! Tests for ML-DSA implementation
//!
//! Organized into:
//! - Unit tests (in each module)
//! - Integration tests (sign/verify roundtrip)
//! - KAT tests (FIPS 204 test vectors)

#[cfg(test)]
mod integration {
    use crate::ml_dsa::{MlDsa, MlDsa44, MlDsa65, MlDsa87};

    /// Test that ML-DSA-44 sign/verify roundtrip works
    #[test]
    fn test_ml_dsa_44_sign_verify_roundtrip() {
        let (sk, vk) = MlDsa44::generate_keypair();
        let message = b"Test message for ML-DSA-44 integration test";
        let sig = MlDsa44::sign(&sk, message);
        assert!(
            MlDsa44::verify(&vk, message, &sig).is_ok(),
            "ML-DSA-44 sign/verify roundtrip failed"
        );
    }

    /// Test that ML-DSA-65 sign/verify roundtrip works
    #[test]
    fn test_ml_dsa_65_sign_verify_roundtrip() {
        let (sk, vk) = MlDsa65::generate_keypair();
        let message = b"Test message for ML-DSA-65 integration test";
        let sig = MlDsa65::sign(&sk, message);
        assert!(
            MlDsa65::verify(&vk, message, &sig).is_ok(),
            "ML-DSA-65 sign/verify roundtrip failed"
        );
    }

    /// Test that ML-DSA-87 sign/verify roundtrip works
    #[test]
    fn test_ml_dsa_87_sign_verify_roundtrip() {
        let (sk, vk) = MlDsa87::generate_keypair();
        let message = b"Test message for ML-DSA-87 integration test";
        let sig = MlDsa87::sign(&sk, message);
        assert!(
            MlDsa87::verify(&vk, message, &sig).is_ok(),
            "ML-DSA-87 sign/verify roundtrip failed"
        );
    }

    /// Test that wrong message fails verification
    #[test]
    fn test_wrong_message_fails() {
        let (sk, vk) = MlDsa65::generate_keypair();
        let sig = MlDsa65::sign(&sk, b"message 1");
        assert!(
            MlDsa65::verify(&vk, b"message 2", &sig).is_err(),
            "Verification should fail for wrong message"
        );
    }

    /// Test that wrong key fails verification
    #[test]
    fn test_wrong_key_fails() {
        let (sk1, _vk1) = MlDsa65::generate_keypair();
        let (_sk2, vk2) = MlDsa65::generate_keypair();
        let sig = MlDsa65::sign(&sk1, b"test message");
        assert!(
            MlDsa65::verify(&vk2, b"test message", &sig).is_err(),
            "Verification should fail with wrong key"
        );
    }

    /// Test signing and verification with empty message
    #[test]
    fn test_empty_message() {
        let (sk, vk) = MlDsa44::generate_keypair();
        let message = b"";
        let sig = MlDsa44::sign(&sk, message);
        assert!(
            MlDsa44::verify(&vk, message, &sig).is_ok(),
            "Empty message sign/verify failed"
        );
    }

    /// Test signing and verification with large message
    #[test]
    fn test_large_message() {
        let (sk, vk) = MlDsa65::generate_keypair();
        let message = vec![0xABu8; 100_000]; // 100KB message
        let sig = MlDsa65::sign(&sk, &message);
        assert!(
            MlDsa65::verify(&vk, &message, &sig).is_ok(),
            "Large message sign/verify failed"
        );
    }
}

#[cfg(test)]
mod kat {
    //! FIPS 204 Known Answer Tests
    //!
    //! These tests will verify our implementation against official NIST vectors.

    /// KAT test for ML-DSA-44 key generation
    #[test]
    #[should_panic]
    fn test_ml_dsa_44_keygen_kat() {
        // TODO: Add NIST FIPS 204 test vectors
        panic!("KAT vectors not yet added");

        // Future implementation:
        // let seed = hex!("...");
        // let expected_pk = hex!("...");
        // let expected_sk = hex!("...");
        // let (pk, sk) = MlDsa44::generate_from_seed(&seed);
        // assert_eq!(pk.to_bytes(), expected_pk);
        // assert_eq!(sk.to_bytes(), expected_sk);
    }

    /// KAT test for ML-DSA-65 signing
    #[test]
    #[should_panic]
    fn test_ml_dsa_65_sign_kat() {
        // TODO: Add NIST FIPS 204 test vectors
        panic!("KAT vectors not yet added");
    }

    /// KAT test for ML-DSA-87 verification
    #[test]
    #[should_panic]
    fn test_ml_dsa_87_verify_kat() {
        // TODO: Add NIST FIPS 204 test vectors
        panic!("KAT vectors not yet added");
    }
}

#[cfg(test)]
mod ntt_kat {
    //! NTT Known Answer Tests
    //!
    //! Verify NTT implementation against known values.

    use crate::ml_dsa::ntt::{ntt, inv_ntt};
    use crate::ml_dsa::params::N;

    /// Test NTT with known input/output
    #[test]
    #[should_panic]
    fn test_ntt_known_answer() {
        // TODO: Add known NTT test vectors
        panic!("NTT test vectors not yet added");

        // Future implementation:
        // let input = [/* 256 coefficients */];
        // let expected_output = [/* 256 NTT coefficients */];
        // let mut coeffs = input;
        // ntt(&mut coeffs);
        // assert_eq!(coeffs, expected_output);
    }

    /// Test inverse NTT with known input/output
    #[test]
    #[should_panic]
    fn test_inv_ntt_known_answer() {
        // TODO: Add known inverse NTT test vectors
        panic!("Inverse NTT test vectors not yet added");
    }
}
