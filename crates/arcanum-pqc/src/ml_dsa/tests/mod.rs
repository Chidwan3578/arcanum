//! Tests for ML-DSA implementation
//!
//! Organized into:
//! - Unit tests (in each module)
//! - Integration tests (sign/verify roundtrip)
//! - KAT tests (FIPS 204 test vectors)

#[cfg(test)]
mod integration {
    use crate::ml_dsa::params::{Params44, Params65, Params87};

    /// Test that ML-DSA-44 sign/verify roundtrip works
    #[test]
    #[should_panic]
    fn test_ml_dsa_44_sign_verify_roundtrip() {
        // TODO: Will fail until full implementation is complete
        panic!("ML-DSA-44 not yet implemented");

        // Future implementation:
        // let (sk, vk) = MlDsa44::generate_keypair();
        // let message = b"test message";
        // let sig = MlDsa44::sign(&sk, message);
        // assert!(MlDsa44::verify(&vk, message, &sig).is_ok());
    }

    /// Test that ML-DSA-65 sign/verify roundtrip works
    #[test]
    #[should_panic]
    fn test_ml_dsa_65_sign_verify_roundtrip() {
        // TODO: Will fail until full implementation is complete
        panic!("ML-DSA-65 not yet implemented");
    }

    /// Test that ML-DSA-87 sign/verify roundtrip works
    #[test]
    #[should_panic]
    fn test_ml_dsa_87_sign_verify_roundtrip() {
        // TODO: Will fail until full implementation is complete
        panic!("ML-DSA-87 not yet implemented");
    }

    /// Test that wrong message fails verification
    #[test]
    #[should_panic]
    fn test_wrong_message_fails() {
        panic!("ML-DSA not yet implemented");

        // Future implementation:
        // let (sk, vk) = MlDsa65::generate_keypair();
        // let sig = MlDsa65::sign(&sk, b"message 1");
        // assert!(MlDsa65::verify(&vk, b"message 2", &sig).is_err());
    }

    /// Test that wrong key fails verification
    #[test]
    #[should_panic]
    fn test_wrong_key_fails() {
        panic!("ML-DSA not yet implemented");

        // Future implementation:
        // let (sk1, _) = MlDsa65::generate_keypair();
        // let (_, vk2) = MlDsa65::generate_keypair();
        // let sig = MlDsa65::sign(&sk1, b"test");
        // assert!(MlDsa65::verify(&vk2, b"test", &sig).is_err());
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
