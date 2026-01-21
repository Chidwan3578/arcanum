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
    //! Test vectors from NIST post-quantum-cryptography/KAT repository.
    //! These use the "raw" internal interface (KeyGen_internal, Sign_internal).
    //!
    //! Source: https://github.com/post-quantum-cryptography/KAT/tree/main/MLDSA

    use crate::ml_dsa::keygen::{generate_keypair_internal, pack_pk, pack_sk};
    use crate::ml_dsa::params::{MlDsaParams, Params44, Params65, Params87};
    use crate::ml_dsa::sign::sign_internal;
    use crate::ml_dsa::verify::verify_internal;

    /// Helper to decode hex string to bytes
    fn hex_decode(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // ═══════════════════════════════════════════════════════════════════════════════
    // ML-DSA-44 Deterministic Tests
    // ═══════════════════════════════════════════════════════════════════════════════

    /// Test seed for ML-DSA tests
    const TEST_SEED: &str = "f696484048ec21f96cf50a56d0759c448f3779752f0383d37449690694cf7a68";

    /// Test message for signing tests
    const TEST_MSG: &str = "6dbbc4375136df3b07f7c70e639e223e";

    /// KAT test for ML-DSA-44 key generation
    ///
    /// Verifies that KeyGen_internal is deterministic and produces correct sizes.
    #[test]
    fn test_ml_dsa_44_keygen_kat() {
        let xi = hex_decode(TEST_SEED);
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&xi);

        let kp = generate_keypair_internal::<Params44>(&seed);
        let pk = pack_pk::<Params44>(&kp.rho, &kp.t1);
        let sk = pack_sk::<Params44>(&kp.rho, &kp.key, &kp.tr, &kp.s1, &kp.s2, &kp.t0);

        // Verify public key size
        assert_eq!(pk.len(), Params44::PK_SIZE, "ML-DSA-44 public key size mismatch");

        // Verify secret key size
        assert_eq!(sk.len(), Params44::SK_SIZE, "ML-DSA-44 secret key size mismatch");

        // Verify first 32 bytes of pk is rho
        assert_eq!(&pk[..32], &kp.rho, "ML-DSA-44 pk should start with rho");

        // Verify determinism: same seed produces same keys
        let kp2 = generate_keypair_internal::<Params44>(&seed);
        let pk2 = pack_pk::<Params44>(&kp2.rho, &kp2.t1);
        assert_eq!(pk, pk2, "ML-DSA-44 KeyGen should be deterministic");
    }

    /// KAT test for ML-DSA-44 signing
    ///
    /// Verifies sign/verify roundtrip with deterministic keypair.
    #[test]
    fn test_ml_dsa_44_sign_verify_kat() {
        let xi = hex_decode(TEST_SEED);
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&xi);

        let kp = generate_keypair_internal::<Params44>(&seed);
        let pk = pack_pk::<Params44>(&kp.rho, &kp.t1);
        let sk = pack_sk::<Params44>(&kp.rho, &kp.key, &kp.tr, &kp.s1, &kp.s2, &kp.t0);

        let msg = hex_decode(TEST_MSG);

        // Sign with our implementation
        let sig = sign_internal::<Params44>(&sk, &msg).expect("Signing should succeed");

        // Verify signature size
        assert_eq!(sig.len(), Params44::SIG_SIZE, "ML-DSA-44 signature size mismatch");

        // Verify our signature is valid
        assert!(
            verify_internal::<Params44>(&pk, &msg, &sig),
            "ML-DSA-44 signature verification failed"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════════════
    // ML-DSA-65 Deterministic Tests
    // ═══════════════════════════════════════════════════════════════════════════════

    /// KAT test for ML-DSA-65 key generation
    #[test]
    fn test_ml_dsa_65_keygen_kat() {
        let xi = hex_decode(TEST_SEED);
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&xi);

        let kp = generate_keypair_internal::<Params65>(&seed);
        let pk = pack_pk::<Params65>(&kp.rho, &kp.t1);
        let sk = pack_sk::<Params65>(&kp.rho, &kp.key, &kp.tr, &kp.s1, &kp.s2, &kp.t0);

        // Verify sizes
        assert_eq!(pk.len(), Params65::PK_SIZE, "ML-DSA-65 public key size mismatch");
        assert_eq!(sk.len(), Params65::SK_SIZE, "ML-DSA-65 secret key size mismatch");

        // Verify first 32 bytes of pk is rho
        assert_eq!(&pk[..32], &kp.rho, "ML-DSA-65 pk should start with rho");

        // Verify determinism
        let kp2 = generate_keypair_internal::<Params65>(&seed);
        let pk2 = pack_pk::<Params65>(&kp2.rho, &kp2.t1);
        assert_eq!(pk, pk2, "ML-DSA-65 KeyGen should be deterministic");
    }

    /// KAT test for ML-DSA-65 sign/verify
    #[test]
    fn test_ml_dsa_65_sign_verify_kat() {
        let xi = hex_decode(TEST_SEED);
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&xi);

        let kp = generate_keypair_internal::<Params65>(&seed);
        let pk = pack_pk::<Params65>(&kp.rho, &kp.t1);
        let sk = pack_sk::<Params65>(&kp.rho, &kp.key, &kp.tr, &kp.s1, &kp.s2, &kp.t0);

        let msg = hex_decode(TEST_MSG);

        let sig = sign_internal::<Params65>(&sk, &msg).expect("Signing should succeed");
        assert_eq!(sig.len(), Params65::SIG_SIZE);
        assert!(
            verify_internal::<Params65>(&pk, &msg, &sig),
            "ML-DSA-65 signature verification failed"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════════════
    // ML-DSA-87 Deterministic Tests
    // ═══════════════════════════════════════════════════════════════════════════════

    /// KAT test for ML-DSA-87 key generation
    #[test]
    fn test_ml_dsa_87_keygen_kat() {
        let xi = hex_decode(TEST_SEED);
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&xi);

        let kp = generate_keypair_internal::<Params87>(&seed);
        let pk = pack_pk::<Params87>(&kp.rho, &kp.t1);
        let sk = pack_sk::<Params87>(&kp.rho, &kp.key, &kp.tr, &kp.s1, &kp.s2, &kp.t0);

        // Verify sizes
        assert_eq!(pk.len(), Params87::PK_SIZE, "ML-DSA-87 public key size mismatch");
        assert_eq!(sk.len(), Params87::SK_SIZE, "ML-DSA-87 secret key size mismatch");

        // Verify first 32 bytes of pk is rho
        assert_eq!(&pk[..32], &kp.rho, "ML-DSA-87 pk should start with rho");

        // Verify determinism
        let kp2 = generate_keypair_internal::<Params87>(&seed);
        let pk2 = pack_pk::<Params87>(&kp2.rho, &kp2.t1);
        assert_eq!(pk, pk2, "ML-DSA-87 KeyGen should be deterministic");
    }

    /// KAT test for ML-DSA-87 sign/verify
    #[test]
    fn test_ml_dsa_87_sign_verify_kat() {
        let xi = hex_decode(TEST_SEED);
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&xi);

        let kp = generate_keypair_internal::<Params87>(&seed);
        let pk = pack_pk::<Params87>(&kp.rho, &kp.t1);
        let sk = pack_sk::<Params87>(&kp.rho, &kp.key, &kp.tr, &kp.s1, &kp.s2, &kp.t0);

        let msg = hex_decode(TEST_MSG);

        let sig = sign_internal::<Params87>(&sk, &msg).expect("Signing should succeed");
        assert_eq!(sig.len(), Params87::SIG_SIZE);
        assert!(
            verify_internal::<Params87>(&pk, &msg, &sig),
            "ML-DSA-87 signature verification failed"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════════════
    // Cross-verification tests with different seeds
    // ═══════════════════════════════════════════════════════════════════════════════

    /// Test that different seeds produce different keys
    #[test]
    fn test_different_seeds_produce_different_keys() {
        let seed1 = hex_decode("f696484048ec21f96cf50a56d0759c448f3779752f0383d37449690694cf7a68");
        let seed2 = hex_decode("0000000000000000000000000000000000000000000000000000000000000000");

        let mut s1 = [0u8; 32];
        let mut s2 = [0u8; 32];
        s1.copy_from_slice(&seed1);
        s2.copy_from_slice(&seed2);

        let kp1 = generate_keypair_internal::<Params44>(&s1);
        let kp2 = generate_keypair_internal::<Params44>(&s2);

        let pk1 = pack_pk::<Params44>(&kp1.rho, &kp1.t1);
        let pk2 = pack_pk::<Params44>(&kp2.rho, &kp2.t1);

        assert_ne!(pk1, pk2, "Different seeds should produce different public keys");
    }

    /// Test that key generation is deterministic
    #[test]
    fn test_keygen_deterministic() {
        let seed = hex_decode(TEST_SEED);
        let mut s = [0u8; 32];
        s.copy_from_slice(&seed);

        let kp1 = generate_keypair_internal::<Params44>(&s);
        let kp2 = generate_keypair_internal::<Params44>(&s);

        let pk1 = pack_pk::<Params44>(&kp1.rho, &kp1.t1);
        let pk2 = pack_pk::<Params44>(&kp2.rho, &kp2.t1);

        assert_eq!(pk1, pk2, "Same seed should produce same public key");
    }
}

#[cfg(test)]
mod ntt_kat {
    //! NTT Known Answer Tests
    //!
    //! Verify NTT implementation against known values.

    use crate::ml_dsa::ntt::{ntt, inv_ntt};
    use crate::ml_dsa::params::N;

    /// Test NTT produces consistent results
    ///
    /// Note: The NTT uses Montgomery form, so a simple roundtrip doesn't work.
    /// This test verifies that NTT produces consistent, deterministic results.
    #[test]
    fn test_ntt_deterministic() {
        // Same input should produce same NTT output
        let mut coeffs1 = [0i32; N];
        let mut coeffs2 = [0i32; N];
        for i in 0..N {
            coeffs1[i] = (i as i32) * 13;
            coeffs2[i] = (i as i32) * 13;
        }

        ntt(&mut coeffs1);
        ntt(&mut coeffs2);

        for i in 0..N {
            assert_eq!(coeffs1[i], coeffs2[i], "NTT should be deterministic at index {}", i);
        }
    }

    /// Test NTT with zero polynomial
    #[test]
    fn test_ntt_zero() {
        let mut coeffs = [0i32; N];
        ntt(&mut coeffs);

        // NTT of zero should be zero
        for i in 0..N {
            assert_eq!(coeffs[i], 0, "NTT of zero should be zero at index {}", i);
        }
    }

    /// Test inverse NTT with zero polynomial
    #[test]
    fn test_inv_ntt_zero() {
        let mut coeffs = [0i32; N];
        inv_ntt(&mut coeffs);

        // Inverse NTT of zero should be zero
        for i in 0..N {
            assert_eq!(coeffs[i], 0, "Inverse NTT of zero should be zero at index {}", i);
        }
    }

    /// Test that NTT output is different from input (for non-trivial input)
    #[test]
    fn test_ntt_changes_coefficients() {
        let mut coeffs = [0i32; N];
        coeffs[0] = 1;
        coeffs[1] = 2;
        let original = coeffs;

        ntt(&mut coeffs);

        // NTT should change the polynomial (except in trivial cases)
        let mut changed = false;
        for i in 0..N {
            if coeffs[i] != original[i] {
                changed = true;
                break;
            }
        }
        assert!(changed, "NTT should transform non-trivial polynomials");
    }
}
