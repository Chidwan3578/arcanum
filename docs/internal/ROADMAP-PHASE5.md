# Arcanum Phase 5: Research-Grade Cryptographic Framework

This roadmap implements advanced cryptographic primitives building toward the **HoloCrypt** unified framework. Work follows TDD methodology with quick wins interleaved to maintain momentum.

## Overview

| Week | Focus | Tracks | Quick Wins | Complex Tasks |
|------|-------|--------|------------|---------------|
| 1 | Foundations | A, B, D | 4 | 2 |
| 2 | Core Primitives | B, C, D | 3 | 3 |
| 3 | Advanced Protocols | A, B, E | 2 | 3 |
| 4 | Integration | C, F, H | 3 | 2 |
| 5 | HoloCrypt | H | 2 | 3 |
| 6 | Polish & Papers | All | 3 | 1 |

**Tracks:**
- **A**: Formal Verification
- **B**: Threshold Cryptography
- **C**: Post-Quantum Hybrids
- **D**: Zero-Knowledge Primitives
- **E**: Side-Channel Hardening
- **F**: Cryptographic Agility
- **H**: HoloCrypt (capstone)

---

## Week 1: Foundations

**Goal:** Establish testing infrastructure and core primitives

### Sprint 1.1: Constant-Time Testing Infrastructure (Quick Win - 2 hours)
**Track A: Formal Verification**

**TDD Cycle:**
```rust
// tests/timing_tests.rs - Write test first
#[test]
fn aes_gcm_encrypt_is_constant_time() {
    use dudect_bencher::{ctbench_main, BenchRng, Class};

    fn encryption_time(rng: &mut BenchRng, class: Class) -> Vec<u8> {
        let key = match class {
            Class::Left => [0x00u8; 32],  // All zeros
            Class::Right => [0xFFu8; 32], // All ones
        };
        let nonce = Aes256Gcm::generate_nonce();
        let plaintext = vec![0u8; 1024];

        Aes256Gcm::encrypt(&key, &nonce, &plaintext, None).unwrap()
    }

    // Statistical test: t-value should be < 4.5 (no timing leak)
    ctbench_main!(encryption_time);
}
```

**Implementation:**
```
crates/arcanum-verify/
├── Cargo.toml
├── src/
│   ├── lib.rs
│   ├── timing.rs      # dudect integration
│   └── reports.rs     # CI-friendly output
└── tests/
    └── timing_tests.rs
```

**Acceptance:** CI pipeline catches timing regressions

---

### Sprint 1.2: Pedersen Commitments (Quick Win - 3 hours)
**Track D: Zero-Knowledge**

**TDD Cycle:**
```rust
// crates/arcanum-zkp/src/pedersen.rs
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commitment_is_binding() {
        let value1 = Scalar::from(42u64);
        let value2 = Scalar::from(43u64);
        let blinding = Scalar::random(&mut OsRng);

        let commit1 = PedersenCommitment::commit(value1, blinding);
        let commit2 = PedersenCommitment::commit(value2, blinding);

        // Different values must produce different commitments
        assert_ne!(commit1.as_bytes(), commit2.as_bytes());
    }

    #[test]
    fn commitment_is_hiding() {
        let value = Scalar::from(42u64);
        let blinding1 = Scalar::random(&mut OsRng);
        let blinding2 = Scalar::random(&mut OsRng);

        let commit1 = PedersenCommitment::commit(value, blinding1);
        let commit2 = PedersenCommitment::commit(value, blinding2);

        // Same value with different blinding looks random
        assert_ne!(commit1.as_bytes(), commit2.as_bytes());
    }

    #[test]
    fn commitment_opens_correctly() {
        let value = Scalar::from(42u64);
        let blinding = Scalar::random(&mut OsRng);

        let commitment = PedersenCommitment::commit(value, blinding);
        let opening = PedersenOpening { value, blinding };

        assert!(commitment.verify(&opening));
    }

    #[test]
    fn commitments_are_homomorphic() {
        let v1 = Scalar::from(10u64);
        let v2 = Scalar::from(20u64);
        let b1 = Scalar::random(&mut OsRng);
        let b2 = Scalar::random(&mut OsRng);

        let c1 = PedersenCommitment::commit(v1, b1);
        let c2 = PedersenCommitment::commit(v2, b2);
        let c_sum = c1 + c2;

        // C(v1, b1) + C(v2, b2) = C(v1+v2, b1+b2)
        let expected = PedersenCommitment::commit(v1 + v2, b1 + b2);
        assert_eq!(c_sum.as_bytes(), expected.as_bytes());
    }
}
```

**Implementation:**
```
crates/arcanum-zkp/
├── Cargo.toml
├── src/
│   ├── lib.rs
│   ├── pedersen.rs    # Pedersen commitments
│   ├── generators.rs  # Curve generator points
│   └── errors.rs
└── tests/
    └── pedersen_tests.rs
```

**Acceptance:** All commitment properties verified

---

### Sprint 1.3: Shamir Secret Sharing (Complex - 4 hours)
**Track B: Threshold Cryptography**

**TDD Cycle:**
```rust
// crates/arcanum-threshold/src/shamir.rs
#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn split_and_reconstruct_roundtrip() {
        let secret = SecretBytes::random(32);
        let shares = ShamirSecretSharing::split(&secret, threshold: 3, total: 5).unwrap();

        assert_eq!(shares.len(), 5);

        // Any 3 shares can reconstruct
        let reconstructed = ShamirSecretSharing::reconstruct(&shares[0..3]).unwrap();
        assert_eq!(secret.expose(), reconstructed.expose());

        // Different 3 shares also work
        let reconstructed2 = ShamirSecretSharing::reconstruct(&shares[2..5]).unwrap();
        assert_eq!(secret.expose(), reconstructed2.expose());
    }

    #[test]
    fn fewer_than_threshold_fails() {
        let secret = SecretBytes::random(32);
        let shares = ShamirSecretSharing::split(&secret, threshold: 3, total: 5).unwrap();

        // Only 2 shares - should fail
        let result = ShamirSecretSharing::reconstruct(&shares[0..2]);
        assert!(result.is_err());
    }

    #[test]
    fn shares_reveal_nothing_individually() {
        let secret = SecretBytes::random(32);
        let shares = ShamirSecretSharing::split(&secret, threshold: 3, total: 5).unwrap();

        // Single share should look random, not correlated with secret
        for share in &shares {
            assert_ne!(share.data(), secret.expose());
        }
    }

    proptest! {
        #[test]
        fn prop_any_k_shares_reconstruct(
            secret in prop::collection::vec(any::<u8>(), 32),
            threshold in 2usize..10,
            extra in 0usize..5,
        ) {
            let total = threshold + extra;
            let secret = SecretBytes::from(secret);
            let shares = ShamirSecretSharing::split(&secret, threshold, total).unwrap();

            // Try all combinations of exactly k shares
            for combo in shares.iter().combinations(threshold) {
                let reconstructed = ShamirSecretSharing::reconstruct(&combo).unwrap();
                prop_assert_eq!(secret.expose(), reconstructed.expose());
            }
        }
    }
}
```

**Implementation:**
```
crates/arcanum-threshold/
├── Cargo.toml
├── src/
│   ├── lib.rs
│   ├── shamir.rs       # Core SSS over GF(2^256)
│   ├── polynomial.rs   # Polynomial arithmetic
│   ├── field.rs        # Finite field operations
│   └── errors.rs
└── tests/
    ├── shamir_tests.rs
    └── property_tests.rs
```

**Acceptance:** k-of-n reconstruction works for all valid combinations

---

### Sprint 1.4: Schnorr Proofs of Knowledge (Quick Win - 3 hours)
**Track D: Zero-Knowledge**

**TDD Cycle:**
```rust
// crates/arcanum-zkp/src/schnorr.rs
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prove_and_verify_discrete_log() {
        // Prover knows x such that Y = g^x
        let secret = Scalar::random(&mut OsRng);
        let public = RistrettoPoint::generator() * secret;

        // Generate proof without revealing secret
        let proof = SchnorrProof::prove(&secret, &public);

        // Verifier checks proof
        assert!(proof.verify(&public));
    }

    #[test]
    fn proof_fails_for_wrong_public_key() {
        let secret = Scalar::random(&mut OsRng);
        let public = RistrettoPoint::generator() * secret;
        let wrong_public = RistrettoPoint::generator() * Scalar::random(&mut OsRng);

        let proof = SchnorrProof::prove(&secret, &public);

        // Proof should fail for different public key
        assert!(!proof.verify(&wrong_public));
    }

    #[test]
    fn proof_is_non_interactive_fiat_shamir() {
        let secret = Scalar::random(&mut OsRng);
        let public = RistrettoPoint::generator() * secret;

        // Same inputs should produce same proof (deterministic)
        let proof1 = SchnorrProof::prove_deterministic(&secret, &public, b"context");
        let proof2 = SchnorrProof::prove_deterministic(&secret, &public, b"context");

        assert_eq!(proof1.challenge, proof2.challenge);
        assert_eq!(proof1.response, proof2.response);
    }

    #[test]
    fn batch_verification_faster_than_individual() {
        let proofs: Vec<_> = (0..100).map(|_| {
            let secret = Scalar::random(&mut OsRng);
            let public = RistrettoPoint::generator() * secret;
            (SchnorrProof::prove(&secret, &public), public)
        }).collect();

        // Batch verify
        let (proof_refs, public_refs): (Vec<_>, Vec<_>) = proofs.iter()
            .map(|(p, pk)| (p, pk))
            .unzip();

        assert!(SchnorrProof::batch_verify(&proof_refs, &public_refs));
    }
}
```

**Implementation:**
- `crates/arcanum-zkp/src/schnorr.rs`
- Fiat-Shamir transform for non-interactive proofs
- Batch verification optimization

**Acceptance:** ZK proof of discrete log knowledge

---

### Sprint 1.5: Verifiable Secret Sharing (Complex - 4 hours)
**Track B: Threshold Cryptography**

**TDD Cycle:**
```rust
// crates/arcanum-threshold/src/feldman.rs
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shares_are_verifiable() {
        let secret = Scalar::random(&mut OsRng);
        let (shares, commitments) = FeldmanVSS::split(&secret, threshold: 3, total: 5).unwrap();

        // Each share can be verified against public commitments
        for share in &shares {
            assert!(share.verify(&commitments));
        }
    }

    #[test]
    fn tampered_share_detected() {
        let secret = Scalar::random(&mut OsRng);
        let (mut shares, commitments) = FeldmanVSS::split(&secret, threshold: 3, total: 5).unwrap();

        // Tamper with a share
        shares[0].value = Scalar::random(&mut OsRng);

        // Verification should fail
        assert!(!shares[0].verify(&commitments));
    }

    #[test]
    fn commitments_hide_secret() {
        let secret1 = Scalar::random(&mut OsRng);
        let secret2 = Scalar::random(&mut OsRng);

        let (_, commitments1) = FeldmanVSS::split(&secret1, 3, 5).unwrap();
        let (_, commitments2) = FeldmanVSS::split(&secret2, 3, 5).unwrap();

        // Commitments don't reveal which secret was shared
        // (This is a statistical test in practice)
        assert_ne!(commitments1[0], commitments2[0]);
    }
}
```

**Implementation:**
- Feldman VSS with Pedersen commitments
- Complaint mechanism for dishonest dealers
- Integration with Shamir reconstruction

**Acceptance:** Verifiable shares, detectable tampering

---

### Sprint 1.6: Project Structure Setup (Quick Win - 1 hour)

**Create workspace structure:**
```
crates/
├── arcanum-zkp/           # Zero-knowledge proofs
│   ├── Cargo.toml
│   └── src/lib.rs
├── arcanum-threshold/     # Threshold cryptography
│   ├── Cargo.toml
│   └── src/lib.rs
├── arcanum-verify/        # Formal verification tooling
│   ├── Cargo.toml
│   └── src/lib.rs
├── arcanum-pqc/           # Post-quantum cryptography
│   ├── Cargo.toml
│   └── src/lib.rs
├── arcanum-agile/         # Cryptographic agility
│   ├── Cargo.toml
│   └── src/lib.rs
└── arcanum-holocrypt/     # HoloCrypt framework
    ├── Cargo.toml
    └── src/lib.rs
```

**Acceptance:** All crates compile, CI passes

---

## Week 2: Core Primitives

**Goal:** Build threshold signatures and PQC integration

### Sprint 2.1: ML-KEM Integration (Quick Win - 3 hours)
**Track C: Post-Quantum**

**TDD Cycle:**
```rust
// crates/arcanum-pqc/src/ml_kem.rs
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kem_encapsulate_decapsulate_roundtrip() {
        let (decapsulation_key, encapsulation_key) = MlKem768::generate_keypair();

        let (ciphertext, shared_secret_sender) = encapsulation_key.encapsulate();
        let shared_secret_receiver = decapsulation_key.decapsulate(&ciphertext).unwrap();

        assert_eq!(shared_secret_sender.as_bytes(), shared_secret_receiver.as_bytes());
    }

    #[test]
    fn different_keypairs_produce_different_secrets() {
        let (dk1, ek1) = MlKem768::generate_keypair();
        let (dk2, _ek2) = MlKem768::generate_keypair();

        let (ciphertext, _) = ek1.encapsulate();

        // Wrong decapsulation key should fail
        let result = dk2.decapsulate(&ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn ciphertext_is_correct_size() {
        let (_, ek) = MlKem768::generate_keypair();
        let (ciphertext, _) = ek.encapsulate();

        assert_eq!(ciphertext.len(), ML_KEM_768_CIPHERTEXT_SIZE);
    }

    #[test]
    fn shared_secret_is_256_bits() {
        let (dk, ek) = MlKem768::generate_keypair();
        let (ciphertext, shared_secret) = ek.encapsulate();

        assert_eq!(shared_secret.as_bytes().len(), 32);
    }
}
```

**Implementation:**
- Wrapper around `ml-kem` crate
- Key serialization/deserialization
- Integration with arcanum-core types

**Acceptance:** NIST ML-KEM-768 test vectors pass

---

### Sprint 2.2: Hybrid KEM (X25519 + ML-KEM) (Complex - 4 hours)
**Track C: Post-Quantum**

**TDD Cycle:**
```rust
// crates/arcanum-pqc/src/hybrid_kem.rs
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hybrid_kem_roundtrip() {
        let (dk, ek) = HybridKem::generate_keypair();

        let (ciphertext, shared_secret_sender) = ek.encapsulate();
        let shared_secret_receiver = dk.decapsulate(&ciphertext).unwrap();

        assert_eq!(shared_secret_sender.as_bytes(), shared_secret_receiver.as_bytes());
    }

    #[test]
    fn shared_secret_combines_both_kems() {
        // The shared secret should be derived from BOTH classical and PQC
        // If either is compromised alone, the secret is still safe

        let (dk, ek) = HybridKem::generate_keypair();
        let (ciphertext, shared_secret) = ek.encapsulate();

        // Extract classical and PQC components
        let classical_only = X25519::decapsulate(&dk.classical, &ciphertext.classical);
        let pqc_only = MlKem768::decapsulate(&dk.pqc, &ciphertext.pqc);

        // Combined secret should be different from either component
        assert_ne!(shared_secret.as_bytes(), classical_only.as_bytes());
        assert_ne!(shared_secret.as_bytes(), pqc_only.as_bytes());
    }

    #[test]
    fn hybrid_uses_hkdf_combination() {
        // Verify the combination follows the draft-irtf-cfrg-hybrid-kems approach
        let (dk, ek) = HybridKem::generate_keypair();
        let (ciphertext, shared_secret) = ek.encapsulate();

        let classical_ss = X25519::decapsulate(&dk.classical, &ciphertext.classical);
        let pqc_ss = MlKem768::decapsulate(&dk.pqc, &ciphertext.pqc);

        // Combined = HKDF(classical || pqc, salt=ciphertext, info="hybrid-kem")
        let expected = Hkdf::<Sha256>::derive(
            &[classical_ss.as_bytes(), pqc_ss.as_bytes()].concat(),
            ciphertext.as_bytes(),
            b"arcanum-hybrid-kem-v1",
            32,
        ).unwrap();

        assert_eq!(shared_secret.as_bytes(), &expected);
    }
}
```

**Implementation:**
```rust
pub struct HybridKem;

impl HybridKem {
    pub fn generate_keypair() -> (HybridDecapsulationKey, HybridEncapsulationKey) {
        let (x25519_secret, x25519_public) = X25519::generate_keypair();
        let (mlkem_dk, mlkem_ek) = MlKem768::generate_keypair();

        (
            HybridDecapsulationKey { classical: x25519_secret, pqc: mlkem_dk },
            HybridEncapsulationKey { classical: x25519_public, pqc: mlkem_ek },
        )
    }
}
```

**Acceptance:** Security = max(X25519, ML-KEM-768)

---

### Sprint 2.3: Range Proofs with Bulletproofs (Complex - 6 hours)
**Track D: Zero-Knowledge**

**TDD Cycle:**
```rust
// crates/arcanum-zkp/src/bulletproofs.rs
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn range_proof_valid_value() {
        let value = 42u64;
        let blinding = Scalar::random(&mut OsRng);

        let commitment = PedersenCommitment::commit_u64(value, blinding);
        let proof = RangeProof::prove(value, blinding, 64); // 64-bit range

        assert!(proof.verify(&commitment, 64));
    }

    #[test]
    fn range_proof_hides_value() {
        let value = 42u64;
        let blinding = Scalar::random(&mut OsRng);

        let proof = RangeProof::prove(value, blinding, 64);

        // Proof should not reveal the value
        // (verifier learns only that 0 <= value < 2^64)
        assert!(!proof.reveals_value());
    }

    #[test]
    fn range_proof_fails_for_out_of_range() {
        // This shouldn't be possible to construct, but test anyway
        let value = u64::MAX;
        let blinding = Scalar::random(&mut OsRng);

        let commitment = PedersenCommitment::commit_u64(value, blinding);

        // Trying to prove 8-bit range for a large value
        let result = RangeProof::prove_with_range(value, blinding, 0, 256);
        assert!(result.is_err());
    }

    #[test]
    fn aggregated_range_proofs() {
        let values = vec![10u64, 20, 30, 40];
        let blindings: Vec<_> = (0..4).map(|_| Scalar::random(&mut OsRng)).collect();

        let commitments: Vec<_> = values.iter().zip(&blindings)
            .map(|(v, b)| PedersenCommitment::commit_u64(*v, *b))
            .collect();

        // Aggregate proof is smaller than 4 individual proofs
        let agg_proof = RangeProof::prove_aggregated(&values, &blindings, 64);

        assert!(agg_proof.verify_aggregated(&commitments, 64));
        assert!(agg_proof.size() < 4 * RangeProof::single_proof_size(64));
    }
}
```

**Implementation:**
- Use `bulletproofs` crate as backend
- Wrap in Arcanum types
- Support aggregation

**Acceptance:** Confidential values with compact proofs

---

### Sprint 2.4: ML-DSA Integration (Quick Win - 3 hours)
**Track C: Post-Quantum**

**TDD Cycle:**
```rust
// crates/arcanum-pqc/src/ml_dsa.rs
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_roundtrip() {
        let (signing_key, verifying_key) = MlDsa65::generate_keypair();
        let message = b"test message";

        let signature = signing_key.sign(message);
        assert!(verifying_key.verify(message, &signature).is_ok());
    }

    #[test]
    fn wrong_message_fails_verification() {
        let (signing_key, verifying_key) = MlDsa65::generate_keypair();

        let signature = signing_key.sign(b"original message");
        assert!(verifying_key.verify(b"different message", &signature).is_err());
    }

    #[test]
    fn deterministic_signatures() {
        let (signing_key, _) = MlDsa65::generate_keypair();
        let message = b"test message";

        let sig1 = signing_key.sign_deterministic(message);
        let sig2 = signing_key.sign_deterministic(message);

        assert_eq!(sig1.as_bytes(), sig2.as_bytes());
    }
}
```

**Implementation:**
- Wrapper around `ml-dsa` crate
- FIPS 204 compliance
- Deterministic and hedged modes

**Acceptance:** NIST ML-DSA-65 test vectors pass

---

### Sprint 2.5: FROST Threshold Signatures - Setup (Complex - 6 hours)
**Track B: Threshold Cryptography**

**TDD Cycle:**
```rust
// crates/arcanum-threshold/src/frost/keygen.rs
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distributed_key_generation() {
        let participants = 5;
        let threshold = 3;

        // Simulate DKG ceremony
        let mut states: Vec<DkgState> = (0..participants)
            .map(|i| DkgState::new(i, threshold, participants))
            .collect();

        // Round 1: Each participant generates and broadcasts commitment
        let round1_msgs: Vec<_> = states.iter_mut()
            .map(|s| s.round1_generate())
            .collect();

        // Each participant receives all round 1 messages
        for state in &mut states {
            for msg in &round1_msgs {
                state.round1_receive(msg).unwrap();
            }
        }

        // Round 2: Each participant generates shares for others
        let round2_msgs: Vec<Vec<_>> = states.iter_mut()
            .map(|s| s.round2_generate())
            .collect();

        // Distribute shares (each participant gets their share from each other)
        for (i, state) in states.iter_mut().enumerate() {
            for (j, msgs) in round2_msgs.iter().enumerate() {
                if i != j {
                    state.round2_receive(&msgs[i]).unwrap();
                }
            }
        }

        // Finalize: Each participant computes their signing share
        let key_packages: Vec<_> = states.iter_mut()
            .map(|s| s.finalize().unwrap())
            .collect();

        // All participants should agree on the group public key
        let group_public_key = key_packages[0].group_public_key();
        for kp in &key_packages {
            assert_eq!(kp.group_public_key(), group_public_key);
        }
    }

    #[test]
    fn dkg_detects_dishonest_participant() {
        // Test that invalid commitments/shares are detected
        let mut states: Vec<DkgState> = (0..5)
            .map(|i| DkgState::new(i, 3, 5))
            .collect();

        let mut round1_msgs: Vec<_> = states.iter_mut()
            .map(|s| s.round1_generate())
            .collect();

        // Participant 2 sends a bad commitment
        round1_msgs[2].commitment = RistrettoPoint::random(&mut OsRng);

        // Others should detect this in round 2
        for state in &mut states {
            for msg in &round1_msgs {
                let _ = state.round1_receive(msg); // May fail for bad msg
            }
        }

        // Complaint mechanism should identify participant 2
        let complaints: Vec<_> = states.iter()
            .flat_map(|s| s.get_complaints())
            .collect();

        assert!(complaints.iter().any(|c| c.accused == 2));
    }
}
```

**Implementation:**
- FROST DKG protocol (RFC draft)
- Ed25519 and secp256k1 variants
- Complaint/blame mechanism

**Acceptance:** Distributed key generation with malicious detection

---

### Sprint 2.6: Composite Signatures (Quick Win - 2 hours)
**Track C: Post-Quantum**

**TDD Cycle:**
```rust
// crates/arcanum-pqc/src/composite.rs
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn composite_signature_roundtrip() {
        let (signing_key, verifying_key) = CompositeSignature::generate_keypair();
        let message = b"test message";

        let signature = signing_key.sign(message);
        assert!(verifying_key.verify(message, &signature).is_ok());
    }

    #[test]
    fn composite_contains_both_signatures() {
        let (signing_key, _) = CompositeSignature::generate_keypair();
        let message = b"test message";

        let signature = signing_key.sign(message);

        // Should contain both Ed25519 and ML-DSA-65 signatures
        assert!(signature.classical.len() == 64); // Ed25519
        assert!(signature.pqc.len() == ML_DSA_65_SIGNATURE_SIZE);
    }

    #[test]
    fn verification_requires_both_valid() {
        let (signing_key, verifying_key) = CompositeSignature::generate_keypair();
        let message = b"test message";

        let mut signature = signing_key.sign(message);

        // Corrupt classical signature
        signature.classical[0] ^= 0xFF;

        // Should fail even though PQC part is valid
        assert!(verifying_key.verify(message, &signature).is_err());
    }
}
```

**Implementation:**
- Ed25519 + ML-DSA-65 composite
- Both must verify for success
- Serialization format

**Acceptance:** Hybrid signature with dual security

---

## Week 3: Advanced Protocols

**Goal:** Complete threshold signing and side-channel hardening

### Sprint 3.1: FROST Signing Protocol (Complex - 8 hours)
**Track B: Threshold Cryptography**

**TDD Cycle:**
```rust
// crates/arcanum-threshold/src/frost/signing.rs
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn threshold_signing_3_of_5() {
        // Setup: Run DKG first
        let key_packages = setup_frost_keys(threshold: 3, total: 5);
        let group_public_key = key_packages[0].group_public_key();

        let message = b"transaction to sign";

        // Select 3 signers (indices 0, 2, 4)
        let signer_indices = [0, 2, 4];

        // Round 1: Generate nonce commitments
        let mut signers: Vec<_> = signer_indices.iter()
            .map(|&i| FrostSigner::new(&key_packages[i]))
            .collect();

        let commitments: Vec<_> = signers.iter_mut()
            .map(|s| s.round1_commit())
            .collect();

        // Each signer receives all commitments
        for signer in &mut signers {
            for commit in &commitments {
                signer.receive_commitment(commit).unwrap();
            }
        }

        // Round 2: Generate signature shares
        let signature_shares: Vec<_> = signers.iter_mut()
            .map(|s| s.round2_sign(message))
            .collect();

        // Aggregate signature shares
        let signature = FrostSigner::aggregate(&signature_shares, &commitments, message).unwrap();

        // Verify with standard Ed25519 verification
        assert!(Ed25519VerifyingKey::from(group_public_key).verify(message, &signature).is_ok());
    }

    #[test]
    fn signing_with_different_subsets() {
        let key_packages = setup_frost_keys(3, 5);
        let group_public_key = key_packages[0].group_public_key();
        let message = b"test message";

        // Different subsets should produce valid signatures
        let subsets = [[0,1,2], [0,2,4], [1,3,4], [0,1,4]];

        for subset in &subsets {
            let signature = frost_sign(&key_packages, subset, message);
            assert!(Ed25519VerifyingKey::from(group_public_key).verify(message, &signature).is_ok());
        }
    }

    #[test]
    fn partial_signature_not_valid_alone() {
        let key_packages = setup_frost_keys(3, 5);
        let message = b"test message";

        // Single signer's share should not be a valid signature
        let mut signer = FrostSigner::new(&key_packages[0]);
        let _commit = signer.round1_commit();
        // Can't complete signing alone
    }
}
```

**Implementation:**
- 2-round FROST protocol
- Compatible with standard Ed25519 verification
- secp256k1 variant for Bitcoin

**Acceptance:** k-of-n threshold signatures, standard verification

---

### Sprint 3.2: Dudect Timing Test Suite (Quick Win - 3 hours)
**Track E: Side-Channel Hardening**

**TDD Cycle:**
```rust
// crates/arcanum-verify/tests/timing_comprehensive.rs
use dudect_bencher::{ctbench_main, BenchRng, Class};

fn aes_gcm_constant_time(rng: &mut BenchRng, class: Class) {
    let key = match class {
        Class::Left => [0x00u8; 32],
        Class::Right => [0xFFu8; 32],
    };
    // ... timing test
}

fn chacha20_constant_time(rng: &mut BenchRng, class: Class) {
    // ... timing test
}

fn x25519_constant_time(rng: &mut BenchRng, class: Class) {
    // ... timing test for DH
}

fn ed25519_sign_constant_time(rng: &mut BenchRng, class: Class) {
    // ... timing test for signing
}

fn hmac_verify_constant_time(rng: &mut BenchRng, class: Class) {
    // Test constant-time MAC verification
}

ctbench_main!(
    aes_gcm_constant_time,
    chacha20_constant_time,
    x25519_constant_time,
    ed25519_sign_constant_time,
    hmac_verify_constant_time
);
```

**Implementation:**
- Statistical timing tests for all crypto operations
- CI integration with failure thresholds
- HTML report generation

**Acceptance:** All operations pass t-test (t < 4.5)

---

### Sprint 3.3: Hacspec Specifications (Complex - 6 hours)
**Track A: Formal Verification**

**TDD Cycle:**
```rust
// specs/arcanum-hacspec/src/aes_gcm.rs
//! Hacspec specification for AES-256-GCM
//! This generates a reference implementation for differential testing

use hacspec_lib::*;

pub fn aes_gcm_encrypt(
    key: &ByteSeq,
    nonce: &ByteSeq,
    plaintext: &ByteSeq,
    aad: &ByteSeq,
) -> (ByteSeq, ByteSeq) {
    // Formal specification
    let cipher_key = aes_key_expansion(key);
    let counter = gcm_init_counter(nonce);

    let ciphertext = gcm_encrypt_blocks(&cipher_key, counter, plaintext);
    let tag = gcm_compute_tag(&cipher_key, nonce, aad, &ciphertext);

    (ciphertext, tag)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_matches_implementation() {
        let key = ByteSeq::from_hex("000102...");
        let nonce = ByteSeq::from_hex("...");
        let plaintext = ByteSeq::from_hex("...");
        let aad = ByteSeq::new(0);

        // Hacspec reference
        let (spec_ct, spec_tag) = aes_gcm_encrypt(&key, &nonce, &plaintext, &aad);

        // Production implementation
        let prod_result = arcanum_symmetric::Aes256Gcm::encrypt(
            key.to_vec(), nonce.to_vec(), plaintext.to_vec(), vec![]
        ).unwrap();

        assert_eq!(spec_ct.to_vec(), &prod_result[..prod_result.len()-16]);
        assert_eq!(spec_tag.to_vec(), &prod_result[prod_result.len()-16..]);
    }
}
```

**Implementation:**
```
specs/arcanum-hacspec/
├── Cargo.toml
├── src/
│   ├── lib.rs
│   ├── aes_gcm.rs
│   ├── chacha20_poly1305.rs
│   └── blake3.rs
└── tests/
    └── differential_tests.rs
```

**Acceptance:** Formal specs match production code

---

### Sprint 3.4: Kani Model Checking (Quick Win - 2 hours)
**Track A: Formal Verification**

**TDD Cycle:**
```rust
// crates/arcanum-core/src/lib.rs
#[cfg(kani)]
mod kani_proofs {
    use super::*;

    #[kani::proof]
    fn secret_bytes_zeroized_on_drop() {
        let secret = SecretBytes::random(32);
        let ptr = secret.expose().as_ptr();
        let len = secret.expose().len();

        drop(secret);

        // Memory should be zeroed (Kani will verify this)
        for i in 0..len {
            unsafe {
                kani::assert(*ptr.add(i) == 0, "Memory not zeroized");
            }
        }
    }

    #[kani::proof]
    fn nonce_never_reused() {
        let mut tracker = NonceTracker::new(1000);

        let nonce1: [u8; 12] = kani::any();
        let nonce2: [u8; 12] = kani::any();

        kani::assume(nonce1 == nonce2);

        tracker.check_and_record(&nonce1).unwrap();
        let result = tracker.check_and_record(&nonce2);

        kani::assert(result.is_err(), "Nonce reuse not detected");
    }

    #[kani::proof]
    #[kani::unwind(33)]
    fn aes_key_length_always_valid() {
        let key = Aes256Gcm::generate_key();
        kani::assert(key.expose().len() == 32, "Invalid key length");
    }
}
```

**Implementation:**
- Kani proofs for memory safety
- CI integration with `cargo kani`
- Bounded model checking for critical paths

**Acceptance:** Kani verifies memory safety properties

---

### Sprint 3.5: Proactive Secret Sharing (Complex - 4 hours)
**Track B: Threshold Cryptography**

**TDD Cycle:**
```rust
// crates/arcanum-threshold/src/proactive.rs
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refresh_shares_without_changing_secret() {
        let secret = SecretBytes::random(32);
        let original_shares = ShamirSecretSharing::split(&secret, 3, 5).unwrap();

        // Refresh all shares
        let refreshed_shares = ProactiveRefresh::refresh(&original_shares, 3, 5).unwrap();

        // New shares should be different
        for (old, new) in original_shares.iter().zip(&refreshed_shares) {
            assert_ne!(old.data(), new.data());
        }

        // But reconstruct to same secret
        let reconstructed = ShamirSecretSharing::reconstruct(&refreshed_shares[0..3]).unwrap();
        assert_eq!(secret.expose(), reconstructed.expose());
    }

    #[test]
    fn old_shares_incompatible_with_new() {
        let secret = SecretBytes::random(32);
        let original_shares = ShamirSecretSharing::split(&secret, 3, 5).unwrap();
        let refreshed_shares = ProactiveRefresh::refresh(&original_shares, 3, 5).unwrap();

        // Mixing old and new shares should fail
        let mixed = vec![
            original_shares[0].clone(),
            original_shares[1].clone(),
            refreshed_shares[2].clone(),
        ];

        let result = ShamirSecretSharing::reconstruct(&mixed);
        // Either fails or returns wrong secret
        if let Ok(reconstructed) = result {
            assert_ne!(secret.expose(), reconstructed.expose());
        }
    }

    #[test]
    fn refresh_protocol_distributed() {
        // Test the actual refresh protocol between participants
        let key_packages = setup_frost_keys(3, 5);

        // Each participant generates refresh contribution
        let refresh_shares: Vec<_> = key_packages.iter()
            .map(|kp| ProactiveRefresh::generate_refresh_share(kp))
            .collect();

        // Each participant updates their share
        let new_packages: Vec<_> = key_packages.iter()
            .enumerate()
            .map(|(i, kp)| {
                let contributions: Vec<_> = refresh_shares.iter()
                    .map(|rs| &rs[i])
                    .collect();
                kp.apply_refresh(&contributions)
            })
            .collect();

        // Group public key unchanged
        assert_eq!(
            key_packages[0].group_public_key(),
            new_packages[0].group_public_key()
        );
    }
}
```

**Implementation:**
- Zero-knowledge share refresh
- Public key remains constant
- Invalidates old shares

**Acceptance:** Key rotation without public key change

---

## Week 4: Integration

**Goal:** Versioned containers and HoloCrypt foundations

### Sprint 4.1: Algorithm Registry (Quick Win - 2 hours)
**Track F: Cryptographic Agility**

**TDD Cycle:**
```rust
// crates/arcanum-agile/src/registry.rs
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn algorithm_lookup() {
        let aes = AlgorithmRegistry::get(AlgorithmId::Aes256Gcm).unwrap();

        assert_eq!(aes.name(), "AES-256-GCM");
        assert_eq!(aes.key_size(), 32);
        assert_eq!(aes.nonce_size(), 12);
        assert_eq!(aes.security_level(), SecurityLevel::Bits256);
    }

    #[test]
    fn deprecated_algorithms_flagged() {
        let des = AlgorithmRegistry::get(AlgorithmId::TripleDes);

        assert!(des.is_some());
        assert!(des.unwrap().is_deprecated());
        assert_eq!(des.unwrap().deprecation_reason(), Some("Insufficient security margin"));
    }

    #[test]
    fn pqc_algorithms_registered() {
        let mlkem = AlgorithmRegistry::get(AlgorithmId::MlKem768).unwrap();

        assert!(mlkem.is_post_quantum());
        assert!(!mlkem.is_deprecated());
    }
}
```

**Implementation:**
```rust
pub enum AlgorithmId {
    // Symmetric
    Aes256Gcm = 1,
    Aes128Gcm = 2,
    Aes256GcmSiv = 3,
    ChaCha20Poly1305 = 4,
    XChaCha20Poly1305 = 5,

    // Hash
    Sha256 = 16,
    Sha512 = 17,
    Blake3 = 18,

    // Asymmetric
    X25519 = 32,
    Ed25519 = 33,

    // PQC
    MlKem768 = 64,
    MlDsa65 = 65,

    // Hybrid
    HybridKem = 96,
    CompositeSignature = 97,

    // Deprecated
    TripleDes = 128,
    Sha1 = 129,
}
```

**Acceptance:** Central registry for algorithm metadata

---

### Sprint 4.2: Versioned Ciphertext Containers (Complex - 4 hours)
**Track F: Cryptographic Agility**

**TDD Cycle:**
```rust
// crates/arcanum-agile/src/container.rs
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn container_self_describing() {
        let plaintext = b"secret data";
        let key = Aes256Gcm::generate_key();

        let container = AgileCiphertext::encrypt(
            algorithm: AlgorithmId::Aes256Gcm,
            version: 1,
            key: &key,
            plaintext,
        ).unwrap();

        // Container knows its algorithm
        assert_eq!(container.algorithm(), AlgorithmId::Aes256Gcm);
        assert_eq!(container.version(), 1);
    }

    #[test]
    fn forward_compatible_parsing() {
        // Simulate a container from a future version
        let future_bytes = create_future_container_v2();

        let container = AgileCiphertext::parse(&future_bytes).unwrap();

        // Should parse header even if can't decrypt
        assert_eq!(container.version(), 2);
        assert!(container.can_decrypt()); // If we support the algorithm
    }

    #[test]
    fn migration_recommendation() {
        let plaintext = b"secret data";
        let key = Aes256Gcm::generate_key();

        // Create with deprecated algorithm
        let container = AgileCiphertext::encrypt(
            algorithm: AlgorithmId::TripleDes, // Deprecated
            version: 1,
            key: &key,
            plaintext,
        ).unwrap();

        // Should recommend migration
        let recommendation = container.migration_recommendation();
        assert!(recommendation.is_some());
        assert_eq!(recommendation.unwrap().target, AlgorithmId::Aes256Gcm);
    }
}
```

**Implementation:**
```rust
/// Self-describing encrypted container
pub struct AgileCiphertext {
    /// Magic bytes for identification
    magic: [u8; 4], // "ARCN"
    /// Container format version
    format_version: u8,
    /// Algorithm used
    algorithm: AlgorithmId,
    /// Algorithm-specific version
    alg_version: u8,
    /// Nonce/IV
    nonce: Vec<u8>,
    /// Encrypted data + tag
    ciphertext: Vec<u8>,
    /// Optional metadata (encrypted)
    metadata: Option<Vec<u8>>,
}
```

**Acceptance:** Self-describing, forward-compatible containers

---

### Sprint 4.3: Merkle Tree with Authenticated Chunks (Quick Win - 3 hours)
**Track H: HoloCrypt Foundation**

**TDD Cycle:**
```rust
// crates/arcanum-holocrypt/src/merkle.rs
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merkle_proof_verification() {
        let data = vec![b"chunk0", b"chunk1", b"chunk2", b"chunk3"];
        let tree = MerkleTree::from_leaves(&data);

        // Generate proof for chunk 2
        let proof = tree.proof(2);

        // Verify proof against root
        assert!(proof.verify(b"chunk2", tree.root()));
    }

    #[test]
    fn tampered_chunk_fails_verification() {
        let data = vec![b"chunk0", b"chunk1", b"chunk2", b"chunk3"];
        let tree = MerkleTree::from_leaves(&data);
        let proof = tree.proof(2);

        // Tampered chunk should fail
        assert!(!proof.verify(b"tampered", tree.root()));
    }

    #[test]
    fn encrypted_merkle_tree() {
        let data = vec![b"chunk0", b"chunk1", b"chunk2", b"chunk3"];
        let key = Aes256Gcm::generate_key();

        let tree = EncryptedMerkleTree::from_plaintexts(&data, &key);

        // Root commitment doesn't reveal data
        let root = tree.root();

        // Can decrypt individual chunks with proof
        let (chunk, proof) = tree.reveal(2, &key).unwrap();
        assert_eq!(chunk, b"chunk2");
        assert!(proof.verify_encrypted(tree.root()));
    }
}
```

**Implementation:**
- BLAKE3-based Merkle tree
- Chunk-level encryption
- Proof generation/verification

**Acceptance:** Efficient selective disclosure

---

### Sprint 4.4: BBS+ Signatures (Complex - 6 hours)
**Track D: Zero-Knowledge**

**TDD Cycle:**
```rust
// crates/arcanum-zkp/src/bbs.rs
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_message_vector() {
        let (signing_key, verifying_key) = BbsPlus::generate_keypair(5); // 5 message slots

        let messages = vec![
            b"name: Alice".to_vec(),
            b"age: 30".to_vec(),
            b"country: US".to_vec(),
            b"license: valid".to_vec(),
            b"issued: 2024".to_vec(),
        ];

        let signature = signing_key.sign(&messages);
        assert!(verifying_key.verify(&messages, &signature).is_ok());
    }

    #[test]
    fn selective_disclosure() {
        let (signing_key, verifying_key) = BbsPlus::generate_keypair(5);

        let messages = vec![
            b"name: Alice".to_vec(),
            b"age: 30".to_vec(),
            b"country: US".to_vec(),
            b"license: valid".to_vec(),
            b"issued: 2024".to_vec(),
        ];

        let signature = signing_key.sign(&messages);

        // Create proof revealing only indices 2 and 3
        let proof = BbsProof::derive(
            &signature,
            &messages,
            revealed_indices: &[2, 3],
        );

        // Verifier only sees country and license
        let revealed = vec![
            (2, b"country: US".to_vec()),
            (3, b"license: valid".to_vec()),
        ];

        assert!(proof.verify(&verifying_key, &revealed).is_ok());
    }

    #[test]
    fn unlinkable_presentations() {
        let (signing_key, verifying_key) = BbsPlus::generate_keypair(3);
        let messages = vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()];
        let signature = signing_key.sign(&messages);

        // Multiple proofs from same signature look unrelated
        let proof1 = BbsProof::derive(&signature, &messages, &[0]);
        let proof2 = BbsProof::derive(&signature, &messages, &[0]);

        // Different randomness = unlinkable
        assert_ne!(proof1.as_bytes(), proof2.as_bytes());

        // Both valid
        assert!(proof1.verify(&verifying_key, &[(0, b"a".to_vec())]).is_ok());
        assert!(proof2.verify(&verifying_key, &[(0, b"a".to_vec())]).is_ok());
    }
}
```

**Implementation:**
- BBS+ signature scheme
- Selective disclosure proofs
- Unlinkable presentations

**Acceptance:** Anonymous credentials with attribute revelation

---

### Sprint 4.5: Policy Engine (Quick Win - 2 hours)
**Track F: Cryptographic Agility**

**TDD Cycle:**
```rust
// crates/arcanum-agile/src/policy.rs
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enforce_minimum_security_level() {
        let policy = Policy::builder()
            .min_security_level(SecurityLevel::Bits128)
            .build();

        assert!(policy.allows(AlgorithmId::Aes256Gcm));
        assert!(policy.allows(AlgorithmId::Aes128Gcm));
        assert!(!policy.allows(AlgorithmId::TripleDes)); // Only 112-bit
    }

    #[test]
    fn require_post_quantum() {
        let policy = Policy::builder()
            .require_post_quantum(true)
            .build();

        assert!(!policy.allows(AlgorithmId::X25519));
        assert!(policy.allows(AlgorithmId::MlKem768));
        assert!(policy.allows(AlgorithmId::HybridKem)); // Hybrid counts
    }

    #[test]
    fn fips_compliance_profile() {
        let policy = Policy::fips_140_3();

        assert!(policy.allows(AlgorithmId::Aes256Gcm));
        assert!(policy.allows(AlgorithmId::Sha256));
        assert!(!policy.allows(AlgorithmId::ChaCha20Poly1305)); // Not FIPS
        assert!(!policy.allows(AlgorithmId::Blake3)); // Not FIPS
    }
}
```

**Implementation:**
- Declarative policy language
- Compliance profiles (FIPS, SOC2)
- Runtime enforcement

**Acceptance:** Configurable algorithm restrictions

---

## Week 5: HoloCrypt

**Goal:** Build the unified holocryptographic framework

### Sprint 5.1: HoloCrypt Core Structure (Complex - 6 hours)
**Track H: HoloCrypt**

**TDD Cycle:**
```rust
// crates/arcanum-holocrypt/src/lib.rs
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_and_unseal_roundtrip() {
        let data = TestRecord {
            name: "Alice".into(),
            balance: 1000,
            verified: true,
        };

        let (sealing_key, opening_key) = HoloCrypt::generate_keypair();

        let container = HoloCrypt::seal(&data, &sealing_key).unwrap();
        let recovered: TestRecord = container.unseal(&opening_key).unwrap();

        assert_eq!(data, recovered);
    }

    #[test]
    fn container_has_all_layers() {
        let data = b"test data";
        let (sealing_key, _) = HoloCrypt::generate_keypair();

        let container = HoloCrypt::seal(data, &sealing_key).unwrap();

        // Verify all components present
        assert!(container.ciphertext().len() > 0);
        assert!(container.commitment().len() == 32);
        assert!(container.merkle_root().len() == 32);
        assert!(container.validity_proof().is_some());
        assert!(container.signature().len() > 0);
    }

    #[test]
    fn verify_without_decrypting() {
        let data = b"test data";
        let (sealing_key, _) = HoloCrypt::generate_keypair();

        let container = HoloCrypt::seal(data, &sealing_key).unwrap();

        // Third party can verify structure without access to plaintext
        assert!(container.verify_structure().is_ok());
    }
}
```

**Implementation:**
```rust
pub struct HoloCrypt<T> {
    // Layer 1: Encryption
    ciphertext: AgileCiphertext,

    // Layer 2: Commitment
    commitment: PedersenCommitment,

    // Layer 3: Merkle structure
    merkle_root: [u8; 32],
    chunk_count: usize,

    // Layer 4: Zero-knowledge proof
    validity_proof: Option<BulletproofRangeProof>,

    // Layer 5: Signature
    signature: CompositeSignature,

    _phantom: PhantomData<T>,
}
```

**Acceptance:** All 5 cryptographic layers working together

---

### Sprint 5.2: Threshold Key Distribution (Complex - 4 hours)
**Track H: HoloCrypt**

**TDD Cycle:**
```rust
// crates/arcanum-holocrypt/src/threshold.rs
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_with_threshold_access() {
        let data = b"confidential data";

        let recipients = generate_recipients(5);
        let threshold = 3;

        let container = HoloCrypt::seal_threshold(
            data,
            &recipients,
            threshold,
        ).unwrap();

        // Any 3 recipients can unseal
        let shares = vec![
            recipients[0].derive_share(&container),
            recipients[2].derive_share(&container),
            recipients[4].derive_share(&container),
        ];

        let recovered = container.unseal_threshold(&shares).unwrap();
        assert_eq!(data, &recovered[..]);
    }

    #[test]
    fn two_shares_insufficient() {
        let data = b"confidential data";
        let recipients = generate_recipients(5);

        let container = HoloCrypt::seal_threshold(data, &recipients, 3).unwrap();

        let shares = vec![
            recipients[0].derive_share(&container),
            recipients[1].derive_share(&container),
        ];

        assert!(container.unseal_threshold(&shares).is_err());
    }
}
```

**Implementation:**
- FROST key shares embedded in container
- k-of-n access control
- Share refresh support

**Acceptance:** Distributed trust for HoloCrypt containers

---

### Sprint 5.3: Selective Disclosure (Quick Win - 3 hours)
**Track H: HoloCrypt**

**TDD Cycle:**
```rust
// crates/arcanum-holocrypt/src/disclosure.rs
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reveal_single_chunk() {
        let chunks = vec![b"chunk0", b"chunk1", b"chunk2", b"chunk3"];
        let (sealing_key, opening_key) = HoloCrypt::generate_keypair();

        let container = HoloCrypt::seal_chunks(&chunks, &sealing_key).unwrap();

        // Reveal only chunk 2
        let (chunk, proof) = container.reveal_chunk(2, &opening_key).unwrap();

        assert_eq!(chunk, b"chunk2");
        assert!(proof.verify(container.merkle_root()));
    }

    #[test]
    fn reveal_with_merkle_proof() {
        let chunks = vec![b"chunk0", b"chunk1", b"chunk2", b"chunk3"];
        let (sealing_key, opening_key) = HoloCrypt::generate_keypair();

        let container = HoloCrypt::seal_chunks(&chunks, &sealing_key).unwrap();
        let (chunk, proof) = container.reveal_chunk(2, &opening_key).unwrap();

        // Third party can verify chunk belongs to container
        // without seeing other chunks
        assert!(HoloCrypt::verify_chunk(&chunk, &proof, container.merkle_root()));
    }
}
```

**Implementation:**
- Chunk-level decryption
- Merkle inclusion proofs
- Privacy-preserving verification

**Acceptance:** Reveal minimum necessary data

---

### Sprint 5.4: Property Proofs (Complex - 5 hours)
**Track H: HoloCrypt**

**TDD Cycle:**
```rust
// crates/arcanum-holocrypt/src/properties.rs
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prove_value_in_range() {
        let record = FinancialRecord { balance: 5000 };
        let (sealing_key, opening_key) = HoloCrypt::generate_keypair();

        let container = HoloCrypt::seal(&record, &sealing_key).unwrap();

        // Prove balance is in range [1000, 10000] without revealing exact value
        let proof = container.prove_property(
            Property::InRange { field: "balance", min: 1000, max: 10000 },
            &opening_key,
        ).unwrap();

        // Verifier learns only that property holds
        assert!(proof.verify(container.commitment()).is_ok());
    }

    #[test]
    fn prove_field_equals() {
        let record = Person { name: "Alice".into(), age: 30 };
        let (sealing_key, opening_key) = HoloCrypt::generate_keypair();

        let container = HoloCrypt::seal(&record, &sealing_key).unwrap();

        // Prove name is "Alice" without revealing age
        let proof = container.prove_property(
            Property::Equals { field: "name", value: "Alice" },
            &opening_key,
        ).unwrap();

        assert!(proof.verify(container.commitment()).is_ok());
    }

    #[test]
    fn prove_hash_preimage() {
        let data = b"secret preimage";
        let expected_hash = Blake3::hash(data);
        let (sealing_key, opening_key) = HoloCrypt::generate_keypair();

        let container = HoloCrypt::seal(data, &sealing_key).unwrap();

        // Prove container holds preimage of known hash
        let proof = container.prove_property(
            Property::HashPreimage { hash: expected_hash },
            &opening_key,
        ).unwrap();

        assert!(proof.verify_preimage(&expected_hash).is_ok());
    }
}
```

**Implementation:**
- Bulletproof range proofs integration
- Schnorr equality proofs
- Hash preimage proofs

**Acceptance:** Prove properties without revealing data

---

### Sprint 5.5: PQC Envelope (Quick Win - 2 hours)
**Track H: HoloCrypt**

**TDD Cycle:**
```rust
// crates/arcanum-holocrypt/src/pqc_envelope.rs
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn container_survives_classical_break() {
        let data = b"long-term secret";

        // Use hybrid keys
        let (sealing_key, opening_key) = HoloCrypt::generate_hybrid_keypair();

        let container = HoloCrypt::seal(data, &sealing_key).unwrap();

        // Container uses both classical and PQC
        assert!(container.has_pqc_protection());
    }

    #[test]
    fn pqc_algorithms_used() {
        let (sealing_key, _) = HoloCrypt::generate_hybrid_keypair();

        assert_eq!(sealing_key.classical_algorithm(), AlgorithmId::X25519);
        assert_eq!(sealing_key.pqc_algorithm(), AlgorithmId::MlKem768);
    }
}
```

**Implementation:**
- Hybrid key encapsulation
- Composite signature for container
- Migration path metadata

**Acceptance:** Quantum-resistant container encryption

---

## Week 6: Polish & Papers

**Goal:** Documentation, benchmarks, and research outputs

### Sprint 6.1: Comprehensive Benchmarks (Quick Win - 3 hours)

```rust
// benches/holocrypt_benchmarks.rs
fn bench_seal_unseal(c: &mut Criterion) {
    let mut group = c.benchmark_group("HoloCrypt");

    for size in [1024, 4096, 65536, 1048576].iter() {
        let data = vec![0u8; *size];
        let (sk, ok) = HoloCrypt::generate_keypair();

        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_with_input(BenchmarkId::new("seal", size), size, |b, _| {
            b.iter(|| HoloCrypt::seal(&data, &sk))
        });

        let container = HoloCrypt::seal(&data, &sk).unwrap();
        group.bench_with_input(BenchmarkId::new("unseal", size), size, |b, _| {
            b.iter(|| container.unseal(&ok))
        });
    }

    group.finish();
}
```

**Acceptance:** Performance data for all operations

---

### Sprint 6.2: Security Documentation (Quick Win - 2 hours)

Document:
- Security model and threat analysis
- Composition security proofs
- Side-channel considerations
- Migration recommendations

---

### Sprint 6.3: API Reference (Quick Win - 2 hours)

- Rustdoc for all public APIs
- Examples in documentation
- Quick start guide

---

### Sprint 6.4: Research Paper Draft (Complex - 8 hours)

**Suggested Paper Structure:**

1. **Abstract**
2. **Introduction**
   - Motivation: Need for composable crypto primitives
   - Contributions
3. **Background**
   - Pedersen commitments, ZK proofs, threshold crypto
4. **HoloCrypt Design**
   - Layered architecture
   - Security properties
5. **Security Analysis**
   - Formal security model
   - Composition theorem
6. **Implementation**
   - Rust implementation details
   - Performance optimizations
7. **Evaluation**
   - Benchmarks
   - Comparison with alternatives
8. **Related Work**
9. **Conclusion**

---

## Summary

### Milestone Timeline

```
Week 1: Foundations
├── Sprint 1.1: CT testing infrastructure (2 hr) ✓
├── Sprint 1.2: Pedersen commitments (3 hr) ✓
├── Sprint 1.3: Shamir secret sharing (4 hr) ✓
├── Sprint 1.4: Schnorr proofs (3 hr) ✓
├── Sprint 1.5: Verifiable secret sharing (4 hr) ✓
└── Sprint 1.6: Project structure (1 hr) ✓

Week 2: Core Primitives
├── Sprint 2.1: ML-KEM integration (3 hr) ✓
├── Sprint 2.2: Hybrid KEM (4 hr) ✓
├── Sprint 2.3: Bulletproof range proofs (6 hr) ✓
├── Sprint 2.4: ML-DSA integration (3 hr) ✓
├── Sprint 2.5: FROST DKG (6 hr) ✓
└── Sprint 2.6: Composite signatures (2 hr) ✓

Week 3: Advanced Protocols
├── Sprint 3.1: FROST signing (8 hr) ✓
├── Sprint 3.2: Dudect timing tests (3 hr) ✓
├── Sprint 3.3: Hacspec specs (6 hr) ✓
├── Sprint 3.4: Kani model checking (2 hr) ✓
└── Sprint 3.5: Proactive refresh (4 hr) ✓

Week 4: Integration
├── Sprint 4.1: Algorithm registry (2 hr) ✓
├── Sprint 4.2: Versioned containers (4 hr) ✓
├── Sprint 4.3: Merkle tree (3 hr) ✓
├── Sprint 4.4: BBS+ signatures (6 hr) ✓
└── Sprint 4.5: Policy engine (2 hr) ✓

Week 5: HoloCrypt
├── Sprint 5.1: Core structure (6 hr) ✓
├── Sprint 5.2: Threshold distribution (4 hr) ✓
├── Sprint 5.3: Selective disclosure (3 hr) ✓
├── Sprint 5.4: Property proofs (5 hr) ✓
└── Sprint 5.5: PQC envelope (2 hr) ✓

Week 6: Polish
├── Sprint 6.1: Benchmarks (3 hr) ✓
├── Sprint 6.2: Security docs (2 hr) ✓
├── Sprint 6.3: API reference (2 hr) ✓
└── Sprint 6.4: Paper draft (8 hr) ✓
```

### Deliverables

| Crate | Purpose | Status |
|-------|---------|--------|
| `arcanum-zkp` | Zero-knowledge proofs | New |
| `arcanum-threshold` | Threshold cryptography | New |
| `arcanum-verify` | Formal verification | New |
| `arcanum-pqc` | Post-quantum crypto | New |
| `arcanum-agile` | Crypto agility | New |
| `arcanum-holocrypt` | Unified framework | New |

### Research Outputs

1. **Paper**: "HoloCrypt: Composable Cryptographic Data Structures"
2. **Formal specs**: Hacspec specifications for core primitives
3. **Proofs**: Kani model checking results
4. **Benchmarks**: Comprehensive performance analysis

---

*Phase 5 Roadmap created: 2025-12-23*
*Estimated effort: 6 weeks (~120 hours)*
