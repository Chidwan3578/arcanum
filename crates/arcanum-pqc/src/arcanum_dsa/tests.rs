//! Agent-Optimized TDD Tests for Arcanum-DSA
//!
//! # Test Methodology
//!
//! These tests serve as **executable specifications**. An agent implementing
//! Arcanum-DSA should:
//! 1. Read these tests to understand requirements
//! 2. Implement until all tests pass
//! 3. Never modify tests to make implementation easier
//!
//! # Test Categories
//!
//! 1. **Parameter Invariants**: Mathematical properties that must hold
//! 2. **SIMD Constraints**: Batching requirements for optimization
//! 3. **Security Bounds**: Ensure security margins are maintained
//! 4. **Functional Tests**: Sign/verify correctness (when implemented)

use super::params::*;

// ═══════════════════════════════════════════════════════════════════════════════
// PARAMETER INVARIANT TESTS
// These define the mathematical contracts that parameters must satisfy
// ═══════════════════════════════════════════════════════════════════════════════

/// INVARIANT: L must be a multiple of 4 for SIMD batching
///
/// Rationale: 4-way Keccak processes 4 elements in parallel.
/// Non-multiple-of-4 values cause inefficient partial batches.
#[test]
fn invariant_l_is_multiple_of_4() {
    assert_eq!(
        Params44::L % 4,
        0,
        "Params44::L={} not divisible by 4",
        Params44::L
    );
    assert_eq!(
        Params65::L % 4,
        0,
        "Params65::L={} not divisible by 4",
        Params65::L
    );
    assert_eq!(
        Params87::L % 4,
        0,
        "Params87::L={} not divisible by 4",
        Params87::L
    );
}

/// INVARIANT: K×L must be a multiple of 4 for expand_a batching
///
/// Rationale: Matrix A has K×L elements, all sampled via 4-way Keccak.
#[test]
fn invariant_k_times_l_is_multiple_of_4() {
    assert_eq!(
        (Params44::K * Params44::L) % 4,
        0,
        "Params44: K×L={} not divisible by 4",
        Params44::K * Params44::L
    );
    assert_eq!(
        (Params65::K * Params65::L) % 4,
        0,
        "Params65: K×L={} not divisible by 4",
        Params65::K * Params65::L
    );
    assert_eq!(
        (Params87::K * Params87::L) % 4,
        0,
        "Params87: K×L={} not divisible by 4",
        Params87::K * Params87::L
    );
}

/// INVARIANT: Dimension must meet or exceed ML-DSA equivalent
///
/// Rationale: Security is proportional to lattice dimension.
/// We must not reduce security below the target level.
#[test]
fn invariant_dimension_meets_security_level() {
    assert!(
        Params44::DIMENSION >= Params44::ML_DSA_EQUIVALENT_DIM,
        "Params44: dimension {} < ML-DSA equivalent {}",
        Params44::DIMENSION,
        Params44::ML_DSA_EQUIVALENT_DIM
    );
    assert!(
        Params65::DIMENSION >= Params65::ML_DSA_EQUIVALENT_DIM,
        "Params65: dimension {} < ML-DSA equivalent {}",
        Params65::DIMENSION,
        Params65::ML_DSA_EQUIVALENT_DIM
    );
    assert!(
        Params87::DIMENSION >= Params87::ML_DSA_EQUIVALENT_DIM,
        "Params87: dimension {} < ML-DSA equivalent {}",
        Params87::DIMENSION,
        Params87::ML_DSA_EQUIVALENT_DIM
    );
}

/// INVARIANT: Beta equals Tau times Eta
///
/// Rationale: BETA is the rejection bound, defined as τ·η in the spec.
/// Incorrect BETA causes signature verification failures.
#[test]
fn invariant_beta_equals_tau_times_eta() {
    assert_eq!(
        Params44::BETA,
        (Params44::TAU * Params44::ETA) as u32,
        "Params44: BETA={} != TAU×ETA={}",
        Params44::BETA,
        Params44::TAU * Params44::ETA
    );
    assert_eq!(
        Params65::BETA,
        (Params65::TAU * Params65::ETA) as u32,
        "Params65: BETA={} != TAU×ETA={}",
        Params65::BETA,
        Params65::TAU * Params65::ETA
    );
    assert_eq!(
        Params87::BETA,
        (Params87::TAU * Params87::ETA) as u32,
        "Params87: BETA={} != TAU×ETA={}",
        Params87::BETA,
        Params87::TAU * Params87::ETA
    );
}

/// INVARIANT: Gamma1 must be a power of 2
///
/// Rationale: Sampling uses bit masking which requires power-of-2 bounds.
#[test]
fn invariant_gamma1_is_power_of_2() {
    assert!(
        Params44::GAMMA1.is_power_of_two(),
        "Params44::GAMMA1={} not power of 2",
        Params44::GAMMA1
    );
    assert!(
        Params65::GAMMA1.is_power_of_two(),
        "Params65::GAMMA1={} not power of 2",
        Params65::GAMMA1
    );
    assert!(
        Params87::GAMMA1.is_power_of_two(),
        "Params87::GAMMA1={} not power of 2",
        Params87::GAMMA1
    );
}

/// INVARIANT: Gamma2 divides (Q-1) evenly
///
/// Rationale: Rounding uses (Q-1)/gamma2 which must be an integer.
#[test]
fn invariant_gamma2_divides_q_minus_1() {
    assert_eq!(
        (Q as u32 - 1) % Params44::GAMMA2,
        0,
        "Params44: (Q-1) % GAMMA2 != 0"
    );
    assert_eq!(
        (Q as u32 - 1) % Params65::GAMMA2,
        0,
        "Params65: (Q-1) % GAMMA2 != 0"
    );
    assert_eq!(
        (Q as u32 - 1) % Params87::GAMMA2,
        0,
        "Params87: (Q-1) % GAMMA2 != 0"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// SIMD OPTIMIZATION TESTS
// These verify the SIMD batching properties that enable optimization
// ═══════════════════════════════════════════════════════════════════════════════

/// SIMD: Verify expand_mask batch efficiency
///
/// For each parameter set, compute:
/// - Number of full 4-way batches
/// - Number of leftover elements
///
/// Arcanum-DSA should have 0 leftovers.
#[test]
fn simd_expand_mask_has_no_leftover() {
    let leftovers_44 = Params44::L % 4;
    let leftovers_65 = Params65::L % 4;
    let leftovers_87 = Params87::L % 4;

    assert_eq!(
        leftovers_44, 0,
        "Params44: {} leftover elements in expand_mask",
        leftovers_44
    );
    assert_eq!(
        leftovers_65, 0,
        "Params65: {} leftover elements in expand_mask",
        leftovers_65
    );
    assert_eq!(
        leftovers_87, 0,
        "Params87: {} leftover elements in expand_mask",
        leftovers_87
    );
}

/// SIMD: Verify expand_a batch efficiency
///
/// Matrix A has K×L elements. Should be divisible by 4.
#[test]
fn simd_expand_a_has_no_leftover() {
    let total_44 = Params44::K * Params44::L;
    let total_65 = Params65::K * Params65::L;
    let total_87 = Params87::K * Params87::L;

    assert_eq!(
        total_44 % 4,
        0,
        "Params44: K×L={} has {} leftovers",
        total_44,
        total_44 % 4
    );
    assert_eq!(
        total_65 % 4,
        0,
        "Params65: K×L={} has {} leftovers",
        total_65,
        total_65 % 4
    );
    assert_eq!(
        total_87 % 4,
        0,
        "Params87: K×L={} has {} leftovers",
        total_87,
        total_87 % 4
    );
}

/// SIMD: Verify 8-way (AVX-512) potential
///
/// For future AVX-512 optimization, check if L is also divisible by 8.
/// Note: Params65 uses L=4 for performance (smaller than ML-DSA-65's L=5)
#[test]
fn simd_avx512_potential() {
    // Params44: L=4, not divisible by 8 (but optimal for 4-way)
    // Params65: L=4, not divisible by 8 (but optimal for 4-way, reduced from ML-DSA's L=5)
    // Params87: L=8, divisible by 8 ✓

    // Params87 is AVX-512 ready
    let avx512_ready_87 = Params87::L % 8 == 0;
    assert!(
        avx512_ready_87,
        "Params87::L={} should be AVX-512 ready",
        Params87::L
    );

    // Params65 prioritizes minimal L over AVX-512 (L=4 < ML-DSA's L=5)
    assert_eq!(Params65::L, 4, "Params65 uses L=4 for performance");
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECURITY MARGIN TESTS
// These verify that security margins are positive and reasonable
// ═══════════════════════════════════════════════════════════════════════════════

/// SECURITY: Params44 must have non-negative security margin
#[test]
fn security_margin_params44_non_negative() {
    let margin = (Params44::DIMENSION * 100 / Params44::ML_DSA_EQUIVALENT_DIM) as i32 - 100;
    assert!(
        margin >= 0,
        "Params44: security margin {}% is negative",
        margin
    );
    println!("Params44 security margin: {}%", margin);
}

/// SECURITY: Params65 must have non-negative security margin
///
/// With K=7, L=4, dimension = 256×11 = 2816 (same as ML-DSA-65)
#[test]
fn security_margin_params65_non_negative() {
    let margin = (Params65::DIMENSION * 100 / Params65::ML_DSA_EQUIVALENT_DIM) as i32 - 100;
    assert!(
        margin >= 0,
        "Params65: security margin {}% is negative",
        margin
    );
    println!(
        "Params65 security margin: {}% (same dimension as ML-DSA-65)",
        margin
    );
}

/// SECURITY: Params87 must have positive security margin (we increased dimension)
#[test]
fn security_margin_params87_positive() {
    let margin = (Params87::DIMENSION * 100 / Params87::ML_DSA_EQUIVALENT_DIM) as i32 - 100;
    assert!(
        margin > 0,
        "Params87: expected positive security margin, got {}%",
        margin
    );
    println!("Params87 security margin: {}%", margin);
}

/// SECURITY: Dimensions should be strictly increasing across security levels
#[test]
fn security_dimensions_strictly_increasing() {
    assert!(
        Params65::DIMENSION > Params44::DIMENSION,
        "Params65 dimension {} should exceed Params44 dimension {}",
        Params65::DIMENSION,
        Params44::DIMENSION
    );
    assert!(
        Params87::DIMENSION > Params65::DIMENSION,
        "Params87 dimension {} should exceed Params65 dimension {}",
        Params87::DIMENSION,
        Params65::DIMENSION
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// SIZE IMPACT TESTS
// These document the size trade-offs of SIMD optimization
// ═══════════════════════════════════════════════════════════════════════════════

/// SIZE: Document public key size increase
///
/// Public key contains: ρ (32 bytes) + t₁ (K polynomials, each 320 bytes for 10-bit coeffs)
/// This test documents the size impact of parameter changes.
#[test]
fn size_document_public_key_impact() {
    // ML-DSA-65: K=6, pk = 32 + 6*320 = 1952 bytes
    // Arcanum-65: K=4, pk = 32 + 4*320 = 1312 bytes (smaller!)
    let ml_dsa_65_pk = 32 + 6 * 320;
    let arcanum_65_pk = 32 + Params65::K * 320;

    println!("ML-DSA-65 public key: {} bytes", ml_dsa_65_pk);
    println!("Arcanum-65 public key: {} bytes", arcanum_65_pk);
    println!(
        "Difference: {} bytes",
        arcanum_65_pk as i32 - ml_dsa_65_pk as i32
    );

    // ML-DSA-87: K=8, pk = 32 + 8*320 = 2592 bytes
    // Arcanum-87: K=8, pk = 32 + 8*320 = 2592 bytes (same)
    let ml_dsa_87_pk = 32 + 8 * 320;
    let arcanum_87_pk = 32 + Params87::K * 320;

    println!("ML-DSA-87 public key: {} bytes", ml_dsa_87_pk);
    println!("Arcanum-87 public key: {} bytes", arcanum_87_pk);
}

/// SIZE: Document secret key size increase
///
/// Secret key contains: ρ, K, tr, s₁ (L polys), s₂ (K polys), t₀ (K polys)
#[test]
fn size_document_secret_key_impact() {
    // Simplified calculation focusing on L impact
    // s₁ has L polynomials, each ~96 bytes for η=4

    // ML-DSA-65: L=5
    let ml_dsa_65_s1_size = 5 * 96;
    let arcanum_65_s1_size = Params65::L * 96;

    println!("ML-DSA-65 s₁ size: {} bytes", ml_dsa_65_s1_size);
    println!("Arcanum-65 s₁ size: {} bytes", arcanum_65_s1_size);
    println!(
        "s₁ increase: {} bytes",
        arcanum_65_s1_size as i32 - ml_dsa_65_s1_size as i32
    );

    // ML-DSA-87: L=7
    let ml_dsa_87_s1_size = 7 * 64; // η=2 uses 64 bytes
    let arcanum_87_s1_size = Params87::L * 64;

    println!("ML-DSA-87 s₁ size: {} bytes", ml_dsa_87_s1_size);
    println!("Arcanum-87 s₁ size: {} bytes", arcanum_87_s1_size);
}

/// SIZE: Document signature size increase
///
/// Signature contains: c̃ (LAMBDA bytes), z (L polynomials), hint h
#[test]
fn size_document_signature_impact() {
    // z has L polynomials, each needs ~576 or ~640 bytes depending on gamma1

    // For gamma1 = 2^19 (Params65/87): 20 bits per coeff, 640 bytes per poly
    let bytes_per_poly_gamma19 = 640;

    // ML-DSA-65: L=5
    let ml_dsa_65_z_size = 5 * bytes_per_poly_gamma19;
    let arcanum_65_z_size = Params65::L * bytes_per_poly_gamma19;

    println!("ML-DSA-65 z size: {} bytes", ml_dsa_65_z_size);
    println!("Arcanum-65 z size: {} bytes", arcanum_65_z_size);
    println!(
        "z increase: {} bytes",
        arcanum_65_z_size as i32 - ml_dsa_65_z_size as i32
    );

    // ML-DSA-87: L=7
    let ml_dsa_87_z_size = 7 * bytes_per_poly_gamma19;
    let arcanum_87_z_size = Params87::L * bytes_per_poly_gamma19;

    println!("ML-DSA-87 z size: {} bytes", ml_dsa_87_z_size);
    println!("Arcanum-87 z size: {} bytes", arcanum_87_z_size);
}

// ═══════════════════════════════════════════════════════════════════════════════
// FUNCTIONAL TESTS
// These test actual sign/verify using the MlDsaNative implementation
// ═══════════════════════════════════════════════════════════════════════════════

use super::api::{ArcanumDsa, ArcanumDsa44, ArcanumDsa65, ArcanumDsa87};

/// FUNCTIONAL: Sign and verify should roundtrip for Params44
#[test]
fn functional_sign_verify_roundtrip_44() {
    let (sk, vk) = ArcanumDsa44::generate_keypair();
    let msg = b"test message for Arcanum-DSA-44";
    let sig = ArcanumDsa44::sign(&sk, msg);
    assert!(
        ArcanumDsa44::verify(&vk, msg, &sig).is_ok(),
        "Arcanum-DSA-44 signature verification failed"
    );
}

/// FUNCTIONAL: Sign and verify should roundtrip for Params65
#[test]
fn functional_sign_verify_roundtrip_65() {
    let (sk, vk) = ArcanumDsa65::generate_keypair();
    let msg = b"test message for Arcanum-DSA-65 with SIMD-optimized L=8";
    let sig = ArcanumDsa65::sign(&sk, msg);
    assert!(
        ArcanumDsa65::verify(&vk, msg, &sig).is_ok(),
        "Arcanum-DSA-65 signature verification failed"
    );
}

/// FUNCTIONAL: Sign and verify should roundtrip for Params87
#[test]
fn functional_sign_verify_roundtrip_87() {
    let (sk, vk) = ArcanumDsa87::generate_keypair();
    let msg = b"test message for Arcanum-DSA-87 with maximum security";
    let sig = ArcanumDsa87::sign(&sk, msg);
    assert!(
        ArcanumDsa87::verify(&vk, msg, &sig).is_ok(),
        "Arcanum-DSA-87 signature verification failed"
    );
}

/// FUNCTIONAL: Invalid signature should fail verification
#[test]
fn functional_invalid_signature_rejected() {
    let (sk, vk) = ArcanumDsa65::generate_keypair();
    let sig = ArcanumDsa65::sign(&sk, b"message A");

    // Verify with different message should fail
    let result = ArcanumDsa65::verify(&vk, b"message B", &sig);
    assert!(
        result.is_err(),
        "Verification should fail for wrong message"
    );
}

/// FUNCTIONAL: Wrong key should fail verification
#[test]
fn functional_wrong_key_rejected() {
    let (sk1, _vk1) = ArcanumDsa65::generate_keypair();
    let (_sk2, vk2) = ArcanumDsa65::generate_keypair();

    let msg = b"test message";
    let sig = ArcanumDsa65::sign(&sk1, msg);

    // Verify with wrong key should fail
    let result = ArcanumDsa65::verify(&vk2, msg, &sig);
    assert!(result.is_err(), "Verification should fail with wrong key");
}

/// FUNCTIONAL: Empty message should work
#[test]
fn functional_empty_message() {
    let (sk, vk) = ArcanumDsa44::generate_keypair();
    let msg = b"";
    let sig = ArcanumDsa44::sign(&sk, msg);
    assert!(
        ArcanumDsa44::verify(&vk, msg, &sig).is_ok(),
        "Empty message signature verification failed"
    );
}

/// FUNCTIONAL: Large message should work
#[test]
fn functional_large_message() {
    let (sk, vk) = ArcanumDsa87::generate_keypair();
    let msg = vec![0x42u8; 10000]; // 10KB message
    let sig = ArcanumDsa87::sign(&sk, &msg);
    assert!(
        ArcanumDsa87::verify(&vk, &msg, &sig).is_ok(),
        "Large message signature verification failed"
    );
}

/// FUNCTIONAL: Key sizes match parameter specifications
#[test]
fn functional_key_sizes_match_params() {
    use super::api::{sizes_44, sizes_65, sizes_87};

    // Params44 (identical to ML-DSA-44)
    let (sk44, vk44) = ArcanumDsa44::generate_keypair();
    assert_eq!(sk44.to_bytes().len(), sizes_44::SK_SIZE);
    assert_eq!(vk44.to_bytes().len(), sizes_44::PK_SIZE);

    // Params65 (SIMD-optimized)
    let (sk65, vk65) = ArcanumDsa65::generate_keypair();
    assert_eq!(sk65.to_bytes().len(), sizes_65::SK_SIZE);
    assert_eq!(vk65.to_bytes().len(), sizes_65::PK_SIZE);

    // Params87 (SIMD-optimized)
    let (sk87, vk87) = ArcanumDsa87::generate_keypair();
    assert_eq!(sk87.to_bytes().len(), sizes_87::SK_SIZE);
    assert_eq!(vk87.to_bytes().len(), sizes_87::PK_SIZE);
}

/// FUNCTIONAL: Signature sizes match parameter specifications
#[test]
fn functional_signature_sizes_match_params() {
    use super::api::{sizes_44, sizes_65, sizes_87};

    let msg = b"size test";

    let (sk44, _) = ArcanumDsa44::generate_keypair();
    let sig44 = ArcanumDsa44::sign(&sk44, msg);
    assert_eq!(sig44.to_bytes().len(), sizes_44::SIG_SIZE);

    let (sk65, _) = ArcanumDsa65::generate_keypair();
    let sig65 = ArcanumDsa65::sign(&sk65, msg);
    assert_eq!(sig65.to_bytes().len(), sizes_65::SIG_SIZE);

    let (sk87, _) = ArcanumDsa87::generate_keypair();
    let sig87 = ArcanumDsa87::sign(&sk87, msg);
    assert_eq!(sig87.to_bytes().len(), sizes_87::SIG_SIZE);
}

/// BENCHMARK: Comprehensive sign performance comparison
#[test]
#[ignore = "Benchmark - run manually with: cargo test --release benchmark"]
fn benchmark_sign_performance() {
    use crate::ml_dsa::{MlDsa, MlDsa44, MlDsa65, MlDsa87};
    use std::time::Instant;

    const ITERATIONS: u32 = 1000;
    const WARMUP: u32 = 100;

    fn bench_sign<F: Fn()>(name: &str, iterations: u32, warmup: u32, f: F) -> std::time::Duration {
        // Warmup
        for _ in 0..warmup {
            f();
        }
        // Timed run
        let start = Instant::now();
        for _ in 0..iterations {
            f();
        }
        let elapsed = start.elapsed();
        let avg = elapsed / iterations;
        println!("{}: {:?} avg over {} iterations", name, avg, iterations);
        avg
    }

    println!("\n╔════════════════════════════════════════════════════════════╗");
    println!(
        "║          SIGN PERFORMANCE BENCHMARK ({} iterations)       ║",
        ITERATIONS
    );
    println!("╚════════════════════════════════════════════════════════════╝\n");

    // Pre-generate keys to isolate sign performance
    let (ml_sk44, _) = MlDsa44::generate_keypair();
    let (ml_sk65, _) = MlDsa65::generate_keypair();
    let (ml_sk87, _) = MlDsa87::generate_keypair();
    let (ar_sk44, _) = ArcanumDsa44::generate_keypair();
    let (ar_sk65, _) = ArcanumDsa65::generate_keypair();
    let (ar_sk87, _) = ArcanumDsa87::generate_keypair();

    let msg = b"benchmark message for sign performance testing";

    println!("─── Level 2 (L=4 for both) ───");
    let ml44 = bench_sign("ML-DSA-44 sign", ITERATIONS, WARMUP, || {
        let _ = MlDsa44::sign(&ml_sk44, msg);
    });
    let ar44 = bench_sign("Arcanum-44 sign", ITERATIONS, WARMUP, || {
        let _ = ArcanumDsa44::sign(&ar_sk44, msg);
    });
    println!(
        "  Ratio: {:.2}x ({})\n",
        ar44.as_nanos() as f64 / ml44.as_nanos() as f64,
        if ar44 < ml44 {
            "Arcanum faster"
        } else {
            "ML-DSA faster"
        }
    );

    println!("─── Level 3 (ML-DSA K=6,L=5 vs Arcanum K=7,L=4 SIMD) ───");
    let ml65 = bench_sign("ML-DSA-65 sign", ITERATIONS, WARMUP, || {
        let _ = MlDsa65::sign(&ml_sk65, msg);
    });
    let ar65 = bench_sign("Arcanum-65 sign", ITERATIONS, WARMUP, || {
        let _ = ArcanumDsa65::sign(&ar_sk65, msg);
    });
    println!(
        "  Ratio: {:.2}x ({})\n",
        ar65.as_nanos() as f64 / ml65.as_nanos() as f64,
        if ar65 < ml65 {
            "Arcanum faster"
        } else {
            "ML-DSA faster"
        }
    );

    println!("─── Level 5 (ML-DSA L=7 scalar vs Arcanum L=8 SIMD) ───");
    let ml87 = bench_sign("ML-DSA-87 sign", ITERATIONS, WARMUP, || {
        let _ = MlDsa87::sign(&ml_sk87, msg);
    });
    let ar87 = bench_sign("Arcanum-87 sign", ITERATIONS, WARMUP, || {
        let _ = ArcanumDsa87::sign(&ar_sk87, msg);
    });
    println!(
        "  Ratio: {:.2}x ({})\n",
        ar87.as_nanos() as f64 / ml87.as_nanos() as f64,
        if ar87 < ml87 {
            "Arcanum faster"
        } else {
            "ML-DSA faster"
        }
    );
}
