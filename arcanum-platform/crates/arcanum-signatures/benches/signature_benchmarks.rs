//! Benchmarks for digital signature operations.
//!
//! Run with: `cargo bench -p arcanum-signatures --all-features`

use criterion::{
    black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput,
};

#[cfg(feature = "ed25519")]
use arcanum_signatures::ed25519::{Ed25519SigningKey, Ed25519BatchVerifier};

#[cfg(feature = "ed25519")]
use arcanum_signatures::BatchVerifier;

#[cfg(feature = "ecdsa")]
use arcanum_signatures::ecdsa_impl::{P256SigningKey, P384SigningKey, Secp256k1SigningKey};

#[cfg(feature = "schnorr")]
use arcanum_signatures::schnorr::SchnorrSigningKey;

use arcanum_signatures::{SigningKey, VerifyingKey};

// Message sizes for benchmarking
const MESSAGE_SIZES: &[usize] = &[32, 256, 1024, 4096, 16384];

// ═══════════════════════════════════════════════════════════════════════════════
// ED25519 BENCHMARKS
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(feature = "ed25519")]
fn bench_ed25519_keygen(c: &mut Criterion) {
    c.bench_function("ed25519/keygen", |b| {
        b.iter(|| black_box(Ed25519SigningKey::generate()))
    });
}

#[cfg(feature = "ed25519")]
fn bench_ed25519_sign(c: &mut Criterion) {
    let signing_key = Ed25519SigningKey::generate();

    let mut group = c.benchmark_group("ed25519/sign");

    for size in MESSAGE_SIZES {
        let message = vec![0u8; *size];

        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| black_box(signing_key.sign(&message)))
        });
    }

    group.finish();
}

#[cfg(feature = "ed25519")]
fn bench_ed25519_verify(c: &mut Criterion) {
    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();

    let mut group = c.benchmark_group("ed25519/verify");

    for size in MESSAGE_SIZES {
        let message = vec![0u8; *size];
        let signature = signing_key.sign(&message);

        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| black_box(verifying_key.verify(&message, &signature)))
        });
    }

    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════════════
// ED25519 BATCH VERIFICATION BENCHMARKS
// ═══════════════════════════════════════════════════════════════════════════════

/// Batch sizes for batch verification benchmarks
const BATCH_SIZES: &[usize] = &[1, 4, 8, 16, 32, 64, 128];

/// Benchmark batch verification for different batch sizes
#[cfg(feature = "ed25519")]
fn bench_ed25519_batch_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("ed25519/batch_verify");

    for &batch_size in BATCH_SIZES {
        // Generate unique key pairs and signatures for each item in batch
        let items: Vec<_> = (0..batch_size)
            .map(|i| {
                let signing_key = Ed25519SigningKey::generate();
                let verifying_key = signing_key.verifying_key();
                let message = format!("message {}", i).into_bytes();
                let signature = signing_key.sign(&message);
                (verifying_key, message, signature)
            })
            .collect();

        // Build references for batch verify
        let batch_items: Vec<_> = items
            .iter()
            .map(|(vk, msg, sig)| (vk, msg.as_slice(), sig))
            .collect();

        group.throughput(Throughput::Elements(batch_size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(batch_size),
            &batch_items,
            |b, items| {
                b.iter(|| black_box(Ed25519BatchVerifier::verify_batch(items)))
            },
        );
    }

    group.finish();
}

/// Compare batch verification vs individual verification
#[cfg(feature = "ed25519")]
fn bench_ed25519_batch_vs_individual(c: &mut Criterion) {
    // Use a medium batch size for comparison
    const COMPARISON_BATCH_SIZE: usize = 32;

    let items: Vec<_> = (0..COMPARISON_BATCH_SIZE)
        .map(|i| {
            let signing_key = Ed25519SigningKey::generate();
            let verifying_key = signing_key.verifying_key();
            let message = format!("message {}", i).into_bytes();
            let signature = signing_key.sign(&message);
            (verifying_key, message, signature)
        })
        .collect();

    let batch_items: Vec<_> = items
        .iter()
        .map(|(vk, msg, sig)| (vk, msg.as_slice(), sig))
        .collect();

    let mut group = c.benchmark_group("ed25519/batch_comparison/32");
    group.throughput(Throughput::Elements(COMPARISON_BATCH_SIZE as u64));

    // Batch verification
    group.bench_function("batch", |b| {
        b.iter(|| black_box(Ed25519BatchVerifier::verify_batch(&batch_items)))
    });

    // Individual verification (for comparison)
    group.bench_function("individual", |b| {
        b.iter(|| {
            for (vk, msg, sig) in &items {
                black_box(vk.verify(msg, sig)).unwrap();
            }
        })
    });

    group.finish();
}

/// Benchmark batch verification with same signing key (common use case)
#[cfg(feature = "ed25519")]
fn bench_ed25519_batch_same_key(c: &mut Criterion) {
    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();

    let mut group = c.benchmark_group("ed25519/batch_same_key");

    for &batch_size in BATCH_SIZES {
        // All messages signed by same key
        let items: Vec<_> = (0..batch_size)
            .map(|i| {
                let message = format!("message {}", i).into_bytes();
                let signature = signing_key.sign(&message);
                (message, signature)
            })
            .collect();

        // Build references for batch verify (same verifying key for all)
        let batch_items: Vec<_> = items
            .iter()
            .map(|(msg, sig)| (&verifying_key, msg.as_slice(), sig))
            .collect();

        group.throughput(Throughput::Elements(batch_size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(batch_size),
            &batch_items,
            |b, items| {
                b.iter(|| black_box(Ed25519BatchVerifier::verify_batch(items)))
            },
        );
    }

    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════════════
// ECDSA P-256 BENCHMARKS
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(feature = "ecdsa")]
fn bench_p256_keygen(c: &mut Criterion) {
    c.bench_function("ecdsa_p256/keygen", |b| {
        b.iter(|| black_box(P256SigningKey::generate()))
    });
}

#[cfg(feature = "ecdsa")]
fn bench_p256_sign(c: &mut Criterion) {
    let signing_key = P256SigningKey::generate();

    let mut group = c.benchmark_group("ecdsa_p256/sign");

    for size in MESSAGE_SIZES {
        let message = vec![0u8; *size];

        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| black_box(signing_key.sign(&message)))
        });
    }

    group.finish();
}

#[cfg(feature = "ecdsa")]
fn bench_p256_verify(c: &mut Criterion) {
    let signing_key = P256SigningKey::generate();
    let verifying_key = signing_key.verifying_key();

    let mut group = c.benchmark_group("ecdsa_p256/verify");

    for size in MESSAGE_SIZES {
        let message = vec![0u8; *size];
        let signature = signing_key.sign(&message);

        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| black_box(verifying_key.verify(&message, &signature)))
        });
    }

    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════════════
// ECDSA P-384 BENCHMARKS
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(feature = "ecdsa")]
fn bench_p384_keygen(c: &mut Criterion) {
    c.bench_function("ecdsa_p384/keygen", |b| {
        b.iter(|| black_box(P384SigningKey::generate()))
    });
}

#[cfg(feature = "ecdsa")]
fn bench_p384_sign(c: &mut Criterion) {
    let signing_key = P384SigningKey::generate();
    let message = vec![0u8; 256];

    c.bench_function("ecdsa_p384/sign/256", |b| {
        b.iter(|| black_box(signing_key.sign(&message)))
    });
}

#[cfg(feature = "ecdsa")]
fn bench_p384_verify(c: &mut Criterion) {
    let signing_key = P384SigningKey::generate();
    let verifying_key = signing_key.verifying_key();
    let message = vec![0u8; 256];
    let signature = signing_key.sign(&message);

    c.bench_function("ecdsa_p384/verify/256", |b| {
        b.iter(|| black_box(verifying_key.verify(&message, &signature)))
    });
}

// ═══════════════════════════════════════════════════════════════════════════════
// ECDSA SECP256K1 BENCHMARKS
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(feature = "ecdsa")]
fn bench_secp256k1_keygen(c: &mut Criterion) {
    c.bench_function("ecdsa_secp256k1/keygen", |b| {
        b.iter(|| black_box(Secp256k1SigningKey::generate()))
    });
}

#[cfg(feature = "ecdsa")]
fn bench_secp256k1_sign(c: &mut Criterion) {
    let signing_key = Secp256k1SigningKey::generate();
    let message = vec![0u8; 256];

    c.bench_function("ecdsa_secp256k1/sign/256", |b| {
        b.iter(|| black_box(signing_key.sign(&message)))
    });
}

#[cfg(feature = "ecdsa")]
fn bench_secp256k1_verify(c: &mut Criterion) {
    let signing_key = Secp256k1SigningKey::generate();
    let verifying_key = signing_key.verifying_key();
    let message = vec![0u8; 256];
    let signature = signing_key.sign(&message);

    c.bench_function("ecdsa_secp256k1/verify/256", |b| {
        b.iter(|| black_box(verifying_key.verify(&message, &signature)))
    });
}

// ═══════════════════════════════════════════════════════════════════════════════
// SCHNORR BENCHMARKS
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(feature = "schnorr")]
fn bench_schnorr_keygen(c: &mut Criterion) {
    c.bench_function("schnorr/keygen", |b| {
        b.iter(|| black_box(SchnorrSigningKey::generate()))
    });
}

#[cfg(feature = "schnorr")]
fn bench_schnorr_sign(c: &mut Criterion) {
    let signing_key = SchnorrSigningKey::generate();
    let message = vec![0u8; 256];

    c.bench_function("schnorr/sign/256", |b| {
        b.iter(|| black_box(signing_key.sign(&message)))
    });
}

#[cfg(feature = "schnorr")]
fn bench_schnorr_verify(c: &mut Criterion) {
    let signing_key = SchnorrSigningKey::generate();
    let verifying_key = signing_key.verifying_key();
    let message = vec![0u8; 256];
    let signature = signing_key.sign(&message);

    c.bench_function("schnorr/verify/256", |b| {
        b.iter(|| black_box(verifying_key.verify(&message, &signature)))
    });
}

// ═══════════════════════════════════════════════════════════════════════════════
// ALGORITHM COMPARISON
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(all(feature = "ed25519", feature = "ecdsa"))]
fn bench_signature_comparison(c: &mut Criterion) {
    let ed25519_key = Ed25519SigningKey::generate();
    let p256_key = P256SigningKey::generate();
    let secp256k1_key = Secp256k1SigningKey::generate();

    let message = vec![0u8; 256];

    let mut group = c.benchmark_group("comparison/sign/256");
    group.throughput(Throughput::Bytes(256));

    group.bench_function("ed25519", |b| {
        b.iter(|| black_box(ed25519_key.sign(&message)))
    });

    group.bench_function("ecdsa_p256", |b| {
        b.iter(|| black_box(p256_key.sign(&message)))
    });

    group.bench_function("ecdsa_secp256k1", |b| {
        b.iter(|| black_box(secp256k1_key.sign(&message)))
    });

    #[cfg(feature = "schnorr")]
    {
        let schnorr_key = SchnorrSigningKey::generate();
        group.bench_function("schnorr", |b| {
            b.iter(|| black_box(schnorr_key.sign(&message)))
        });
    }

    group.finish();

    // Verify comparison
    let ed25519_vk = ed25519_key.verifying_key();
    let p256_vk = p256_key.verifying_key();
    let secp256k1_vk = secp256k1_key.verifying_key();

    let ed25519_sig = ed25519_key.sign(&message);
    let p256_sig = p256_key.sign(&message);
    let secp256k1_sig = secp256k1_key.sign(&message);

    let mut group = c.benchmark_group("comparison/verify/256");
    group.throughput(Throughput::Bytes(256));

    group.bench_function("ed25519", |b| {
        b.iter(|| black_box(ed25519_vk.verify(&message, &ed25519_sig)))
    });

    group.bench_function("ecdsa_p256", |b| {
        b.iter(|| black_box(p256_vk.verify(&message, &p256_sig)))
    });

    group.bench_function("ecdsa_secp256k1", |b| {
        b.iter(|| black_box(secp256k1_vk.verify(&message, &secp256k1_sig)))
    });

    #[cfg(feature = "schnorr")]
    {
        let schnorr_key = SchnorrSigningKey::generate();
        let schnorr_vk = schnorr_key.verifying_key();
        let schnorr_sig = schnorr_key.sign(&message);
        group.bench_function("schnorr", |b| {
            b.iter(|| black_box(schnorr_vk.verify(&message, &schnorr_sig)))
        });
    }

    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════════════
// CRITERION CONFIGURATION
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(all(feature = "ed25519", feature = "ecdsa", feature = "schnorr"))]
criterion_group!(
    benches,
    // Ed25519
    bench_ed25519_keygen,
    bench_ed25519_sign,
    bench_ed25519_verify,
    // Ed25519 Batch Verification
    bench_ed25519_batch_verify,
    bench_ed25519_batch_vs_individual,
    bench_ed25519_batch_same_key,
    // ECDSA P-256
    bench_p256_keygen,
    bench_p256_sign,
    bench_p256_verify,
    // ECDSA P-384
    bench_p384_keygen,
    bench_p384_sign,
    bench_p384_verify,
    // ECDSA secp256k1
    bench_secp256k1_keygen,
    bench_secp256k1_sign,
    bench_secp256k1_verify,
    // Schnorr
    bench_schnorr_keygen,
    bench_schnorr_sign,
    bench_schnorr_verify,
    // Comparison
    bench_signature_comparison,
);

#[cfg(all(feature = "ed25519", feature = "ecdsa", not(feature = "schnorr")))]
criterion_group!(
    benches,
    bench_ed25519_keygen,
    bench_ed25519_sign,
    bench_ed25519_verify,
    bench_ed25519_batch_verify,
    bench_ed25519_batch_vs_individual,
    bench_ed25519_batch_same_key,
    bench_p256_keygen,
    bench_p256_sign,
    bench_p256_verify,
    bench_p384_keygen,
    bench_p384_sign,
    bench_p384_verify,
    bench_secp256k1_keygen,
    bench_secp256k1_sign,
    bench_secp256k1_verify,
    bench_signature_comparison,
);

#[cfg(all(feature = "ed25519", not(feature = "ecdsa")))]
criterion_group!(
    benches,
    bench_ed25519_keygen,
    bench_ed25519_sign,
    bench_ed25519_verify,
    bench_ed25519_batch_verify,
    bench_ed25519_batch_vs_individual,
    bench_ed25519_batch_same_key,
);

#[cfg(all(feature = "ecdsa", not(feature = "ed25519")))]
criterion_group!(
    benches,
    bench_p256_keygen,
    bench_p256_sign,
    bench_p256_verify,
    bench_p384_keygen,
    bench_p384_sign,
    bench_p384_verify,
    bench_secp256k1_keygen,
    bench_secp256k1_sign,
    bench_secp256k1_verify,
);

#[cfg(not(any(feature = "ed25519", feature = "ecdsa")))]
fn no_features(_c: &mut Criterion) {}

#[cfg(not(any(feature = "ed25519", feature = "ecdsa")))]
criterion_group!(benches, no_features);

criterion_main!(benches);
