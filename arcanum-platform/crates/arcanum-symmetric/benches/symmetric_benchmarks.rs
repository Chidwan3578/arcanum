//! Benchmarks for symmetric encryption operations.
//!
//! Run with: `cargo bench -p arcanum-symmetric --all-features`

use criterion::{
    black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput,
};

#[cfg(feature = "aes")]
use arcanum_symmetric::aes_ciphers::{Aes128Gcm, Aes256Gcm, Aes256GcmSiv};

#[cfg(feature = "chacha20")]
use arcanum_symmetric::chacha_ciphers::{ChaCha20Poly1305Cipher, XChaCha20Poly1305Cipher};

use arcanum_symmetric::{Cipher, CipherBuilder, CipherInstance, NonceStrategy};

// Standard message sizes for benchmarking
const SIZES: &[usize] = &[64, 256, 1024, 4096, 16384, 65536];

// ═══════════════════════════════════════════════════════════════════════════════
// AES-256-GCM BENCHMARKS
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(feature = "aes")]
fn bench_aes256gcm_encrypt(c: &mut Criterion) {
    let key = Aes256Gcm::generate_key();
    let nonce = Aes256Gcm::generate_nonce();

    let mut group = c.benchmark_group("aes256gcm/encrypt");

    for size in SIZES {
        let plaintext = vec![0u8; *size];

        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| black_box(Aes256Gcm::encrypt(&key, &nonce, &plaintext, None)))
        });
    }

    group.finish();
}

#[cfg(feature = "aes")]
fn bench_aes256gcm_decrypt(c: &mut Criterion) {
    let key = Aes256Gcm::generate_key();
    let nonce = Aes256Gcm::generate_nonce();

    let mut group = c.benchmark_group("aes256gcm/decrypt");

    for size in SIZES {
        let plaintext = vec![0u8; *size];
        let ciphertext = Aes256Gcm::encrypt(&key, &nonce, &plaintext, None).unwrap();

        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| black_box(Aes256Gcm::decrypt(&key, &nonce, &ciphertext, None)))
        });
    }

    group.finish();
}

#[cfg(feature = "aes")]
fn bench_aes256gcm_seal_open(c: &mut Criterion) {
    let key = Aes256Gcm::generate_key();

    let mut group = c.benchmark_group("aes256gcm/seal_open");

    for size in SIZES {
        let plaintext = vec![0u8; *size];

        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::new("seal", size), size, |b, _| {
            b.iter(|| black_box(Aes256Gcm::seal(&key, &plaintext)))
        });

        let sealed = Aes256Gcm::seal(&key, &plaintext).unwrap();
        group.bench_with_input(BenchmarkId::new("open", size), size, |b, _| {
            b.iter(|| black_box(Aes256Gcm::open(&key, &sealed)))
        });
    }

    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════════════
// AES-128-GCM BENCHMARKS
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(feature = "aes")]
fn bench_aes128gcm_encrypt(c: &mut Criterion) {
    let key = Aes128Gcm::generate_key();
    let nonce = Aes128Gcm::generate_nonce();

    let mut group = c.benchmark_group("aes128gcm/encrypt");

    for size in SIZES {
        let plaintext = vec![0u8; *size];

        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| black_box(Aes128Gcm::encrypt(&key, &nonce, &plaintext, None)))
        });
    }

    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════════════
// AES-256-GCM-SIV BENCHMARKS
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(feature = "aes")]
fn bench_aes256gcmsiv_encrypt(c: &mut Criterion) {
    let key = Aes256GcmSiv::generate_key();
    let nonce = Aes256GcmSiv::generate_nonce();

    let mut group = c.benchmark_group("aes256gcmsiv/encrypt");

    for size in SIZES {
        let plaintext = vec![0u8; *size];

        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| black_box(Aes256GcmSiv::encrypt(&key, &nonce, &plaintext, None)))
        });
    }

    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════════════
// CHACHA20-POLY1305 BENCHMARKS
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(feature = "chacha20")]
fn bench_chacha20poly1305_encrypt(c: &mut Criterion) {
    let key = ChaCha20Poly1305Cipher::generate_key();
    let nonce = ChaCha20Poly1305Cipher::generate_nonce();

    let mut group = c.benchmark_group("chacha20poly1305/encrypt");

    for size in SIZES {
        let plaintext = vec![0u8; *size];

        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| {
                black_box(ChaCha20Poly1305Cipher::encrypt(
                    &key, &nonce, &plaintext, None,
                ))
            })
        });
    }

    group.finish();
}

#[cfg(feature = "chacha20")]
fn bench_chacha20poly1305_decrypt(c: &mut Criterion) {
    let key = ChaCha20Poly1305Cipher::generate_key();
    let nonce = ChaCha20Poly1305Cipher::generate_nonce();

    let mut group = c.benchmark_group("chacha20poly1305/decrypt");

    for size in SIZES {
        let plaintext = vec![0u8; *size];
        let ciphertext =
            ChaCha20Poly1305Cipher::encrypt(&key, &nonce, &plaintext, None).unwrap();

        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| {
                black_box(ChaCha20Poly1305Cipher::decrypt(
                    &key, &nonce, &ciphertext, None,
                ))
            })
        });
    }

    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════════════
// XCHACHA20-POLY1305 BENCHMARKS
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(feature = "chacha20")]
fn bench_xchacha20poly1305_encrypt(c: &mut Criterion) {
    let key = XChaCha20Poly1305Cipher::generate_key();
    let nonce = XChaCha20Poly1305Cipher::generate_nonce();

    let mut group = c.benchmark_group("xchacha20poly1305/encrypt");

    for size in SIZES {
        let plaintext = vec![0u8; *size];

        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| {
                black_box(XChaCha20Poly1305Cipher::encrypt(
                    &key, &nonce, &plaintext, None,
                ))
            })
        });
    }

    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════════════
// CIPHER INSTANCE (BUILDER API) BENCHMARKS
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(feature = "aes")]
fn bench_cipher_instance_random_nonce(c: &mut Criterion) {
    let key = Aes256Gcm::generate_key();
    let cipher = CipherInstance::<Aes256Gcm>::new(&key).unwrap();
    let plaintext = vec![0u8; 1024];

    c.bench_function("cipher_instance/aes256gcm/random_nonce/1k", |b| {
        b.iter(|| black_box(cipher.encrypt(&plaintext)))
    });
}

#[cfg(feature = "aes")]
fn bench_cipher_instance_counter_nonce(c: &mut Criterion) {
    let key = Aes256Gcm::generate_key();
    let cipher = CipherBuilder::<Aes256Gcm>::new()
        .key(&key)
        .nonce_strategy(NonceStrategy::Counter)
        .build()
        .unwrap();
    let plaintext = vec![0u8; 1024];

    c.bench_function("cipher_instance/aes256gcm/counter_nonce/1k", |b| {
        b.iter(|| black_box(cipher.encrypt(&plaintext)))
    });
}

// ═══════════════════════════════════════════════════════════════════════════════
// ALGORITHM COMPARISON
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(all(feature = "aes", feature = "chacha20"))]
fn bench_algorithm_comparison(c: &mut Criterion) {
    let aes256_key = Aes256Gcm::generate_key();
    let aes256_nonce = Aes256Gcm::generate_nonce();
    let aes128_key = Aes128Gcm::generate_key();
    let aes128_nonce = Aes128Gcm::generate_nonce();
    let chacha_key = ChaCha20Poly1305Cipher::generate_key();
    let chacha_nonce = ChaCha20Poly1305Cipher::generate_nonce();

    let plaintext = vec![0u8; 4096];

    let mut group = c.benchmark_group("comparison/encrypt/4k");
    group.throughput(Throughput::Bytes(4096));

    group.bench_function("aes256gcm", |b| {
        b.iter(|| black_box(Aes256Gcm::encrypt(&aes256_key, &aes256_nonce, &plaintext, None)))
    });

    group.bench_function("aes128gcm", |b| {
        b.iter(|| black_box(Aes128Gcm::encrypt(&aes128_key, &aes128_nonce, &plaintext, None)))
    });

    group.bench_function("chacha20poly1305", |b| {
        b.iter(|| {
            black_box(ChaCha20Poly1305Cipher::encrypt(
                &chacha_key,
                &chacha_nonce,
                &plaintext,
                None,
            ))
        })
    });

    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════════════
// KEY GENERATION BENCHMARKS
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(feature = "aes")]
fn bench_key_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("keygen");

    group.bench_function("aes256", |b| {
        b.iter(|| black_box(Aes256Gcm::generate_key()))
    });

    group.bench_function("aes128", |b| {
        b.iter(|| black_box(Aes128Gcm::generate_key()))
    });

    #[cfg(feature = "chacha20")]
    group.bench_function("chacha20", |b| {
        b.iter(|| black_box(ChaCha20Poly1305Cipher::generate_key()))
    });

    group.finish();
}

// ═══════════════════════════════════════════════════════════════════════════════
// CRITERION CONFIGURATION
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(all(feature = "aes", feature = "chacha20"))]
criterion_group!(
    benches,
    // AES-256-GCM
    bench_aes256gcm_encrypt,
    bench_aes256gcm_decrypt,
    bench_aes256gcm_seal_open,
    // AES-128-GCM
    bench_aes128gcm_encrypt,
    // AES-256-GCM-SIV
    bench_aes256gcmsiv_encrypt,
    // ChaCha20-Poly1305
    bench_chacha20poly1305_encrypt,
    bench_chacha20poly1305_decrypt,
    // XChaCha20-Poly1305
    bench_xchacha20poly1305_encrypt,
    // CipherInstance API
    bench_cipher_instance_random_nonce,
    bench_cipher_instance_counter_nonce,
    // Comparisons
    bench_algorithm_comparison,
    bench_key_generation,
);

#[cfg(all(feature = "aes", not(feature = "chacha20")))]
criterion_group!(
    benches,
    bench_aes256gcm_encrypt,
    bench_aes256gcm_decrypt,
    bench_aes256gcm_seal_open,
    bench_aes128gcm_encrypt,
    bench_aes256gcmsiv_encrypt,
    bench_cipher_instance_random_nonce,
    bench_cipher_instance_counter_nonce,
    bench_key_generation,
);

#[cfg(all(feature = "chacha20", not(feature = "aes")))]
criterion_group!(
    benches,
    bench_chacha20poly1305_encrypt,
    bench_chacha20poly1305_decrypt,
    bench_xchacha20poly1305_encrypt,
);

#[cfg(not(any(feature = "aes", feature = "chacha20")))]
fn no_features(_c: &mut Criterion) {}

#[cfg(not(any(feature = "aes", feature = "chacha20")))]
criterion_group!(benches, no_features);

criterion_main!(benches);
