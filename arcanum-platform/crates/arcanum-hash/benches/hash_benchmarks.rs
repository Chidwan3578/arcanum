//! Benchmarks for hash function operations.

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};

#[cfg(feature = "sha2")]
use arcanum_hash::sha2_impl::Sha256;

#[cfg(feature = "blake3")]
use arcanum_hash::blake3_impl::Blake3;

#[cfg(feature = "argon2")]
use arcanum_hash::argon2_impl::{Argon2, Argon2Params};

use arcanum_hash::traits::Hasher;

#[cfg(feature = "sha2")]
fn bench_sha256(c: &mut Criterion) {
    let mut group = c.benchmark_group("sha256");

    for size in [64, 256, 1024, 4096, 65536].iter() {
        let data = vec![0u8; *size];

        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| {
                black_box(Sha256::hash(&data))
            })
        });
    }

    group.finish();
}

#[cfg(feature = "blake3")]
fn bench_blake3(c: &mut Criterion) {
    let mut group = c.benchmark_group("blake3");

    for size in [64, 256, 1024, 4096, 65536, 1048576].iter() {
        let data = vec![0u8; *size];

        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| {
                black_box(Blake3::hash(&data))
            })
        });
    }

    group.finish();
}

#[cfg(feature = "argon2")]
fn bench_argon2_hash(c: &mut Criterion) {
    let mut group = c.benchmark_group("argon2");
    group.sample_size(10); // Argon2 is intentionally slow

    let password = b"benchmark-password";

    // Low-cost params for benchmarking
    let params = Argon2Params {
        memory_cost: 16 * 1024, // 16 MB
        time_cost: 2,
        parallelism: 1,
        output_length: 32,
    };

    group.bench_function("hash_16mb_t2", |b| {
        b.iter(|| {
            black_box(Argon2::hash_password(password, &params))
        })
    });

    group.finish();
}

#[cfg(feature = "hkdf")]
use arcanum_hash::hkdf_impl::Hkdf;

#[cfg(all(feature = "hkdf", feature = "sha2"))]
fn bench_hkdf_derive(c: &mut Criterion) {
    let ikm = b"input key material for benchmarking";
    let salt = Some(b"benchmark salt".as_slice());
    let info = Some(b"benchmark info".as_slice());

    c.bench_function("hkdf_sha256_derive_32", |b| {
        b.iter(|| {
            black_box(Hkdf::<Sha256>::derive(ikm, salt, info, 32))
        })
    });
}

#[cfg(all(feature = "sha2", feature = "blake3", feature = "argon2", feature = "hkdf"))]
criterion_group!(
    benches,
    bench_sha256,
    bench_blake3,
    bench_argon2_hash,
    bench_hkdf_derive,
);

#[cfg(all(feature = "sha2", feature = "blake3", not(any(feature = "argon2", feature = "hkdf"))))]
criterion_group!(
    benches,
    bench_sha256,
    bench_blake3,
);

#[cfg(all(feature = "sha2", not(feature = "blake3")))]
criterion_group!(
    benches,
    bench_sha256,
);

#[cfg(all(feature = "blake3", not(feature = "sha2")))]
criterion_group!(
    benches,
    bench_blake3,
);

#[cfg(not(any(feature = "sha2", feature = "blake3")))]
fn no_features(_c: &mut Criterion) {}

#[cfg(not(any(feature = "sha2", feature = "blake3")))]
criterion_group!(benches, no_features);

criterion_main!(benches);
