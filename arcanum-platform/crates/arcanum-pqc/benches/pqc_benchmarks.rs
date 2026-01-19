//! Benchmarks for post-quantum cryptography operations.

use criterion::{black_box, criterion_group, criterion_main, Criterion};

#[cfg(feature = "ml-kem")]
use arcanum_pqc::kem::{MlKem512, MlKem768, MlKem1024};

#[cfg(feature = "ml-dsa")]
use arcanum_pqc::dsa::{MlDsa44, MlDsa65, MlDsa87};

#[cfg(feature = "ml-kem")]
fn bench_mlkem_keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("mlkem_keygen");

    group.bench_function("mlkem512", |b| {
        b.iter(|| black_box(MlKem512::generate_keypair()))
    });

    group.bench_function("mlkem768", |b| {
        b.iter(|| black_box(MlKem768::generate_keypair()))
    });

    group.bench_function("mlkem1024", |b| {
        b.iter(|| black_box(MlKem1024::generate_keypair()))
    });

    group.finish();
}

#[cfg(feature = "ml-kem")]
fn bench_mlkem_encapsulate(c: &mut Criterion) {
    let (_, ek768) = MlKem768::generate_keypair().unwrap();

    c.bench_function("mlkem768_encapsulate", |b| {
        b.iter(|| black_box(MlKem768::encapsulate(&ek768)))
    });
}

#[cfg(feature = "ml-kem")]
fn bench_mlkem_decapsulate(c: &mut Criterion) {
    let (dk768, ek768) = MlKem768::generate_keypair().unwrap();
    let (ct, _) = MlKem768::encapsulate(&ek768).unwrap();

    c.bench_function("mlkem768_decapsulate", |b| {
        b.iter(|| black_box(MlKem768::decapsulate(&dk768, &ct)))
    });
}

#[cfg(feature = "ml-dsa")]
fn bench_mldsa_keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("mldsa_keygen");

    group.bench_function("mldsa44", |b| {
        b.iter(|| black_box(MlDsa44::generate_keypair()))
    });

    group.bench_function("mldsa65", |b| {
        b.iter(|| black_box(MlDsa65::generate_keypair()))
    });

    group.bench_function("mldsa87", |b| {
        b.iter(|| black_box(MlDsa87::generate_keypair()))
    });

    group.finish();
}

#[cfg(feature = "ml-dsa")]
fn bench_mldsa_sign(c: &mut Criterion) {
    let (sk, _) = MlDsa65::generate_keypair().unwrap();
    let message = b"Benchmark message for ML-DSA signing";

    c.bench_function("mldsa65_sign", |b| {
        b.iter(|| black_box(MlDsa65::sign(&sk, message)))
    });
}

#[cfg(feature = "ml-dsa")]
fn bench_mldsa_verify(c: &mut Criterion) {
    let (sk, vk) = MlDsa65::generate_keypair().unwrap();
    let message = b"Benchmark message for ML-DSA verification";
    let signature = MlDsa65::sign(&sk, message).unwrap();

    c.bench_function("mldsa65_verify", |b| {
        b.iter(|| black_box(MlDsa65::verify(&vk, message, &signature)))
    });
}

#[cfg(all(feature = "ml-kem", feature = "ml-dsa"))]
criterion_group!(
    benches,
    bench_mlkem_keygen,
    bench_mlkem_encapsulate,
    bench_mlkem_decapsulate,
    bench_mldsa_keygen,
    bench_mldsa_sign,
    bench_mldsa_verify,
);

#[cfg(all(feature = "ml-kem", not(feature = "ml-dsa")))]
criterion_group!(
    benches,
    bench_mlkem_keygen,
    bench_mlkem_encapsulate,
    bench_mlkem_decapsulate,
);

#[cfg(all(feature = "ml-dsa", not(feature = "ml-kem")))]
criterion_group!(
    benches,
    bench_mldsa_keygen,
    bench_mldsa_sign,
    bench_mldsa_verify,
);

#[cfg(not(any(feature = "ml-kem", feature = "ml-dsa")))]
fn no_features(_c: &mut Criterion) {}

#[cfg(not(any(feature = "ml-kem", feature = "ml-dsa")))]
criterion_group!(benches, no_features);

criterion_main!(benches);
