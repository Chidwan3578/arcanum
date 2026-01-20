//! Benchmarks for asymmetric cryptography operations.

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};

#[cfg(feature = "x25519")]
use arcanum_asymmetric::x25519::{X25519SecretKey, X25519PublicKey};

use arcanum_asymmetric::ecdh::{
    EcdhP256, EcdhP384,
    P256SecretKey, P384SecretKey,
};

#[cfg(feature = "x25519")]
fn bench_x25519(c: &mut Criterion) {
    let mut group = c.benchmark_group("X25519");

    group.bench_function("keygen", |b| {
        b.iter(|| X25519SecretKey::generate())
    });

    let alice_secret = X25519SecretKey::generate();
    let bob_secret = X25519SecretKey::generate();
    let bob_public = bob_secret.public_key();

    group.bench_function("derive_public", |b| {
        b.iter(|| black_box(&alice_secret).public_key())
    });

    group.bench_function("diffie_hellman", |b| {
        b.iter(|| black_box(&alice_secret).diffie_hellman(black_box(&bob_public)))
    });

    group.finish();
}

fn bench_ecdh_p256(c: &mut Criterion) {
    let mut group = c.benchmark_group("ECDH-P256");

    group.bench_function("keygen", |b| {
        b.iter(|| P256SecretKey::generate())
    });

    let alice_secret = P256SecretKey::generate();
    let bob_secret = P256SecretKey::generate();
    let bob_public = bob_secret.public_key();

    group.bench_function("derive_public", |b| {
        b.iter(|| black_box(&alice_secret).public_key())
    });

    group.bench_function("diffie_hellman", |b| {
        b.iter(|| EcdhP256::diffie_hellman(black_box(&alice_secret), black_box(&bob_public)))
    });

    group.finish();
}

fn bench_ecdh_p384(c: &mut Criterion) {
    let mut group = c.benchmark_group("ECDH-P384");

    group.bench_function("keygen", |b| {
        b.iter(|| P384SecretKey::generate())
    });

    let alice_secret = P384SecretKey::generate();
    let bob_secret = P384SecretKey::generate();
    let bob_public = bob_secret.public_key();

    group.bench_function("derive_public", |b| {
        b.iter(|| black_box(&alice_secret).public_key())
    });

    group.bench_function("diffie_hellman", |b| {
        b.iter(|| EcdhP384::diffie_hellman(black_box(&alice_secret), black_box(&bob_public)))
    });

    group.finish();
}

#[cfg(feature = "ecies")]
fn bench_ecies(c: &mut Criterion) {
    use arcanum_asymmetric::ecies::EciesP256;

    let mut group = c.benchmark_group("ECIES-P256");

    let (secret_key, public_key) = EciesP256::generate_keypair();
    let plaintext = b"Hello, ECIES encryption benchmark!";

    group.bench_function("encrypt", |b| {
        b.iter(|| EciesP256::encrypt(black_box(&public_key), black_box(plaintext)))
    });

    let ciphertext = EciesP256::encrypt(&public_key, plaintext).unwrap();

    group.bench_function("decrypt", |b| {
        b.iter(|| EciesP256::decrypt(black_box(&secret_key), black_box(&ciphertext)))
    });

    group.finish();
}

#[cfg(feature = "rsa")]
fn bench_rsa(c: &mut Criterion) {
    use arcanum_asymmetric::rsa_impl::RsaKeyPair;

    let mut group = c.benchmark_group("RSA");

    // RSA key generation is slow, so we use a smaller sample size
    group.sample_size(10);

    group.bench_function("keygen_2048", |b| {
        b.iter(|| RsaKeyPair::generate(2048))
    });

    let (private_key, public_key) = RsaKeyPair::generate(2048).unwrap();
    let plaintext = b"RSA encryption benchmark message";

    group.sample_size(100);

    group.bench_function("encrypt_oaep_2048", |b| {
        b.iter(|| public_key.encrypt_oaep(black_box(plaintext)))
    });

    let ciphertext = public_key.encrypt_oaep(plaintext).unwrap();

    group.bench_function("decrypt_oaep_2048", |b| {
        b.iter(|| private_key.decrypt_oaep(black_box(&ciphertext)))
    });

    group.finish();
}

// Conditionally include benchmarks based on features
criterion_group!(
    benches,
    #[cfg(feature = "x25519")]
    bench_x25519,
    bench_ecdh_p256,
    bench_ecdh_p384,
    #[cfg(feature = "ecies")]
    bench_ecies,
    #[cfg(feature = "rsa")]
    bench_rsa,
);

// Fallback for minimal feature set
#[cfg(not(any(feature = "x25519", feature = "ecies", feature = "rsa")))]
criterion_group!(benches, bench_ecdh_p256, bench_ecdh_p384);

criterion_main!(benches);
