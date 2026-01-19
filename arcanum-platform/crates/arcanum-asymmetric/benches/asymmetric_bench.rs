//! Benchmarks for asymmetric cryptography operations.

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};

#[cfg(feature = "x25519")]
use arcanum_asymmetric::x25519::{X25519SecretKey, X25519PublicKey};

#[cfg(feature = "rsa")]
use arcanum_asymmetric::rsa_impl::RsaKeyPair;

#[cfg(feature = "x25519")]
fn bench_x25519_keygen(c: &mut Criterion) {
    c.bench_function("x25519_keygen", |b| {
        b.iter(|| {
            black_box(X25519SecretKey::generate())
        })
    });
}

#[cfg(feature = "x25519")]
fn bench_x25519_dh(c: &mut Criterion) {
    let alice_secret = X25519SecretKey::generate();
    let bob_secret = X25519SecretKey::generate();
    let bob_public = bob_secret.public_key();

    c.bench_function("x25519_diffie_hellman", |b| {
        b.iter(|| {
            black_box(alice_secret.derive_shared_secret(&bob_public))
        })
    });
}

#[cfg(feature = "rsa")]
fn bench_rsa_keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("rsa_keygen");
    group.sample_size(10); // RSA keygen is slow

    for bits in [2048, 3072, 4096].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(bits), bits, |b, &bits| {
            b.iter(|| {
                black_box(RsaKeyPair::generate(bits))
            })
        });
    }
    group.finish();
}

#[cfg(feature = "rsa")]
fn bench_rsa_encrypt_decrypt(c: &mut Criterion) {
    let keypair = RsaKeyPair::generate(2048).unwrap();
    let (private_key, public_key) = (keypair.private_key(), keypair.public_key());
    let message = b"Hello, RSA benchmark!";

    c.bench_function("rsa_2048_encrypt_oaep", |b| {
        b.iter(|| {
            black_box(public_key.encrypt_oaep(message))
        })
    });

    let ciphertext = public_key.encrypt_oaep(message).unwrap();

    c.bench_function("rsa_2048_decrypt_oaep", |b| {
        b.iter(|| {
            black_box(private_key.decrypt_oaep(&ciphertext))
        })
    });
}

#[cfg(all(feature = "x25519", feature = "rsa"))]
criterion_group!(
    benches,
    bench_x25519_keygen,
    bench_x25519_dh,
    bench_rsa_keygen,
    bench_rsa_encrypt_decrypt,
);

#[cfg(all(feature = "x25519", not(feature = "rsa")))]
criterion_group!(
    benches,
    bench_x25519_keygen,
    bench_x25519_dh,
);

#[cfg(all(feature = "rsa", not(feature = "x25519")))]
criterion_group!(
    benches,
    bench_rsa_keygen,
    bench_rsa_encrypt_decrypt,
);

#[cfg(not(any(feature = "x25519", feature = "rsa")))]
criterion_group!(benches,);

criterion_main!(benches);
