//! Comparative benchmarks: RustCrypto vs ring
//!
//! This benchmark compares the cryptographic backends that Arcanum uses:
//! - RustCrypto: Pure Rust implementations (Arcanum's primary backend)
//! - ring: BoringSSL wrapper (peer library, C-based)
//!
//! Results help understand the performance trade-offs documented in ADR-0001.

use criterion::{
    black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput,
};

// Message sizes for benchmarking
const SIZES: &[usize] = &[64, 256, 1024, 4096, 16384, 65536];

// ═══════════════════════════════════════════════════════════════════════════════
// SYMMETRIC ENCRYPTION BENCHMARKS
// ═══════════════════════════════════════════════════════════════════════════════

mod rustcrypto_aes {
    use aead::{Aead, KeyInit};
    use aes_gcm::Aes256Gcm;
    use rand::RngCore;

    pub fn keygen() -> ([u8; 32], [u8; 12]) {
        let mut key = [0u8; 32];
        let mut nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut key);
        rand::thread_rng().fill_bytes(&mut nonce);
        (key, nonce)
    }

    pub fn encrypt(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8]) -> Vec<u8> {
        let cipher = Aes256Gcm::new_from_slice(key).unwrap();
        let nonce = aes_gcm::Nonce::from_slice(nonce);
        cipher.encrypt(nonce, plaintext).unwrap()
    }

    pub fn decrypt(key: &[u8; 32], nonce: &[u8; 12], ciphertext: &[u8]) -> Vec<u8> {
        let cipher = Aes256Gcm::new_from_slice(key).unwrap();
        let nonce = aes_gcm::Nonce::from_slice(nonce);
        cipher.decrypt(nonce, ciphertext).unwrap()
    }
}

mod rustcrypto_chacha {
    use aead::{Aead, KeyInit};
    use chacha20poly1305::ChaCha20Poly1305;
    use rand::RngCore;

    pub fn keygen() -> ([u8; 32], [u8; 12]) {
        let mut key = [0u8; 32];
        let mut nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut key);
        rand::thread_rng().fill_bytes(&mut nonce);
        (key, nonce)
    }

    pub fn encrypt(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8]) -> Vec<u8> {
        let cipher = ChaCha20Poly1305::new_from_slice(key).unwrap();
        let nonce = chacha20poly1305::Nonce::from_slice(nonce);
        cipher.encrypt(nonce, plaintext).unwrap()
    }

    pub fn decrypt(key: &[u8; 32], nonce: &[u8; 12], ciphertext: &[u8]) -> Vec<u8> {
        let cipher = ChaCha20Poly1305::new_from_slice(key).unwrap();
        let nonce = chacha20poly1305::Nonce::from_slice(nonce);
        cipher.decrypt(nonce, ciphertext).unwrap()
    }
}

mod ring_aes {
    use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
    use ring::rand::{SecureRandom, SystemRandom};

    pub fn keygen() -> (Vec<u8>, [u8; 12]) {
        let rng = SystemRandom::new();
        let mut key = vec![0u8; 32];
        let mut nonce = [0u8; 12];
        rng.fill(&mut key).unwrap();
        rng.fill(&mut nonce).unwrap();
        (key, nonce)
    }

    pub fn encrypt(key: &[u8], nonce: &[u8; 12], plaintext: &[u8]) -> Vec<u8> {
        let unbound_key = UnboundKey::new(&AES_256_GCM, key).unwrap();
        let key = LessSafeKey::new(unbound_key);
        let nonce = Nonce::assume_unique_for_key(*nonce);
        let mut in_out = plaintext.to_vec();
        key.seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
            .unwrap();
        in_out
    }

    pub fn decrypt(key: &[u8], nonce: &[u8; 12], ciphertext: &[u8]) -> Vec<u8> {
        let unbound_key = UnboundKey::new(&AES_256_GCM, key).unwrap();
        let key = LessSafeKey::new(unbound_key);
        let nonce = Nonce::assume_unique_for_key(*nonce);
        let mut in_out = ciphertext.to_vec();
        let plaintext = key
            .open_in_place(nonce, Aad::empty(), &mut in_out)
            .unwrap();
        plaintext.to_vec()
    }
}

mod ring_chacha {
    use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};
    use ring::rand::{SecureRandom, SystemRandom};

    pub fn keygen() -> (Vec<u8>, [u8; 12]) {
        let rng = SystemRandom::new();
        let mut key = vec![0u8; 32];
        let mut nonce = [0u8; 12];
        rng.fill(&mut key).unwrap();
        rng.fill(&mut nonce).unwrap();
        (key, nonce)
    }

    pub fn encrypt(key: &[u8], nonce: &[u8; 12], plaintext: &[u8]) -> Vec<u8> {
        let unbound_key = UnboundKey::new(&CHACHA20_POLY1305, key).unwrap();
        let key = LessSafeKey::new(unbound_key);
        let nonce = Nonce::assume_unique_for_key(*nonce);
        let mut in_out = plaintext.to_vec();
        key.seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
            .unwrap();
        in_out
    }

    pub fn decrypt(key: &[u8], nonce: &[u8; 12], ciphertext: &[u8]) -> Vec<u8> {
        let unbound_key = UnboundKey::new(&CHACHA20_POLY1305, key).unwrap();
        let key = LessSafeKey::new(unbound_key);
        let nonce = Nonce::assume_unique_for_key(*nonce);
        let mut in_out = ciphertext.to_vec();
        let plaintext = key
            .open_in_place(nonce, Aad::empty(), &mut in_out)
            .unwrap();
        plaintext.to_vec()
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// DIGITAL SIGNATURE BENCHMARKS
// ═══════════════════════════════════════════════════════════════════════════════

mod rustcrypto_ed25519 {
    use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
    use rand::rngs::OsRng;

    pub fn keygen() -> (SigningKey, VerifyingKey) {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        (signing_key, verifying_key)
    }

    pub fn sign(signing_key: &SigningKey, message: &[u8]) -> Signature {
        signing_key.sign(message)
    }

    pub fn verify(verifying_key: &VerifyingKey, message: &[u8], signature: &Signature) -> bool {
        verifying_key.verify(message, signature).is_ok()
    }
}

mod ring_ed25519 {
    use ring::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};
    use ring::rand::SystemRandom;

    pub struct RingKeyPair {
        keypair: Ed25519KeyPair,
        public_key_bytes: Vec<u8>,
    }

    pub fn keygen() -> RingKeyPair {
        let rng = SystemRandom::new();
        let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let keypair = Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();
        let public_key_bytes = keypair.public_key().as_ref().to_vec();
        RingKeyPair { keypair, public_key_bytes }
    }

    pub fn sign(keypair: &RingKeyPair, message: &[u8]) -> Vec<u8> {
        keypair.keypair.sign(message).as_ref().to_vec()
    }

    pub fn verify(keypair: &RingKeyPair, message: &[u8], signature: &[u8]) -> bool {
        let public_key = UnparsedPublicKey::new(&ED25519, &keypair.public_key_bytes);
        public_key.verify(message, signature).is_ok()
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// HASH FUNCTION BENCHMARKS
// ═══════════════════════════════════════════════════════════════════════════════

mod rustcrypto_sha256 {
    use sha2::{Sha256, Digest};

    pub fn hash(data: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().to_vec()
    }
}

mod blake3_crate {
    pub fn hash(data: &[u8]) -> Vec<u8> {
        blake3::hash(data).as_bytes().to_vec()
    }
}

mod ring_sha256 {
    use ring::digest::{digest, SHA256};

    pub fn hash(data: &[u8]) -> Vec<u8> {
        digest(&SHA256, data).as_ref().to_vec()
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// BENCHMARK FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════════════

fn bench_aes256_gcm(c: &mut Criterion) {
    let mut group = c.benchmark_group("AES-256-GCM");

    for size in SIZES {
        let plaintext = vec![0u8; *size];
        group.throughput(Throughput::Bytes(*size as u64));

        // RustCrypto (Arcanum's backend)
        let (rc_key, rc_nonce) = rustcrypto_aes::keygen();
        let rc_ciphertext = rustcrypto_aes::encrypt(&rc_key, &rc_nonce, &plaintext);

        group.bench_with_input(
            BenchmarkId::new("RustCrypto/encrypt", size),
            size,
            |b, _| b.iter(|| rustcrypto_aes::encrypt(black_box(&rc_key), black_box(&rc_nonce), black_box(&plaintext))),
        );

        group.bench_with_input(
            BenchmarkId::new("RustCrypto/decrypt", size),
            size,
            |b, _| b.iter(|| rustcrypto_aes::decrypt(black_box(&rc_key), black_box(&rc_nonce), black_box(&rc_ciphertext))),
        );

        // ring
        let (ring_key, ring_nonce) = ring_aes::keygen();
        let ring_ciphertext = ring_aes::encrypt(&ring_key, &ring_nonce, &plaintext);

        group.bench_with_input(
            BenchmarkId::new("ring/encrypt", size),
            size,
            |b, _| b.iter(|| ring_aes::encrypt(black_box(&ring_key), black_box(&ring_nonce), black_box(&plaintext))),
        );

        group.bench_with_input(
            BenchmarkId::new("ring/decrypt", size),
            size,
            |b, _| b.iter(|| ring_aes::decrypt(black_box(&ring_key), black_box(&ring_nonce), black_box(&ring_ciphertext))),
        );
    }

    group.finish();
}

fn bench_chacha20_poly1305(c: &mut Criterion) {
    let mut group = c.benchmark_group("ChaCha20-Poly1305");

    for size in SIZES {
        let plaintext = vec![0u8; *size];
        group.throughput(Throughput::Bytes(*size as u64));

        // RustCrypto
        let (rc_key, rc_nonce) = rustcrypto_chacha::keygen();
        let rc_ciphertext = rustcrypto_chacha::encrypt(&rc_key, &rc_nonce, &plaintext);

        group.bench_with_input(
            BenchmarkId::new("RustCrypto/encrypt", size),
            size,
            |b, _| b.iter(|| rustcrypto_chacha::encrypt(black_box(&rc_key), black_box(&rc_nonce), black_box(&plaintext))),
        );

        group.bench_with_input(
            BenchmarkId::new("RustCrypto/decrypt", size),
            size,
            |b, _| b.iter(|| rustcrypto_chacha::decrypt(black_box(&rc_key), black_box(&rc_nonce), black_box(&rc_ciphertext))),
        );

        // ring
        let (ring_key, ring_nonce) = ring_chacha::keygen();
        let ring_ciphertext = ring_chacha::encrypt(&ring_key, &ring_nonce, &plaintext);

        group.bench_with_input(
            BenchmarkId::new("ring/encrypt", size),
            size,
            |b, _| b.iter(|| ring_chacha::encrypt(black_box(&ring_key), black_box(&ring_nonce), black_box(&plaintext))),
        );

        group.bench_with_input(
            BenchmarkId::new("ring/decrypt", size),
            size,
            |b, _| b.iter(|| ring_chacha::decrypt(black_box(&ring_key), black_box(&ring_nonce), black_box(&ring_ciphertext))),
        );
    }

    group.finish();
}

fn bench_ed25519(c: &mut Criterion) {
    let mut group = c.benchmark_group("Ed25519");

    // Key generation
    group.bench_function("RustCrypto/keygen", |b| {
        b.iter(|| rustcrypto_ed25519::keygen())
    });

    group.bench_function("ring/keygen", |b| {
        b.iter(|| ring_ed25519::keygen())
    });

    // Signing at various message sizes
    for size in &[32usize, 256, 1024, 4096] {
        let message = vec![0u8; *size];
        group.throughput(Throughput::Bytes(*size as u64));

        let (rc_signing_key, rc_verifying_key) = rustcrypto_ed25519::keygen();
        let rc_signature = rustcrypto_ed25519::sign(&rc_signing_key, &message);

        group.bench_with_input(
            BenchmarkId::new("RustCrypto/sign", size),
            size,
            |b, _| b.iter(|| rustcrypto_ed25519::sign(black_box(&rc_signing_key), black_box(&message))),
        );

        group.bench_with_input(
            BenchmarkId::new("RustCrypto/verify", size),
            size,
            |b, _| b.iter(|| rustcrypto_ed25519::verify(black_box(&rc_verifying_key), black_box(&message), black_box(&rc_signature))),
        );

        let ring_keypair = ring_ed25519::keygen();
        let ring_signature = ring_ed25519::sign(&ring_keypair, &message);

        group.bench_with_input(
            BenchmarkId::new("ring/sign", size),
            size,
            |b, _| b.iter(|| ring_ed25519::sign(black_box(&ring_keypair), black_box(&message))),
        );

        group.bench_with_input(
            BenchmarkId::new("ring/verify", size),
            size,
            |b, _| b.iter(|| ring_ed25519::verify(black_box(&ring_keypair), black_box(&message), black_box(&ring_signature))),
        );
    }

    group.finish();
}

fn bench_sha256(c: &mut Criterion) {
    let mut group = c.benchmark_group("SHA-256");

    for size in SIZES {
        let data = vec![0u8; *size];
        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_with_input(
            BenchmarkId::new("RustCrypto", size),
            size,
            |b, _| b.iter(|| rustcrypto_sha256::hash(black_box(&data))),
        );

        group.bench_with_input(
            BenchmarkId::new("ring", size),
            size,
            |b, _| b.iter(|| ring_sha256::hash(black_box(&data))),
        );
    }

    group.finish();
}

fn bench_blake3(c: &mut Criterion) {
    let mut group = c.benchmark_group("BLAKE3");

    for size in SIZES {
        let data = vec![0u8; *size];
        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_with_input(
            BenchmarkId::new("blake3-crate", size),
            size,
            |b, _| b.iter(|| blake3_crate::hash(black_box(&data))),
        );
    }

    group.finish();
}

fn bench_algorithm_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("AlgorithmComparison/4KB");

    let plaintext = vec![0u8; 4096];
    group.throughput(Throughput::Bytes(4096));

    // Symmetric encryption comparison
    let (rc_aes_key, rc_aes_nonce) = rustcrypto_aes::keygen();
    group.bench_function("RustCrypto/AES-256-GCM", |b| {
        b.iter(|| rustcrypto_aes::encrypt(black_box(&rc_aes_key), black_box(&rc_aes_nonce), black_box(&plaintext)))
    });

    let (ring_aes_key, ring_aes_nonce) = ring_aes::keygen();
    group.bench_function("ring/AES-256-GCM", |b| {
        b.iter(|| ring_aes::encrypt(black_box(&ring_aes_key), black_box(&ring_aes_nonce), black_box(&plaintext)))
    });

    let (rc_chacha_key, rc_chacha_nonce) = rustcrypto_chacha::keygen();
    group.bench_function("RustCrypto/ChaCha20-Poly1305", |b| {
        b.iter(|| rustcrypto_chacha::encrypt(black_box(&rc_chacha_key), black_box(&rc_chacha_nonce), black_box(&plaintext)))
    });

    let (ring_chacha_key, ring_chacha_nonce) = ring_chacha::keygen();
    group.bench_function("ring/ChaCha20-Poly1305", |b| {
        b.iter(|| ring_chacha::encrypt(black_box(&ring_chacha_key), black_box(&ring_chacha_nonce), black_box(&plaintext)))
    });

    // Hash comparison
    group.bench_function("RustCrypto/SHA-256", |b| {
        b.iter(|| rustcrypto_sha256::hash(black_box(&plaintext)))
    });

    group.bench_function("ring/SHA-256", |b| {
        b.iter(|| ring_sha256::hash(black_box(&plaintext)))
    });

    group.bench_function("BLAKE3", |b| {
        b.iter(|| blake3_crate::hash(black_box(&plaintext)))
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_aes256_gcm,
    bench_chacha20_poly1305,
    bench_ed25519,
    bench_sha256,
    bench_blake3,
    bench_algorithm_comparison,
);
criterion_main!(benches);
