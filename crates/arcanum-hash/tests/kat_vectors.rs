//! Known Answer Tests (KAT) for hash functions.
//!
//! These tests verify our implementations match official cryptographic
//! test vectors from NIST CAVP and other standards.

use arcanum_hash::{Hasher, Sha256, Sha384, Sha512, Blake3};

// ═══════════════════════════════════════════════════════════════════════════════
// SHA-256 Test Vectors (NIST CAVP)
// ═══════════════════════════════════════════════════════════════════════════════

/// SHA-256 empty string (NIST CAVP ShortMsg)
#[test]
fn sha256_empty() {
    let expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    let hash = Sha256::hash(b"");
    assert_eq!(hash.to_hex(), expected, "SHA-256 empty string mismatch");
}

/// SHA-256 "abc" (NIST CAVP ShortMsg, Len = 24)
#[test]
fn sha256_abc() {
    let expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    let hash = Sha256::hash(b"abc");
    assert_eq!(hash.to_hex(), expected, "SHA-256 'abc' mismatch");
}

/// SHA-256 448-bit message (NIST CAVP ShortMsg, exactly one block minus padding)
#[test]
fn sha256_448_bits() {
    let message = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    let expected = "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1";
    let hash = Sha256::hash(message);
    assert_eq!(hash.to_hex(), expected, "SHA-256 448-bit message mismatch");
}

/// SHA-256 896-bit message (NIST CAVP ShortMsg)
#[test]
fn sha256_896_bits() {
    let message = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    let expected = "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1";
    let hash = Sha256::hash(message);
    assert_eq!(hash.to_hex(), expected, "SHA-256 896-bit message mismatch");
}

/// SHA-256 single byte
#[test]
fn sha256_single_byte() {
    let expected = "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb";
    let hash = Sha256::hash(b"a");
    assert_eq!(hash.to_hex(), expected, "SHA-256 single byte mismatch");
}

/// SHA-256 incremental hashing
#[test]
fn sha256_incremental() {
    let mut hasher = Sha256::new();
    hasher.update(b"abc");
    hasher.update(b"dbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
    let hash = hasher.finalize();

    let expected = "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1";
    assert_eq!(hash.to_hex(), expected, "SHA-256 incremental mismatch");
}

// ═══════════════════════════════════════════════════════════════════════════════
// SHA-384 Test Vectors (NIST CAVP)
// ═══════════════════════════════════════════════════════════════════════════════

/// SHA-384 empty string
#[test]
fn sha384_empty() {
    let expected = "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b";
    let hash = Sha384::hash(b"");
    assert_eq!(hash.to_hex(), expected, "SHA-384 empty string mismatch");
}

/// SHA-384 "abc"
#[test]
fn sha384_abc() {
    let expected = "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7";
    let hash = Sha384::hash(b"abc");
    assert_eq!(hash.to_hex(), expected, "SHA-384 'abc' mismatch");
}

/// SHA-384 896-bit message
#[test]
fn sha384_896_bits() {
    let message = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    let expected = "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039";
    let hash = Sha384::hash(message);
    assert_eq!(hash.to_hex(), expected, "SHA-384 896-bit message mismatch");
}

// ═══════════════════════════════════════════════════════════════════════════════
// SHA-512 Test Vectors (NIST CAVP)
// ═══════════════════════════════════════════════════════════════════════════════

/// SHA-512 empty string
#[test]
fn sha512_empty() {
    let expected = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";
    let hash = Sha512::hash(b"");
    assert_eq!(hash.to_hex(), expected, "SHA-512 empty string mismatch");
}

/// SHA-512 "abc"
#[test]
fn sha512_abc() {
    let expected = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";
    let hash = Sha512::hash(b"abc");
    assert_eq!(hash.to_hex(), expected, "SHA-512 'abc' mismatch");
}

/// SHA-512 896-bit message
#[test]
fn sha512_896_bits() {
    let message = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    let expected = "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909";
    let hash = Sha512::hash(message);
    assert_eq!(hash.to_hex(), expected, "SHA-512 896-bit message mismatch");
}

/// SHA-512 single byte
#[test]
fn sha512_single_byte() {
    let expected = "1f40fc92da241694750979ee6cf582f2d5d7d28e18335de05abc54d0560e0f5302860c652bf08d560252aa5e74210546f369fbbbce8c12cfc7957b2652fe9a75";
    let hash = Sha512::hash(b"a");
    assert_eq!(hash.to_hex(), expected, "SHA-512 single byte mismatch");
}

// ═══════════════════════════════════════════════════════════════════════════════
// BLAKE3 Test Vectors
// ═══════════════════════════════════════════════════════════════════════════════

/// BLAKE3 empty string (verified in blake3_impl.rs)
#[test]
fn blake3_empty() {
    let expected = "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262";
    let hash = Blake3::hash(b"");
    assert_eq!(hash.to_hex(), expected, "BLAKE3 empty string mismatch");
}

/// BLAKE3 "hello" (verified in blake3_impl.rs)
#[test]
fn blake3_hello() {
    let expected = "ea8f163db38682925e4491c5e58d4bb3506ef8c14eb78a86e908c5624a67200f";
    let hash = Blake3::hash(b"hello");
    assert_eq!(hash.to_hex(), expected, "BLAKE3 'hello' mismatch");
}

/// BLAKE3 keyed hash (determinism test)
#[test]
fn blake3_keyed() {
    let key = [0u8; 32];
    let hash1 = Blake3::keyed_hash(&key, b"hello");
    let hash2 = Blake3::keyed_hash(&key, b"hello");
    assert_eq!(hash1, hash2, "BLAKE3 keyed hash should be deterministic");
    assert_eq!(hash1.len(), 32, "BLAKE3 keyed hash should be 32 bytes");
}

/// BLAKE3 key derivation (determinism test)
#[test]
fn blake3_derive_key() {
    let context = "my-app-encryption-key";
    let key1 = Blake3::derive_key(context, b"master-secret", 32);
    let key2 = Blake3::derive_key(context, b"master-secret", 32);
    assert_eq!(key1, key2, "BLAKE3 derive_key should be deterministic");
    assert_eq!(key1.len(), 32, "BLAKE3 derive_key output should be 32 bytes");

    // Different context should produce different output
    let key3 = Blake3::derive_key("different-context", b"master-secret", 32);
    assert_ne!(key1, key3, "Different context should produce different key");
}

// ═══════════════════════════════════════════════════════════════════════════════
// Property Tests
// ═══════════════════════════════════════════════════════════════════════════════

/// Verify output lengths match specification
#[test]
fn hash_output_lengths() {
    assert_eq!(Sha256::hash(b"test").len(), 32, "SHA-256 output should be 32 bytes");
    assert_eq!(Sha384::hash(b"test").len(), 48, "SHA-384 output should be 48 bytes");
    assert_eq!(Sha512::hash(b"test").len(), 64, "SHA-512 output should be 64 bytes");
    assert_eq!(Blake3::hash(b"test").len(), 32, "BLAKE3 output should be 32 bytes");
}

/// Verify determinism: same input produces same output
#[test]
fn hash_determinism() {
    let message = b"The quick brown fox jumps over the lazy dog";

    assert_eq!(Sha256::hash(message), Sha256::hash(message), "SHA-256 should be deterministic");
    assert_eq!(Sha512::hash(message), Sha512::hash(message), "SHA-512 should be deterministic");
    assert_eq!(Blake3::hash(message), Blake3::hash(message), "BLAKE3 should be deterministic");
}

/// Verify avalanche: small change produces different hash
#[test]
fn hash_avalanche() {
    let msg1 = b"The quick brown fox jumps over the lazy dog";
    let msg2 = b"The quick brown fox jumps over the lazy cog";  // 'd' -> 'c'

    assert_ne!(Sha256::hash(msg1), Sha256::hash(msg2), "Different messages should produce different SHA-256 hashes");
    assert_ne!(Sha512::hash(msg1), Sha512::hash(msg2), "Different messages should produce different SHA-512 hashes");
    assert_ne!(Blake3::hash(msg1), Blake3::hash(msg2), "Different messages should produce different BLAKE3 hashes");
}
