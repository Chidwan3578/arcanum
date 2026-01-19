#![no_main]

use libfuzzer_sys::fuzz_target;
use arcanum_hash::{Sha256, Sha512, Blake3, Hasher};

fuzz_target!(|data: &[u8]| {
    // Limit input size to avoid slow tests
    if data.len() > 10 * 1024 * 1024 {
        return;
    }

    // Test all hash algorithms produce consistent output

    // SHA-256
    let hash1 = Sha256::hash(data);
    let hash2 = Sha256::hash(data);
    assert_eq!(hash1, hash2, "SHA-256 not deterministic");
    assert_eq!(hash1.len(), 32);

    // SHA-512
    let hash1 = Sha512::hash(data);
    let hash2 = Sha512::hash(data);
    assert_eq!(hash1, hash2, "SHA-512 not deterministic");
    assert_eq!(hash1.len(), 64);

    // BLAKE3 using the trait's hash method
    let hash1 = <Blake3 as Hasher>::hash(data);
    let hash2 = <Blake3 as Hasher>::hash(data);
    assert_eq!(hash1, hash2, "BLAKE3 not deterministic");
    assert_eq!(hash1.len(), 32);

    // Test incremental hashing matches one-shot
    let mut hasher = Sha256::new();
    for chunk in data.chunks(64) {
        hasher.update(chunk);
    }
    let incremental = hasher.finalize();
    let direct = Sha256::hash(data);
    assert_eq!(incremental, direct, "Incremental hash mismatch");
});
