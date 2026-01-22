#![no_main]

use arcanum_hash::{Blake3, Hasher};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Test oneshot hashing
    let mut hasher1 = Blake3::new();
    hasher1.update(data);
    let hash1 = hasher1.finalize();

    // Test incremental hashing produces same result
    let mut hasher2 = Blake3::new();
    hasher2.update(data);
    let hash2 = hasher2.finalize();
    assert_eq!(hash1.as_ref(), hash2.as_ref());

    // Test incremental with chunked input
    let mut hasher3 = Blake3::new();
    for chunk in data.chunks(17) {
        hasher3.update(chunk);
    }
    let hash3 = hasher3.finalize();
    assert_eq!(hash1.as_ref(), hash3.as_ref());

    // Test keyed hashing if we have enough data
    if data.len() >= 32 {
        let key: [u8; 32] = data[..32].try_into().unwrap();
        let message = &data[32..];

        let keyed1 = Blake3::keyed_hash(&key, message);

        let mut hasher = Blake3::new_keyed(&key);
        hasher.update(message);
        let keyed2 = hasher.finalize();
        assert_eq!(keyed1.as_ref(), keyed2.as_ref());
    }

    // Test derive_key
    if !data.is_empty() {
        let context = "arcanum-fuzz test context";
        let _ = Blake3::derive_key(context, data, 32);
    }
});
