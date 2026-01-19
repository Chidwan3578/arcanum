#![no_main]

use libfuzzer_sys::fuzz_target;
use arcanum_core::key::{SecretKey, PublicKey};

fuzz_target!(|data: &[u8]| {
    // Test SecretKey from slice (various sizes)
    // These should not panic on invalid input
    let _ = SecretKey::<32>::from_slice(data);
    let _ = SecretKey::<16>::from_slice(data);
    let _ = SecretKey::<64>::from_slice(data);

    // Test PublicKey from slice
    let _ = PublicKey::<32>::from_slice(data);
    let _ = PublicKey::<33>::from_slice(data);
    let _ = PublicKey::<65>::from_slice(data);

    // Test valid key size operations
    if data.len() == 32 {
        if let Ok(pk) = PublicKey::<32>::from_slice(data) {
            // Verify as_bytes returns correct data
            assert_eq!(pk.as_bytes().len(), 32);
        }
    }
});
