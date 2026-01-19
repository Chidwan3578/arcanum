#![no_main]

use libfuzzer_sys::fuzz_target;
use arcanum_core::nonce::{Nonce, NonceGenerator};

fuzz_target!(|data: &[u8]| {
    // Test Nonce from slice (various sizes)
    // These should return Err for wrong sizes, not panic
    let _ = Nonce::<12>::from_slice(data);
    let _ = Nonce::<16>::from_slice(data);
    let _ = Nonce::<24>::from_slice(data);

    // Test nonce increment doesn't panic or overflow unsafely
    if data.len() >= 12 {
        if let Ok(mut nonce) = Nonce::<12>::from_slice(&data[..12]) {
            // Should handle increment gracefully
            for _ in 0..100 {
                nonce.increment();
            }
            // Verify nonce is still valid
            assert_eq!(nonce.as_bytes().len(), 12);
        }
    }

    // Test NonceGenerator counter mode
    if data.len() >= 8 {
        let bytes: [u8; 8] = data[..8].try_into().unwrap();
        let start = u64::from_le_bytes(bytes);
        let generator = NonceGenerator::<12>::counter(start);

        // Generate several nonces
        for _ in 0..10 {
            if let Ok(nonce) = generator.generate() {
                assert_eq!(nonce.as_bytes().len(), 12);
            }
        }
    }

    // Test random nonce generation
    let generator = NonceGenerator::<12>::random();
    if let (Ok(nonce1), Ok(nonce2)) = (generator.generate(), generator.generate()) {
        assert_eq!(nonce1.as_bytes().len(), 12);
        assert_eq!(nonce2.as_bytes().len(), 12);
        // Random nonces should be different (very high probability)
        assert_ne!(nonce1.as_bytes(), nonce2.as_bytes());
    }
});
