#![no_main]

use libfuzzer_sys::fuzz_target;
use arcanum_core::encoding::{Hex, Base64, Base32};

fuzz_target!(|data: &[u8]| {
    // Test hex round-trip
    let hex = Hex::encode(data);
    if let Ok(decoded) = Hex::decode(&hex) {
        assert_eq!(data, decoded.as_slice(), "hex round-trip failed");
    }

    // Test base64 round-trip
    let b64 = Base64::encode(data);
    if let Ok(decoded) = Base64::decode(&b64) {
        assert_eq!(data, decoded.as_slice(), "base64 round-trip failed");
    }

    // Test base32 round-trip
    let b32 = Base32::encode(data);
    if let Ok(decoded) = Base32::decode(&b32) {
        assert_eq!(data, decoded.as_slice(), "base32 round-trip failed");
    }

    // Test decoding arbitrary strings (should not panic)
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = Hex::decode(s);
        let _ = Base64::decode(s);
        let _ = Base32::decode(s);
    }
});
