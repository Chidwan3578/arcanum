#![no_main]

use arcanum_pqc::kem::{MlKem768, MlKem768EncapsulationKey, MlKem768DecapsulationKey};
use arcanum_pqc::KeyEncapsulation;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Generate a fresh keypair for testing (returns (dk, ek))
    let (dk, ek) = MlKem768::generate_keypair();

    // Test encapsulation/decapsulation roundtrip
    let (ct, ss1) = MlKem768::encapsulate(&ek);
    let ss2 = MlKem768::decapsulate(&dk, &ct);
    assert!(ss2.is_ok());
    assert_eq!(ss1.as_bytes(), ss2.unwrap().as_bytes());

    // Test decapsulation with fuzzed ciphertext (should fail gracefully or produce different secret)
    if data.len() >= 1088 {
        // ML-KEM-768 ciphertext is 1088 bytes
        if let Ok(ct_fuzzed) = arcanum_pqc::kem::MlKem768Ciphertext::from_bytes(&data[..1088]) {
            // Decapsulation should not panic, may produce "implicit reject" secret
            let _ = MlKem768::decapsulate(&dk, &ct_fuzzed);
        }
    }

    // Test key serialization roundtrips
    let ek_bytes = ek.to_bytes();
    let ek_restored = MlKem768EncapsulationKey::from_bytes(&ek_bytes);
    assert!(ek_restored.is_ok());

    let dk_bytes = dk.to_bytes();
    let dk_restored = MlKem768DecapsulationKey::from_bytes(&dk_bytes);
    assert!(dk_restored.is_ok());

    // Test parsing arbitrary bytes as keys (should fail gracefully for wrong sizes)
    if data.len() >= 32 {
        let _ = MlKem768EncapsulationKey::from_bytes(data);
        let _ = MlKem768DecapsulationKey::from_bytes(data);
    }
});
