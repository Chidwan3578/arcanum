//! # Post-Quantum Hybrid Encryption Example
//!
//! Demonstrates hybrid encryption combining classical X25519 with
//! post-quantum ML-KEM-768 for quantum-resistant key exchange.
//!
//! ## Why Hybrid?
//!
//! - **Defense in depth**: If either algorithm is broken, the other provides security
//! - **Compliance**: Many standards require classical + PQ hybrid during transition
//! - **Performance**: ML-KEM is fast enough for practical use
//!
//! ## Security Level
//!
//! - X25519: ~128-bit classical security
//! - ML-KEM-768: NIST Level 3 (~AES-192 equivalent)
//! - Combined: Secure against both classical and quantum adversaries

use arcanum_asymmetric::x25519::X25519SecretKey;
use arcanum_pqc::MlKem768;
use arcanum_symmetric::prelude::*;
use arcanum_hash::prelude::{HkdfSha256, KeyDerivation};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Post-Quantum Hybrid Encryption Demo ===\n");

    // Bob generates both classical and PQ key pairs (recipient)
    println!("Bob: Generating hybrid key pair...");

    // Classical X25519
    let bob_x25519_secret = X25519SecretKey::generate();
    let bob_x25519_public = bob_x25519_secret.public_key();
    println!("  X25519 public:  {}... (32 bytes)", hex::encode(&bob_x25519_public.to_bytes()[..8]));

    // Post-quantum ML-KEM-768 (returns decapsulation key, encapsulation key as byte vectors)
    let (bob_mlkem_dk, bob_mlkem_ek) = MlKem768::generate_keypair()?;
    println!("  ML-KEM-768 public: {}... ({} bytes)\n",
             hex::encode(&bob_mlkem_ek[..8]),
             bob_mlkem_ek.len());

    // Alice wants to send a message to Bob
    println!("Alice: Encapsulating hybrid key...\n");

    // Classical ECDH
    let alice_x25519_secret = X25519SecretKey::generate();
    let alice_x25519_public = alice_x25519_secret.public_key();
    let x25519_shared = alice_x25519_secret.derive_shared_secret(&bob_x25519_public);
    println!("  X25519 shared:    {}... (32 bytes)", hex::encode(&x25519_shared.as_bytes()[..8]));

    // PQ KEM encapsulation (returns ciphertext and shared secret)
    let (mlkem_ciphertext, mlkem_shared) = MlKem768::encapsulate(&bob_mlkem_ek)?;
    println!("  ML-KEM shared:    {}... (32 bytes)", hex::encode(&mlkem_shared[..8]));
    println!("  ML-KEM ciphertext: {} bytes\n", mlkem_ciphertext.len());

    // Combine shared secrets using HKDF
    let mut combined_ikm = Vec::with_capacity(64);
    combined_ikm.extend_from_slice(x25519_shared.as_bytes());
    combined_ikm.extend_from_slice(&mlkem_shared);

    let hybrid_key = HkdfSha256::derive(&combined_ikm, None, Some(b"pq-hybrid-v1"), 32)?;
    println!("Alice: Hybrid key derived: {}...\n", hex::encode(&hybrid_key[..8]));

    // Encrypt the message
    let message = b"This message is protected against quantum computers!";
    let nonce = Aes256Gcm::generate_nonce();
    let key: [u8; 32] = hybrid_key.clone().try_into().expect("key should be 32 bytes");
    let ciphertext = Aes256Gcm::encrypt(&key, &nonce, message, None)?;

    println!("Alice: Message encrypted: \"{}\"\n", String::from_utf8_lossy(message));

    // Alice sends to Bob:
    // - Her X25519 public key
    // - ML-KEM ciphertext
    // - Nonce
    // - Ciphertext
    println!("--- Transmission ---");
    println!("  Alice X25519 pub: 32 bytes");
    println!("  ML-KEM ciphertext: {} bytes", mlkem_ciphertext.len());
    println!("  Nonce: 12 bytes");
    println!("  Ciphertext: {} bytes", ciphertext.len());
    println!("  Total overhead: {} bytes\n",
             32 + mlkem_ciphertext.len() + 12 + 16); // 16 = auth tag

    // Bob decrypts
    println!("Bob: Decapsulating hybrid key...\n");

    // Classical ECDH
    let bob_x25519_shared = bob_x25519_secret.derive_shared_secret(&alice_x25519_public);
    println!("  X25519 shared:    {}...", hex::encode(&bob_x25519_shared.as_bytes()[..8]));

    // PQ KEM decapsulation
    let bob_mlkem_shared = MlKem768::decapsulate(&bob_mlkem_dk, &mlkem_ciphertext)?;
    println!("  ML-KEM shared:    {}...", hex::encode(&bob_mlkem_shared[..8]));

    // Combine and derive
    let mut bob_combined = Vec::with_capacity(64);
    bob_combined.extend_from_slice(bob_x25519_shared.as_bytes());
    bob_combined.extend_from_slice(&bob_mlkem_shared);

    let bob_hybrid_key = HkdfSha256::derive(&bob_combined, None, Some(b"pq-hybrid-v1"), 32)?;
    println!("\nBob: Hybrid key derived: {}...", hex::encode(&bob_hybrid_key[..8]));

    // Verify keys match
    assert_eq!(hybrid_key, bob_hybrid_key);
    println!("Bob: Keys match!\n");

    // Decrypt
    let bob_key: [u8; 32] = bob_hybrid_key.try_into().expect("key should be 32 bytes");
    let decrypted = Aes256Gcm::decrypt(&bob_key, &nonce, &ciphertext, None)?;

    println!("Bob: Decrypted: \"{}\"", String::from_utf8_lossy(&decrypted));

    // Verify
    assert_eq!(message.as_slice(), decrypted.as_slice());

    println!("\n=== Quantum-resistant encryption successful! ===");
    println!("\nSecurity: Even a quantum computer cannot break this encryption");
    println!("          (would need to break BOTH X25519 AND ML-KEM-768)");

    Ok(())
}
