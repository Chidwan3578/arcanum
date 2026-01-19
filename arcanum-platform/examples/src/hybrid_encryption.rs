//! # Hybrid Encryption Example
//!
//! Demonstrates combining X25519 key exchange with AES-256-GCM encryption
//! for secure message exchange between two parties.
//!
//! ## Workflow
//!
//! 1. Alice and Bob each generate X25519 key pairs
//! 2. They exchange public keys (out of band)
//! 3. Both derive the same shared secret using ECDH
//! 4. The shared secret is used with HKDF to derive an AES key
//! 5. Messages are encrypted/decrypted using AES-256-GCM

use arcanum_asymmetric::x25519::X25519SecretKey;
use arcanum_symmetric::prelude::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Hybrid Encryption Demo ===\n");

    // Alice generates her key pair
    let alice_secret = X25519SecretKey::generate();
    let alice_public = alice_secret.public_key();
    println!("Alice's public key: {}", alice_public.to_hex());

    // Bob generates his key pair
    let bob_secret = X25519SecretKey::generate();
    let bob_public = bob_secret.public_key();
    println!("Bob's public key:   {}\n", bob_public.to_hex());

    // Both compute the shared secret (ECDH)
    let alice_shared = alice_secret.derive_shared_secret(&bob_public);
    let bob_shared = bob_secret.derive_shared_secret(&alice_public);

    // Verify they got the same shared secret
    assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
    println!("Shared secret derived successfully (32 bytes)\n");

    // Derive encryption key using HKDF
    let encryption_key = alice_shared.derive_key(b"arcanum-hybrid-encryption-v1", 32)?;
    println!("Encryption key derived via HKDF\n");

    // Create the cipher key
    let key: [u8; 32] = encryption_key.try_into().expect("key should be 32 bytes");

    // Alice encrypts a message to Bob
    let nonce = Aes256Gcm::generate_nonce();
    let plaintext = b"Hello Bob! This is a secret message from Alice.";

    let ciphertext = Aes256Gcm::encrypt(&key, &nonce, plaintext, None)?;
    println!("Alice encrypted: \"{}\"", String::from_utf8_lossy(plaintext));
    println!("Ciphertext (hex): {}...\n", hex::encode(&ciphertext[..16]));

    // Bob decrypts the message (using his derived key, which is the same)
    let bob_key = bob_shared.derive_key(b"arcanum-hybrid-encryption-v1", 32)?;
    let bob_key: [u8; 32] = bob_key.try_into().expect("key should be 32 bytes");

    let decrypted = Aes256Gcm::decrypt(&bob_key, &nonce, &ciphertext, None)?;
    println!("Bob decrypted:   \"{}\"", String::from_utf8_lossy(&decrypted));

    // Verify decryption worked
    assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    println!("\n=== Success! Messages match ===");

    Ok(())
}
