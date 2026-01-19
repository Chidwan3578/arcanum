//! # Password-Based Encryption Example
//!
//! Demonstrates secure file encryption using a password-derived key.
//! Uses Argon2id for key derivation and AES-256-GCM for encryption.
//!
//! ## Security Features
//!
//! - **Argon2id**: Memory-hard KDF resistant to GPU/ASIC attacks
//! - **Random salt**: Prevents rainbow table attacks
//! - **Random nonce**: Ensures ciphertext uniqueness
//! - **AEAD**: Authenticated encryption prevents tampering
//!
//! ## Storage Format
//!
//! | Salt (32 bytes) | Nonce (12 bytes) | Ciphertext (variable) |

use arcanum_hash::{Argon2, Argon2Params};
use arcanum_hash::PasswordHash;
use arcanum_symmetric::prelude::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Password-Based Encryption Demo ===\n");

    // User's password
    let password = b"my-super-secret-password-2024!";
    println!("Password: \"{}\" ({} chars)\n",
             String::from_utf8_lossy(password), password.len());

    // Generate random salt (store with ciphertext)
    let salt: [u8; 32] = rand::random();
    println!("Salt (random): {}...", hex::encode(&salt[..16]));

    // Derive encryption key using Argon2id
    let params = Argon2Params::default();
    println!("Argon2id params: m={} KiB, t={}, p={}",
             params.memory_cost / 1024, params.time_cost, params.parallelism);

    let derived_key = Argon2::derive_key(password, &salt, &params, 32)?;
    println!("Derived key: {}... ({} bytes)\n",
             hex::encode(&derived_key[..8]), derived_key.len());

    // Prepare plaintext (simulating a file)
    let plaintext = b"This is my secret diary entry for December 2025.\n\
                     Today I learned about password-based encryption.\n\
                     The Argon2 algorithm makes brute-forcing very expensive!";
    println!("Plaintext: {} bytes", plaintext.len());

    // Encrypt with AES-256-GCM
    let nonce = Aes256Gcm::generate_nonce();
    let key: [u8; 32] = derived_key.try_into().expect("key should be 32 bytes");
    let ciphertext = Aes256Gcm::encrypt(&key, &nonce, plaintext, None)?;
    println!("Ciphertext: {} bytes", ciphertext.len());

    // Build the storage format: salt || nonce || ciphertext
    let mut encrypted_file = Vec::new();
    encrypted_file.extend_from_slice(&salt);
    encrypted_file.extend_from_slice(&nonce);
    encrypted_file.extend_from_slice(&ciphertext);
    println!("Total encrypted size: {} bytes\n", encrypted_file.len());
    println!("Overhead: {} bytes (salt + nonce + auth tag)\n",
             encrypted_file.len() - plaintext.len());

    // --- Storage/transmission happens here ---
    println!("--- File stored/transmitted ---\n");

    // Later: Decrypt with the same password
    println!("Decrypting with password...\n");

    // Parse the encrypted file format
    let recovered_salt: [u8; 32] = encrypted_file[..32].try_into()?;
    let recovered_nonce: [u8; 12] = encrypted_file[32..44].try_into()?;
    let recovered_ciphertext = &encrypted_file[44..];

    // Re-derive the key from password
    let redirived_key = Argon2::derive_key(password, &recovered_salt, &params, 32)?;
    let rekey: [u8; 32] = redirived_key.try_into().expect("key should be 32 bytes");

    // Decrypt
    let decrypted = Aes256Gcm::decrypt(&rekey, &recovered_nonce, recovered_ciphertext, None)?;

    println!("Decrypted successfully!");
    println!("---");
    println!("{}", String::from_utf8_lossy(&decrypted));
    println!("---");

    // Verify
    assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    println!("\n=== Decryption verified! ===");

    // Demonstrate wrong password fails
    println!("\nTrying wrong password...");
    let wrong_key = Argon2::derive_key(b"wrong-password", &recovered_salt, &params, 32)?;
    let wrong_key: [u8; 32] = wrong_key.try_into().expect("key should be 32 bytes");

    match Aes256Gcm::decrypt(&wrong_key, &recovered_nonce, recovered_ciphertext, None) {
        Ok(_) => println!("ERROR: Wrong password succeeded (this shouldn't happen!)"),
        Err(_) => println!("Correctly rejected wrong password (authentication failed)"),
    }

    Ok(())
}
