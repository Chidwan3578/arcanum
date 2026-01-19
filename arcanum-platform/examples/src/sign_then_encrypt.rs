//! # Sign-Then-Encrypt Example
//!
//! Demonstrates the secure pattern of signing a message before encrypting it.
//! This ensures both authenticity and confidentiality.
//!
//! ## Why Sign-Then-Encrypt?
//!
//! - The recipient can verify the signature only after decryption
//! - Provides non-repudiation: the sender cannot deny sending the message
//! - The signature is hidden from eavesdroppers
//!
//! ## Workflow
//!
//! 1. Sender signs the plaintext with their Ed25519 private key
//! 2. Sender encrypts (message || signature) with ChaCha20-Poly1305
//! 3. Recipient decrypts to recover message and signature
//! 4. Recipient verifies signature with sender's public key

use arcanum_signatures::ed25519::{Ed25519SigningKey, Ed25519Signature};
use arcanum_signatures::{SigningKey, VerifyingKey, Signature};
use arcanum_symmetric::prelude::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Sign-Then-Encrypt Demo ===\n");

    // Alice (sender) generates signing keys
    let alice_signing_key = Ed25519SigningKey::generate();
    let alice_verifying_key = alice_signing_key.verifying_key();
    println!("Alice's verifying key: {}...", hex::encode(&alice_verifying_key.to_bytes()[..16]));

    // Shared encryption key (in practice, derived via hybrid encryption)
    let encryption_key = ChaCha20Poly1305Cipher::generate_key();
    println!("Shared key established\n");

    // Alice's message
    let message = b"Transfer $1000 to account 12345";
    println!("Original message: \"{}\"\n", String::from_utf8_lossy(message));

    // Step 1: Alice signs the message
    let signature = alice_signing_key.sign(message);
    println!("Signature created ({} bytes)", signature.to_bytes().len());

    // Step 2: Combine message + signature for encryption
    let mut payload = message.to_vec();
    payload.extend_from_slice(&signature.to_bytes());
    println!("Payload prepared: {} bytes (message) + {} bytes (signature)\n",
             message.len(), signature.to_bytes().len());

    // Step 3: Encrypt the combined payload
    let nonce = ChaCha20Poly1305Cipher::generate_nonce();
    let ciphertext = ChaCha20Poly1305Cipher::encrypt(&encryption_key, &nonce, &payload, None)?;
    println!("Encrypted payload: {} bytes", ciphertext.len());
    println!("Ciphertext (hex): {}...\n", hex::encode(&ciphertext[..16]));

    // --- Transmission happens here ---
    println!("--- Message transmitted ---\n");

    // Bob (recipient) decrypts
    let decrypted = ChaCha20Poly1305Cipher::decrypt(&encryption_key, &nonce, &ciphertext, None)?;
    println!("Decrypted payload: {} bytes", decrypted.len());

    // Step 4: Bob extracts message and signature
    let sig_len = 64; // Ed25519 signature is 64 bytes
    let msg_len = decrypted.len() - sig_len;
    let recovered_message = &decrypted[..msg_len];
    let recovered_signature_bytes = &decrypted[msg_len..];

    let recovered_signature = Ed25519Signature::from_bytes(
        recovered_signature_bytes.try_into().expect("signature should be 64 bytes")
    )?;

    println!("Recovered message: \"{}\"", String::from_utf8_lossy(recovered_message));

    // Step 5: Bob verifies Alice's signature
    match alice_verifying_key.verify(recovered_message, &recovered_signature) {
        Ok(()) => {
            println!("\nSignature VERIFIED - message is authentic!");
            println!("Alice cannot deny sending this message (non-repudiation)");
        }
        Err(e) => {
            println!("\nSignature verification FAILED: {:?}", e);
            println!("Message may have been tampered with!");
        }
    }

    println!("\n=== Demo Complete ===");
    Ok(())
}
