//! # Secure Channel Example
//!
//! Demonstrates establishing an encrypted communication channel between
//! two parties using the arcanum-protocols crate.
//!
//! ## Features
//!
//! - Key exchange using X25519
//! - Session key derivation with HKDF
//! - Bidirectional encryption with sequence numbers
//! - Replay protection via sliding window
//!
//! ## Workflow
//!
//! 1. Both parties generate ephemeral key pairs
//! 2. Perform authenticated key exchange
//! 3. Derive separate encryption/decryption keys
//! 4. Exchange encrypted messages with replay protection

use arcanum_protocols::prelude::*;

fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    println!("=== Secure Channel Demo ===\n");

    // Alice initiates the channel
    println!("Alice: Generating ephemeral keys...");
    let (alice_secret, alice_public) = KeyExchangeProtocol::generate_keypair();
    println!("Alice public key: {}...\n", &alice_public.to_hex()[..16]);

    // Bob responds
    println!("Bob: Generating ephemeral keys...");
    let (bob_secret, bob_public) = KeyExchangeProtocol::generate_keypair();
    println!("Bob public key: {}...\n", &bob_public.to_hex()[..16]);

    // Both derive shared secrets
    println!("Performing X25519 key exchange...");
    let alice_shared = KeyExchangeProtocol::derive_shared_secret(&alice_secret, &bob_public)?;
    let bob_shared = KeyExchangeProtocol::derive_shared_secret(&bob_secret, &alice_public)?;

    // Verify they match
    assert_eq!(alice_shared.expose(), bob_shared.expose());
    println!("Shared secret established!\n");

    // Derive session keys (with roles for bidirectional communication)
    println!("Deriving session keys...");
    let alice_keys = SessionKeys::derive_with_roles(&alice_shared, b"secure-channel-v1", true)?;
    let bob_keys = SessionKeys::derive_with_roles(&bob_shared, b"secure-channel-v1", false)?;
    println!("Alice encryption key: {}...", hex::encode(&alice_keys.encryption_key()[..8]));
    println!("Alice decryption key: {}...", hex::encode(&alice_keys.decryption_key()[..8]));
    println!("Bob encryption key:   {}...", hex::encode(&bob_keys.encryption_key()[..8]));
    println!("Bob decryption key:   {}...\n", hex::encode(&bob_keys.decryption_key()[..8]));

    // Verify role-based keys are properly crossed
    assert_eq!(alice_keys.encryption_key(), bob_keys.decryption_key());
    assert_eq!(alice_keys.decryption_key(), bob_keys.encryption_key());
    println!("Key derivation verified: Alice's send = Bob's receive\n");

    // Create secure channels
    let alice_channel = SecureChannel::new(alice_keys);
    let bob_channel = SecureChannel::new(bob_keys);
    println!("Secure channels created!\n");

    // Alice sends messages to Bob
    println!("--- Communication ---\n");

    let messages = [
        "Hello Bob! This is message 1.",
        "How are you today?",
        "This channel is encrypted and authenticated!",
    ];

    for (i, msg) in messages.iter().enumerate() {
        // Alice encrypts
        let encrypted = alice_channel.encrypt(msg.as_bytes())?;
        println!("Alice -> [{:>3} bytes encrypted]", encrypted.ciphertext.len());

        // Bob decrypts
        let plaintext = bob_channel.decrypt(&encrypted)?;
        println!("Bob   <- \"{}\"", String::from_utf8_lossy(&plaintext));

        if i < messages.len() - 1 {
            println!();
        }
    }

    println!("\n--- Bidirectional ---\n");

    // Bob replies
    let reply = "I'm doing great, Alice! Nice secure channel.";
    let bob_encrypted = bob_channel.encrypt(reply.as_bytes())?;
    println!("Bob   -> [{:>3} bytes encrypted]", bob_encrypted.ciphertext.len());

    let alice_plaintext = alice_channel.decrypt(&bob_encrypted)?;
    println!("Alice <- \"{}\"", String::from_utf8_lossy(&alice_plaintext));

    println!("\n--- Security Features ---\n");
    println!("The channel automatically provides:");
    println!("  - Sequence numbers (prevents replay attacks)");
    println!("  - Authenticated encryption (detects tampering)");
    println!("  - Separate send/receive keys (prevents reflection)");

    println!("\n=== Channel established and tested successfully! ===");
    Ok(())
}
