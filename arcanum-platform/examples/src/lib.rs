//! # Arcanum Integration Examples
//!
//! This crate contains examples demonstrating cross-crate integration
//! patterns for the Arcanum cryptographic platform.
//!
//! ## Available Examples
//!
//! Run any example with: `cargo run --example <name>`
//!
//! - **hybrid_encryption**: X25519 + AES-256-GCM for secure messaging
//! - **sign_then_encrypt**: Ed25519 signatures + ChaCha20-Poly1305
//! - **password_encryption**: Argon2 key derivation + AES encryption
//! - **secure_channel**: Full bidirectional encrypted channel
//! - **post_quantum_hybrid**: ML-KEM-768 + X25519 quantum-resistant encryption
//!
//! ## Quick Start
//!
//! ```bash
//! # Run the hybrid encryption example
//! cargo run --example hybrid_encryption
//!
//! # Run all examples
//! for ex in hybrid_encryption sign_then_encrypt password_encryption \
//!           secure_channel post_quantum_hybrid; do
//!     cargo run --example $ex
//! done
//! ```
