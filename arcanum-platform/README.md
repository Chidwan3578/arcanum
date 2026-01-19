# Arcanum Platform

> A comprehensive Rust cryptography library for the [Persona Framework](https://github.com/Daemoniorum-LLC/persona-framework) ecosystem

## Overview

Arcanum is a modular cryptographic library providing:

- **Symmetric Encryption**: AES-GCM, ChaCha20-Poly1305, and more
- **Asymmetric Cryptography**: RSA, ECIES, X25519, ECDH
- **Digital Signatures**: Ed25519, ECDSA, Schnorr
- **Hash Functions**: SHA-2, SHA-3, Blake2, Blake3
- **Post-Quantum Cryptography**: ML-KEM, ML-DSA (NIST FIPS 203/204)
- **Zero-Knowledge Proofs**: Bulletproofs, Schnorr proofs, Pedersen commitments
- **Key Storage**: In-memory, file-based, and encrypted keystores
- **Secure Protocols**: Key exchange, session management, encrypted channels
- **Format Support**: PEM, Base64, Hex encoding

## Quick Start

Add the crates you need to your `Cargo.toml`:

```toml
[dependencies]
arcanum-symmetric = "0.1"
arcanum-signatures = "0.1"
arcanum-hash = "0.1"
```

### Symmetric Encryption (AES-256-GCM)

```rust
use arcanum_symmetric::prelude::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate key and nonce
    let key = Aes256Gcm::generate_key();
    let nonce = Aes256Gcm::generate_nonce();

    // Encrypt
    let plaintext = b"Secret message";
    let ciphertext = Aes256Gcm::encrypt(&key, &nonce, plaintext, None)?;

    // Decrypt
    let decrypted = Aes256Gcm::decrypt(&key, &nonce, &ciphertext, None)?;
    assert_eq!(decrypted, plaintext);

    Ok(())
}
```

### Digital Signatures (Ed25519)

```rust
use arcanum_signatures::prelude::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate keypair
    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();

    // Sign a message
    let message = b"Hello, Arcanum!";
    let signature = signing_key.sign(message);

    // Verify
    verifying_key.verify(message, &signature)?;
    println!("Signature verified!");

    Ok(())
}
```

### Password Hashing (Argon2)

```rust
use arcanum_hash::prelude::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let password = b"secure-password";
    let params = Argon2Params::default();

    // Hash password for storage
    let hash = Argon2::hash_password(password, &params)?;

    // Verify password
    assert!(Argon2::verify_password(password, &hash)?);

    Ok(())
}
```

### Key Exchange (X25519)

```rust
use arcanum_protocols::prelude::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Alice and Bob generate keypairs
    let (alice_secret, alice_public) = KeyExchangeProtocol::generate_keypair();
    let (bob_secret, bob_public) = KeyExchangeProtocol::generate_keypair();

    // Both derive the same shared secret
    let alice_shared = KeyExchangeProtocol::derive_shared_secret(&alice_secret, &bob_public)?;
    let bob_shared = KeyExchangeProtocol::derive_shared_secret(&bob_secret, &alice_public)?;

    // Derive session keys for encrypted communication
    let alice_keys = SessionKeys::derive(&alice_shared, b"my-app-v1")?;
    let bob_keys = SessionKeys::derive(&bob_shared, b"my-app-v1")?;

    Ok(())
}
```

## Which Algorithm Should I Use?

| Task | Recommended | Why |
|------|-------------|-----|
| **Encrypt data** | `Aes256Gcm` | Fast, hardware-accelerated, authenticated |
| **Encrypt (no AES-NI)** | `ChaCha20Poly1305` | Constant-time on all platforms |
| **Hash data** | `Sha256` or `Blake3` | SHA-256 for compatibility, Blake3 for speed |
| **Hash passwords** | `Argon2` | PHC winner, memory-hard |
| **Sign messages** | `Ed25519` | Fast, small signatures, secure |
| **Key exchange** | `X25519` | Fast ECDH, simple API |
| **Post-quantum KEM** | `MlKem768` | NIST standard, good security/size balance |
| **Post-quantum sigs** | `MlDsa65` | NIST standard, medium security |

> **See [ARCHITECTURE.md](./ARCHITECTURE.md)** for detailed algorithm selection guides, common workflows, and security best practices.

## Crates

| Crate | Description |
|-------|-------------|
| `arcanum-core` | Core traits, types, and error handling |
| `arcanum-symmetric` | Symmetric encryption (AES-GCM, ChaCha20-Poly1305) |
| `arcanum-asymmetric` | Asymmetric crypto (RSA, ECIES, X25519, ECDH) |
| `arcanum-signatures` | Digital signatures (Ed25519, ECDSA, Schnorr) |
| `arcanum-hash` | Hash functions and KDFs (SHA, Blake, Argon2, HKDF) |
| `arcanum-pqc` | Post-quantum cryptography (ML-KEM, ML-DSA) |
| `arcanum-zkp` | Zero-knowledge proofs (Bulletproofs, Schnorr) |
| `arcanum-keystore` | Secure key storage backends |
| `arcanum-protocols` | Cryptographic protocols (key exchange, channels) |
| `arcanum-formats` | Data format encoding (PEM, Base64, Hex) |

## Design Principles

1. **Memory Safety**: All sensitive data zeroized on drop via `zeroize`
2. **Type Safety**: Distinct types prevent mixing incompatible keys
3. **Constant Time**: Side-channel resistant operations using `subtle`
4. **Fail Secure**: Errors don't leak sensitive information
5. **No Unsafe Code**: `#![deny(unsafe_code)]` across all crates

## Security Features

- **Automatic Zeroization**: Secret keys are wiped from memory when dropped
- **Constant-Time Operations**: Comparisons use constant-time algorithms
- **Nonce Validation**: Encryption functions validate nonce length
- **Replay Protection**: Secure channels include sequence numbers
- **Key Expiration**: Keystore supports key lifecycle management

## Building

```bash
# Build all crates
cargo build --workspace

# Run tests
cargo test --workspace

# Build with release optimizations
cargo build --workspace --release
```

## Requirements

- Rust 1.85+ (install via [rustup](https://rustup.rs/))

## Project Structure

```
crates/
├── arcanum-core/        # Core traits and types
├── arcanum-symmetric/   # Symmetric encryption
├── arcanum-asymmetric/  # Asymmetric cryptography
├── arcanum-signatures/  # Digital signatures
├── arcanum-hash/        # Hash functions and KDFs
├── arcanum-pqc/         # Post-quantum cryptography
├── arcanum-zkp/         # Zero-knowledge proofs
├── arcanum-keystore/    # Key storage backends
├── arcanum-protocols/   # Cryptographic protocols
└── arcanum-formats/     # Format encoding
```

## License

MIT OR Apache-2.0

## Part of Daemoniorum LLC

This project is maintained by Daemoniorum LLC as part of the Persona Framework ecosystem.

---

Repository extracted from the [persona-framework monorepo](https://github.com/Daemoniorum-LLC/persona-framework).
