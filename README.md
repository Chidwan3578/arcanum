# Arcanum

Cryptographic library for Rust with unified interfaces across classical and post-quantum algorithms.

See [BENCHMARK_REPORT.md](BENCHMARK_REPORT.md) for performance data.

## Architecture

```
arcanum/
├── crates/
│   ├── arcanum-core        # Core traits, types, secure memory
│   ├── arcanum-primitives  # Native cryptographic primitives (zero-dependency)
│   ├── arcanum-symmetric   # AES-GCM, ChaCha20-Poly1305, XChaCha20
│   ├── arcanum-signatures  # Ed25519, ECDSA, Schnorr
│   ├── arcanum-hash        # SHA-2/3, Blake2/3, KDFs (Argon2, HKDF)
│   ├── arcanum-asymmetric  # RSA, ECIES, X25519, X448
│   ├── arcanum-pqc         # ML-KEM, ML-DSA, hybrid schemes
│   ├── arcanum-zkp         # Zero-knowledge proofs
│   ├── arcanum-keystore    # Key management, HSM, TPM
│   ├── arcanum-protocols   # Noise, Double Ratchet
│   └── arcanum-formats     # X.509, JWE/JWS, OpenPGP
```

## Features

### Symmetric Encryption
- **AES-256-GCM**: AEAD with optional hardware acceleration
- **AES-256-GCM-SIV**: Nonce-misuse resistant variant
- **ChaCha20-Poly1305**: Constant-time software implementation
- **XChaCha20-Poly1305**: Extended 192-bit nonce variant

### Digital Signatures
- **Ed25519**: Fast, secure, deterministic (recommended default)
- **ECDSA**: P-256, P-384, secp256k1 curves
- **Schnorr**: BIP-340 compatible (Bitcoin Taproot)

### Hash Functions & KDFs
- **SHA-2**: SHA-256, SHA-384, SHA-512
- **SHA-3**: SHA3-256, SHA3-512, SHAKE
- **Blake2/3**: High-performance hashing
- **Argon2id**: Password hashing (winner of PHC)
- **HKDF**: Key derivation (RFC 5869)

### Post-Quantum Cryptography
- **ML-KEM** (CRYSTALS-Kyber): NIST-standardized KEM
- **ML-DSA** (CRYSTALS-Dilithium): NIST-standardized signatures
- **SLH-DSA** (SPHINCS+): Hash-based signatures
- **Hybrid schemes**: Classical + PQ for defense in depth

### Advanced Features
- Zero-knowledge proofs (Bulletproofs, Groth16)
- Threshold signatures (FROST)
- Secret sharing (Shamir's)
- Secure protocols (Noise Framework, Double Ratchet)

### Batch and Fused APIs

**Batch Processing** - Process multiple independent inputs in parallel:
```rust
use arcanum_primitives::batch::{BatchSha256x4, merkle_root_sha256};

// Hash 4 messages simultaneously (SIMD-ready)
let hashes = BatchSha256x4::hash_parallel([msg1, msg2, msg3, msg4]);

// Batch-optimized Merkle tree
let root = merkle_root_sha256(&leaves);
```

**Fused Operations** - Single-pass encrypt+authenticate for cache efficiency:
```rust
use arcanum_primitives::fused::FusedChaCha20Poly1305;

// Encrypt and MAC in one pass (30-50% fewer cache misses on large messages)
let cipher = FusedChaCha20Poly1305::new(&key);
let tag = cipher.encrypt(&nonce, aad, &mut buffer);
```

## Design Principles

1. **Memory Safety**: All sensitive data zeroized on drop
2. **Type Safety**: Distinct types prevent mixing incompatible keys
3. **Constant Time**: Side-channel resistant operations by default
4. **Fail Secure**: Errors don't leak sensitive information
5. **Composability**: Traits enable algorithm-agnostic code

## Quick Start

```rust
use arcanum_symmetric::prelude::*;
use arcanum_signatures::prelude::*;

// Symmetric encryption
let key = Aes256Gcm::generate_key();
let nonce = Aes256Gcm::generate_nonce();
let ciphertext = Aes256Gcm::encrypt(&key, &nonce, b"secret", None)?;

// Digital signatures
let signing_key = Ed25519SigningKey::generate();
let signature = signing_key.sign(b"message");
signing_key.verifying_key().verify(b"message", &signature)?;
```

## Backend Architecture

Arcanum supports multiple cryptographic backends through a unified interface:

### Native Backend (`arcanum-primitives`)

Pure-Rust implementations with zero RustCrypto dependencies:

| Algorithm | Status | SIMD |
|-----------|--------|------|
| SHA-256/384/512 | Complete | Planned |
| BLAKE3 | Complete | Built-in |
| ChaCha20 | Complete | AVX2/SSE2 |
| Poly1305 | Complete | Batched (4-way) |
| ChaCha20-Poly1305 | Complete | AVX2/SSE2 |
| XChaCha20-Poly1305 | Complete | AVX2/SSE2 |
| **Batch SHA-256** | Complete | Planned (AVX2) |
| **Fused ChaCha20-Poly1305** | Complete | Planned |
| **Merkle Tree** | Complete | Uses Batch SHA-256 |

**Performance (ChaCha20-Poly1305, 4KB blocks):**
- Native + AVX2: ~1,200 MiB/s
- Native + SSE2: ~965 MiB/s
- Native (portable): ~352 MiB/s
- RustCrypto: ~1,940 MiB/s

Enable native backend:
```toml
[dependencies]
arcanum-hash = { version = "0.1", features = ["native"] }
arcanum-symmetric = { version = "0.1", features = ["native"] }
```

### RustCrypto Backend (default)

Production-ready, audited implementations from the RustCrypto project.

## Security

- Built on audited cryptographic libraries (RustCrypto)
- Native backend validated against NIST test vectors
- Follows NIST, IETF, and industry best practices
- Comprehensive test coverage including Wycheproof vectors
- Designed for side-channel resistance

## License

MIT OR Apache-2.0
