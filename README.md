# Arcanum

Cryptographic library for Rust with unified interfaces across classical and post-quantum algorithms.

See [BENCHMARK_REPORT.md](BENCHMARK_REPORT.md) for detailed performance data.

See [docs/DESIGN_NOTES.md](docs/DESIGN_NOTES.md) for the *why* behind architectural decisions.

## Architecture

```
arcanum/
├── crates/
│   ├── arcanum-core        # Core traits, types, secure memory
│   ├── arcanum-primitives  # Native SIMD-optimized primitives
│   ├── arcanum-symmetric   # AES-GCM, ChaCha20-Poly1305, XChaCha20
│   ├── arcanum-asymmetric  # RSA, ECIES, X25519, X448
│   ├── arcanum-signatures  # Ed25519, ECDSA, Schnorr
│   ├── arcanum-hash        # SHA-2/3, Blake2/3, KDFs (Argon2, HKDF)
│   ├── arcanum-pqc         # ML-KEM, ML-DSA, SLH-DSA, hybrid schemes
│   ├── arcanum-zkp         # Zero-knowledge proofs (Bulletproofs)
│   ├── arcanum-threshold   # Shamir, Feldman VSS, FROST
│   ├── arcanum-agile       # Algorithm versioning and migration
│   ├── arcanum-verify      # Timing analysis, side-channel detection
│   └── arcanum-holocrypt   # Composable multi-layer cryptography
```

## Design Philosophy

Arcanum complements the excellent Rust cryptography ecosystem by providing:

- **Batch APIs** for efficiently processing multiple items
- **SIMD optimizations** for throughput-critical paths
- **Post-quantum algorithms** (ML-KEM, ML-DSA, SLH-DSA)
- **Unified interfaces** across classical and PQC algorithms

It works alongside libraries like RustCrypto and the blake3 crate, providing the right tool for each use case.

## Feature Flags

### arcanum-primitives

```toml
[dependencies]
arcanum-primitives = { version = "0.1", features = ["simd", "rayon"] }
```

| Feature | Description | Default |
|---------|-------------|---------|
| `std` | Standard library support | Yes |
| `alloc` | Heap allocation | Yes |
| `simd` | SSE2/AVX2/AVX-512 acceleration | Yes |
| `rayon` | Multi-threaded parallel hashing | No |
| `cuda` | NVIDIA GPU batch hashing (experimental) | No |
| `sha2` | SHA-256/384/512 | Yes |
| `blake3` | BLAKE3 hash function | Yes |
| `chacha20poly1305` | ChaCha20-Poly1305 AEAD | Yes |
| `shake` | SHAKE128/SHAKE256 (for ML-DSA) | No |

### arcanum-pqc

```toml
[dependencies]
arcanum-pqc = { version = "0.1", features = ["ml-kem", "slh-dsa"] }
```

| Feature | Description | Default |
|---------|-------------|---------|
| `ml-kem` | ML-KEM (FIPS 203) key encapsulation | Yes |
| `ml-dsa` | ML-DSA (FIPS 204) via external crate | No |
| `ml-dsa-native` | Native ML-DSA (requires `shake`) | No |
| `slh-dsa` | SLH-DSA (FIPS 205) native | No |
| `hybrid` | X25519 + ML-KEM hybrid | No |
| `simd` | SIMD optimizations | No |
| `parallel` | Rayon parallelism | No |

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
- **ML-KEM** (CRYSTALS-Kyber): NIST-standardized KEM (FIPS 203)
- **ML-DSA** (CRYSTALS-Dilithium): NIST-standardized signatures (FIPS 204)
- **SLH-DSA** (SPHINCS+): Stateless hash-based signatures (FIPS 205)
- **Hybrid schemes**: X25519 + ML-KEM for defense in depth

### Advanced Features

**HoloCrypt** - Composable multi-layer cryptographic containers:
- Layered security: encryption + commitment + Merkle structure + signature
- Selective disclosure: reveal specific chunks with Merkle proofs
- Property proofs: prove value ranges without revealing values
- PQC envelope: ML-KEM-768 quantum-resistant key wrapping
- Threshold access: k-of-n decryption with FROST integration

**Threshold Cryptography**:
- FROST threshold signatures (2-of-3, 3-of-5, etc.)
- Shamir secret sharing with Feldman/Pedersen VSS
- Distributed key generation (DKG) without trusted dealer
- Proactive share refresh: time-bounded security

**Zero-Knowledge Proofs**:
- Bulletproofs range proofs (prove value in [0, 2^n) without revealing it)
- Pedersen commitments (homomorphic: C(a) + C(b) = C(a+b))
- Schnorr proofs of discrete log knowledge

**Algorithm Agility**:
- Self-describing containers with algorithm IDs
- Migration recommendations for deprecated algorithms
- Policy engine for compliance (FIPS 140-3, etc.)

**Security Verification**:
- dudect-style timing analysis for constant-time verification
- Statistical side-channel detection with Welch's t-test
- CI-ready timing regression tests

### Batch and Fused APIs

**Batch Processing** - Process multiple independent inputs:
```rust
use arcanum_primitives::batch::{BatchSha256x4, merkle_root_sha256};

// Hash 4 messages simultaneously
let hashes = BatchSha256x4::hash_parallel([msg1, msg2, msg3, msg4]);

// Batch-optimized Merkle tree
let root = merkle_root_sha256(&leaves);
```

**BLAKE3 Batch Hashing** - For processing multiple messages:
```rust
use arcanum_primitives::blake3_simd::hash_batch_8;

// Hash 8 messages in parallel using AVX-512
let hashes = hash_batch_8(&[msg1, msg2, msg3, msg4, msg5, msg6, msg7, msg8]);
```

**Fused Operations** - Single-pass encrypt+authenticate:
```rust
use arcanum_primitives::fused::FusedChaCha20Poly1305;

// Encrypt and MAC in one pass
let cipher = FusedChaCha20Poly1305::new(&key);
let tag = cipher.encrypt(&nonce, aad, &mut buffer);
```

### HoloCrypt Examples

**Seal and Unseal** - Complete cryptographic container:
```rust
use arcanum_holocrypt::container::HoloCrypt;

// Generate keypair and seal data
let (sealing_key, opening_key) = HoloCrypt::<MyData>::generate_keypair();
let container = HoloCrypt::seal(&data, &sealing_key)?;

// Unseal with verification
let recovered: MyData = container.unseal(&opening_key)?;
```

**Selective Disclosure** - Reveal specific chunks with Merkle proofs:
```rust
use arcanum_holocrypt::selective::{MerkleTreeBuilder, ChunkProof};

// Build tree from data chunks
let tree = MerkleTreeBuilder::from_chunks(&chunks);
let root = tree.root();

// Generate proof for specific chunk (without revealing others)
let proof = tree.generate_proof(chunk_index)?;

// Verifier can confirm chunk authenticity
assert!(proof.verify(&chunk, &root));
```

**Property Proofs** - Prove facts without revealing values:
```rust
use arcanum_holocrypt::properties::PropertyProofBuilder;

// Prove value is in range [0, 100) without revealing the value
let proof = PropertyProofBuilder::build_range_proof(secret_value, 0, 100, commitment)?;

// Verifier confirms the property holds
assert!(proof.verify(&commitment));
```

**PQC Envelope** - Quantum-resistant key wrapping:
```rust
use arcanum_holocrypt::pqc::{PqcEnvelope, PqcKeyPair};

let keypair = PqcKeyPair::generate();  // ML-KEM-768

// Wrap a content key with quantum resistance
let envelope = PqcEnvelope::wrap(&content_key, keypair.encapsulation_key())?;

// Unwrap with decapsulation key
let recovered_key = envelope.unwrap(keypair.decapsulation_key())?;
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

## Benchmarking

```bash
# Run primitives benchmarks
cargo bench -p arcanum-primitives --features "simd,rayon"

# Run PQC benchmarks
cargo bench -p arcanum-pqc --features "ml-kem"
cargo bench -p arcanum-pqc --features "slh-dsa"

# Run signature benchmarks
cargo bench -p arcanum-signatures

# Run all crate benchmarks
cargo bench -p arcanum-symmetric
cargo bench -p arcanum-asymmetric
cargo bench -p arcanum-hash

# Run HoloCrypt benchmarks
cargo bench -p arcanum-holocrypt
```

## When to Use What

| Use Case | Recommendation |
|----------|----------------|
| BLAKE3 single file <512MB | `blake3` crate (well-optimized) |
| BLAKE3 single file 512MB+ | `hash_apex_monolithic()` (parallel benefits) |
| BLAKE3 multiple small files | `hash_batch_8()` (SIMD parallel) |
| ChaCha20-Poly1305 bulk | Arcanum native (SIMD optimized) |
| SHA-256 single message | RustCrypto (SHA-NI accelerated) |
| SHA-256 batch | `BatchSha256x4` (parallel) |
| Post-quantum KEM | `arcanum-pqc` ML-KEM |
| Multi-layer containers | `HoloCrypt` (encrypt+sign+Merkle) |
| Selective disclosure | `MerkleTreeBuilder` (prove parts) |
| Range proofs | `PropertyProofBuilder` (ZK ranges) |
| Distributed secrets | `arcanum-threshold` (FROST/Shamir) |

## Security

- Built on audited cryptographic libraries (RustCrypto)
- Native backend validated against NIST test vectors
- Follows NIST, IETF, and industry best practices
- Comprehensive test coverage including Wycheproof vectors
- Designed for side-channel resistance

## License

MIT OR Apache-2.0
