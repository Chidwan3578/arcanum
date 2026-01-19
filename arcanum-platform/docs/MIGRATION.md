# Arcanum Migration Guide

This guide helps you migrate between Arcanum versions.

## Migrating to 0.2.0 (from 0.1.x)

### New Features

#### Seal/Open API
The new `seal()` and `open()` methods provide a simpler encryption API:

```rust
// Before (0.1.x)
let nonce = Aes256Gcm::generate_nonce();
let ciphertext = Aes256Gcm::encrypt(&key, &nonce, plaintext, None)?;
// Must store nonce separately

// After (0.2.0)
let sealed = Aes256Gcm::seal(&key, plaintext)?;
let opened = Aes256Gcm::open(&key, &sealed)?;
// Nonce is embedded in output
```

#### CipherBuilder Pattern
For more control, use the new builder pattern:

```rust
// New in 0.2.0
let cipher = CipherBuilder::<Aes256Gcm>::new()
    .key(&key)
    .nonce_strategy(NonceStrategy::Counter)
    .build()?;

let ct = cipher.encrypt(plaintext)?;
```

#### Prelude Modules
Import common types with a single line:

```rust
// Before
use arcanum_symmetric::aes::Aes256Gcm;
use arcanum_symmetric::traits::Cipher;

// After
use arcanum_symmetric::prelude::*;
```

### Breaking Changes

#### Error Types

The error enum has been expanded with contextual variants:

```rust
// Before
Error::EncryptionFailed

// After (new variants available)
Error::EncryptionFailedContext {
    algorithm: String,
    reason: String,
}
```

**Migration**: Existing `Error::EncryptionFailed` matches still work. Update error handling to use new context if desired.

#### Argon2 Parameters

The `Argon2Params` struct now uses a builder:

```rust
// Before
let params = Argon2Params {
    memory_cost: 65536,
    time_cost: 3,
    parallelism: 4,
    output_len: 32,
};

// After (builder preferred)
let params = Argon2Params::builder()
    .memory_mib(64)
    .iterations(3)
    .parallelism(4)
    .build();

// Or use presets
let params = Argon2Params::moderate();
```

**Migration**: Direct struct construction still works but builder is recommended.

### Deprecations

None in this release.

---

## Migrating to 0.1.0 (Initial Release)

This is the initial release. No migration needed.

---

## Feature Flag Changes

### 0.2.0

New features added:
- `xchacha20` - XChaCha20-Poly1305 (depends on `chacha20`)
- `legacy` - Blowfish, Twofish, CAST5
- `all` - Enable all algorithms

Default features unchanged:
- `arcanum-symmetric`: `aes`, `chacha20`
- `arcanum-hash`: `sha2`, `sha3`, `blake3`, `kdf`
- `arcanum-signatures`: `ed25519`, `ecdsa`

---

## Version Compatibility Matrix

| Arcanum | Rust MSRV | RustCrypto | Status |
|---------|-----------|------------|--------|
| 0.2.x   | 1.85      | 2024 Q4    | Current |
| 0.1.x   | 1.80      | 2024 Q2    | Maintenance |

---

## Getting Help

If you encounter migration issues:

1. Check the [CHANGELOG.md](CHANGELOG.md) for detailed changes
2. Review the [ADRs](adr/README.md) for architectural context
3. Open an issue on GitHub with the `migration` label
