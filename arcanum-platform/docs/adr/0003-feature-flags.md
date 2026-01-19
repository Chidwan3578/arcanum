# ADR-0003: Feature Flag Design

## Status
Accepted

## Context

Arcanum provides many cryptographic algorithms. Users may want to:
1. Minimize binary size by excluding unused algorithms
2. Avoid compiling slow-to-build dependencies
3. Enable experimental or legacy algorithms selectively

We need a feature flag strategy that balances usability with flexibility.

## Decision

Use **algorithm-based feature flags** with sensible defaults.

### Principles

1. **Default features**: Include commonly-used, modern algorithms
2. **Optional features**: Legacy, experimental, or heavy dependencies
3. **Aggregate features**: `all` feature to enable everything
4. **Dependency gating**: Use `dep:` syntax for optional dependencies

### Example structure

```toml
[features]
default = ["aes", "chacha20"]
aes = ["dep:aes", "dep:aes-gcm", "dep:aes-gcm-siv"]
chacha20 = ["dep:chacha20", "dep:chacha20poly1305"]
xchacha20 = ["chacha20"]
legacy = ["dep:blowfish", "dep:twofish"]
all = ["aes", "chacha20", "xchacha20", "legacy"]
```

### Crate-specific defaults

| Crate | Default Features |
|-------|-----------------|
| arcanum-symmetric | `aes`, `chacha20` |
| arcanum-hash | `sha2`, `sha3`, `blake3`, `kdf` |
| arcanum-signatures | `ed25519`, `ecdsa` |
| arcanum-pqc | `ml-kem`, `ml-dsa` |

## Consequences

### Positive
- Users can minimize dependencies and compile time
- Clear mapping from features to algorithms
- Easy to add new algorithms without affecting defaults
- `all` feature for comprehensive builds

### Negative
- More complex Cargo.toml files
- Users must enable features explicitly for non-default algorithms
- Feature combinations can create subtle bugs

### Usage examples

```toml
# Minimal: just AES-GCM
arcanum-symmetric = { version = "0.1", default-features = false, features = ["aes"] }

# Everything
arcanum-symmetric = { version = "0.1", features = ["all"] }

# Default + legacy
arcanum-symmetric = { version = "0.1", features = ["legacy"] }
```
