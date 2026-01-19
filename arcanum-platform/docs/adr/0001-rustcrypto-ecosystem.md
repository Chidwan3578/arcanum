# ADR-0001: Use RustCrypto Ecosystem

## Status
Accepted

## Context

Arcanum needs to provide cryptographic primitives for encryption, hashing, signatures, and key exchange. We need to decide which underlying cryptographic implementations to use.

Options considered:
1. **RustCrypto** - Pure Rust implementations maintained by the RustCrypto organization
2. **ring** - Rust bindings to BoringSSL (Google's OpenSSL fork)
3. **OpenSSL** - Rust bindings to OpenSSL
4. **libsodium** - Rust bindings to libsodium (sodiumoxide)

## Decision

Use the **RustCrypto ecosystem** as the primary cryptographic backend.

### Rationale

1. **Pure Rust**: No C dependencies, easier cross-compilation, better Rust integration
2. **Audited**: Many RustCrypto crates have undergone security audits
3. **Modular**: Each algorithm is a separate crate, enabling fine-grained dependencies
4. **Active maintenance**: Large community, frequent updates, responsive to CVEs
5. **Feature parity**: Covers all algorithms we need (AES-GCM, ChaCha20-Poly1305, Ed25519, ECDSA, Argon2, etc.)
6. **Consistent API**: All crates follow similar patterns and trait designs

### Specific crates used

- `aes-gcm`, `chacha20poly1305` - AEAD ciphers
- `ed25519-dalek` - Ed25519 signatures
- `p256`, `p384`, `k256` - Elliptic curves (ECDSA, ECDH)
- `x25519-dalek` - X25519 key exchange
- `sha2`, `sha3`, `blake3` - Hash functions
- `argon2`, `scrypt` - Password hashing
- `ml-kem`, `ml-dsa` - Post-quantum (NIST FIPS 203/204)

## Consequences

### Positive
- No system dependencies, works on any platform Rust supports
- Memory safety guarantees from Rust
- Easier to audit (pure Rust, smaller attack surface)
- Better integration with Rust's type system

### Negative
- May be slower than optimized C implementations in some cases
- Some algorithms (RSA) are less mature than ring/OpenSSL
- Need to track security advisories across many crates

### Mitigations
- Use `criterion` benchmarks to monitor performance
- Enable CPU feature detection for hardware acceleration (AES-NI, etc.)
- Integrate `cargo-deny` and RustSec for security monitoring
