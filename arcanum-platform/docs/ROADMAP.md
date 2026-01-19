# Arcanum Roadmap

## Completed

### Phase 1: Quick Wins (API Polish) ✅
- [x] `seal()`/`open()` one-liners for AEAD ciphers
- [x] `From<[u8; N]>` for key types
- [x] `TryFrom<&[u8]>` for variable-length inputs
- [x] `Display` for public keys, KeyUsage, KeyAlgorithm
- [x] Consistent `Debug` redaction for secrets

### Phase 2: Builder Patterns (Ergonomics) ✅
- [x] Argon2 builder pattern
- [x] Scrypt builder pattern

### Phase 2.5: Type Aliases (API Ergonomics) ✅
- [x] Key type aliases (`Key128`, `Key192`, `Key256`, `Key384`, `Key512`)
- [x] Nonce type aliases (`Nonce64`, `Nonce96`, `Nonce128`, `Nonce192`)

### Phase 3: Error Enhancement ✅
- [x] Contextual errors with algorithm names
- [x] `suggestion()` method for recovery advice
- [x] `is_recoverable()` for transient failures

### Phase 4: Display Implementations ✅
- [x] `Argon2Params` display
- [x] `ScryptParams` display
- [x] `KeyUsage` display

### Phase 5: AEAD Builder Pattern ✅
- [x] `NonceStrategy` enum (Random, Counter, CounterFrom)
- [x] `CipherBuilder` for fluent configuration
- [x] `CipherInstance` with automatic nonce generation
- [x] Thread-safe counter-based nonces using `AtomicU64`
- [x] Key zeroization on drop

### Phase 6: Prelude Expansion ✅
- [x] `arcanum-core::prelude` with buffer, encoding, error, key, nonce, random, time, version types
- [x] `arcanum-hash::prelude` with hash functions, password hashing, KDFs, MACs
- [x] `arcanum-signatures::prelude` with all signature variants
- [x] `arcanum-symmetric::prelude` with ciphers and builder types

### Phase 7: Property-Based Testing ✅
- [x] `proptest` integration for arcanum-symmetric (13 tests)
- [x] `proptest` integration for arcanum-signatures (11 tests)
- [x] Encryption/decryption roundtrip verification
- [x] Sign/verify roundtrip verification
- [x] Tampering detection tests
- [x] AAD verification tests
- [x] ECDSA KAT vectors for P-256, P-384, secp256k1 (17 tests)

### Phase 8: Criterion Benchmarks ✅
- [x] Symmetric encryption benchmarks (AES-GCM, ChaCha20-Poly1305)
- [x] Signature benchmarks (Ed25519, ECDSA, Schnorr)
- [x] Algorithm comparison benchmarks
- [x] CipherInstance builder API benchmarks
- [x] Key generation benchmarks
- [x] Ed25519 batch verification benchmarks (7 batch sizes, comparison with individual)

---

## Future Considerations

### Production Hardening
- [x] `#[must_use]` on Result-returning functions (covered by `std::result::Result`)
- [x] Audit feature flags for proper gating
  - arcanum-hash, arcanum-symmetric, arcanum-signatures: ✅ Properly gated
  - arcanum-core: ⚠️ `std` feature defined but not gated (uses std unconditionally)
  - Note: `no_std` support for arcanum-core would require significant refactoring
- [x] Add `cargo-deny` for dependency audit
  - Configuration: `deny.toml` (license compliance, security advisories, banned crates)
  - Run: `cargo install cargo-deny && cargo deny check`
- [x] MSRV policy (minimum supported Rust version)
  - Set to Rust 1.85 in workspace `Cargo.toml`
  - All crates inherit via `rust-version.workspace = true`

### Documentation ✅
- [x] More doc examples on public APIs
  - `Cipher` trait with seal/open example
  - `SigningKey`/`VerifyingKey` traits with Ed25519 example
  - `Argon2` password hashing with builder pattern example
  - `CipherBuilder` with nonce strategy example
- [x] Architecture decision records (ADRs)
  - ADR-0001: RustCrypto ecosystem selection
  - ADR-0002: Error handling strategy
  - ADR-0003: Feature flag design
  - ADR-0004: Nonce management strategy
  - ADR-0005: Key zeroization on drop
- [x] Migration guide for API changes (`docs/MIGRATION.md`)

### CI/CD ✅
- [x] GitHub Actions workflow (`.github/workflows/ci.yml`)
  - Format check, Clippy lints, tests (Linux/macOS/Windows)
  - Feature matrix testing, MSRV check (1.85), docs build
  - Miri undefined behavior detection
- [x] Code coverage reporting (`.github/workflows/coverage.yml`)
  - cargo-llvm-cov integration
  - Codecov upload
- [x] Security audit automation (`.github/workflows/security.yml`)
  - cargo-deny checks (daily)
  - RustSec advisory database
  - Dependency review for PRs
- [x] Benchmark regression detection (`.github/workflows/benchmarks.yml`)
  - Criterion benchmark runs
  - github-action-benchmark integration
  - PR comparison with critcmp
