# Arcanum Fuzzing Report

**Date**: 2026-01-22
**Duration**: 4 hours per target
**Framework**: cargo-fuzz (libFuzzer)
**Hardware**: AMD Ryzen Threadripper PRO 7955WX

---

## Summary

All cryptographic primitives passed extended fuzz testing with **zero crashes** across **1.35 billion total executions**.

---

## Results

| Target | Executions | Coverage | Corpus | Result |
|--------|-----------|----------|--------|--------|
| `fuzz_aes_gcm` | 595,816,891 | 319 edges | 35 inputs | PASS |
| `fuzz_chacha20poly1305` | 363,598,893 | 687 edges | 90 inputs | PASS |
| `fuzz_blake3` | 325,982,072 | 473 edges | 48 inputs | PASS |
| `fuzz_ed25519` | 34,740,428 | 927 edges | 45 inputs | PASS |
| `fuzz_x25519` | 19,325,674 | 327 edges | 3 inputs | PASS |
| `fuzz_ml_kem` | 9,149,947 | 379 edges | 28 inputs | PASS |

---

## Fuzz Targets

### fuzz_aes_gcm
Tests AES-256-GCM encryption/decryption roundtrips and handling of malformed ciphertext.

### fuzz_chacha20poly1305
Tests ChaCha20-Poly1305 AEAD operations including AAD handling and authentication failure paths.

### fuzz_blake3
Tests BLAKE3 hashing with arbitrary input lengths and streaming updates.

### fuzz_ed25519
Tests Ed25519 signature generation and verification, including malformed signatures.

### fuzz_x25519
Tests X25519 key exchange with arbitrary public keys and shared secret derivation.

### fuzz_ml_kem
Tests ML-KEM-768 encapsulation/decapsulation roundtrips (post-quantum KEM).

---

## Running Fuzz Tests

```bash
# Install cargo-fuzz
cargo install cargo-fuzz

# Run a specific target (30 seconds)
cd fuzz
cargo +nightly fuzz run fuzz_chacha20poly1305 -- -max_total_time=30

# Run extended fuzzing (4 hours)
cargo +nightly fuzz run fuzz_chacha20poly1305 -- -max_total_time=14400

# Check for crashes
ls artifacts/*/crash-*
```

---

## Continuous Fuzzing

For production deployments, consider:
- [OSS-Fuzz](https://github.com/google/oss-fuzz) integration for continuous coverage
- Running fuzz tests in CI on each release
- Periodic extended runs (24+ hours) before major releases

---

*Report generated after pre-release fuzz testing.*
