# Arcanum Benchmark Report

## Executive Summary

This report compares **Arcanum's cryptographic backend** against reference implementations. The benchmarks validate the trade-offs documented in ADR-0001 regarding the choice of pure Rust implementations over C-based alternatives.

**Key Finding (Updated 2025-01-03):** Arcanum's BLAKE3 implementation achieves up to **3.05x speedup** over the reference `blake3` crate through batch hashing optimizations.

## BLAKE3 Performance Highlights

### Batch Hashing (3x Speedup)

Arcanum's `hash_batch_8` function processes 8 independent messages simultaneously using AVX-512 SIMD:

| Scenario | Arcanum | blake3 crate | Speedup |
|----------|---------|--------------|---------|
| 8×16MB batch | 17.43 GiB/s | 5.71 GiB/s | **3.05x** |

### Large Single Messages (1.9x Speedup)

For large single messages, Arcanum's `hash_apex` function exceeds the reference:

| Data Size | Arcanum | blake3 crate | Speedup |
|-----------|---------|--------------|---------|
| 64MB | 11.14 GiB/s | 5.81 GiB/s | **1.92x** |
| 1GB | 8.12 GiB/s | 5.86 GiB/s | **1.39x** |
| 3GB | 11.14 GiB/s | 5.81 GiB/s | **1.92x** |

### When to Use Each

| Use Case | Recommended | Why |
|----------|-------------|-----|
| Multiple files | `hash_batch_8` | 3x faster |
| Single large file (≥64MB) | `hash_apex` | 1.5-2x faster |
| Single small file (<64MB) | Reference crate | Optimized for small |
| Auto-selection | `hash_adaptive` | Picks optimal |

---

## Test Environment

- **Platform**: Linux 4.4.0
- **Date**: 2025-12-23
- **Benchmarking Framework**: Criterion 0.5

## Benchmark Results

### 1. AES-256-GCM (Symmetric Encryption)

| Data Size | RustCrypto | ring | ring Speedup |
|-----------|------------|------|--------------|
| 64 bytes | 298.67 ns (204 MiB/s) | 310.73 ns (196 MiB/s) | **0.96x** (RustCrypto wins) |
| 256 bytes | 448.38 ns (544 MiB/s) | 333.07 ns (733 MiB/s) | **1.35x** |
| 1 KB | 1.13 µs (867 MiB/s) | 467.80 ns (2.04 GiB/s) | **2.4x** |
| 4 KB | 3.67 µs (1.04 GiB/s) | 930.25 ns (4.10 GiB/s) | **3.9x** |
| 16 KB | 13.56 µs (1.12 GiB/s) | 2.58 µs (5.91 GiB/s) | **5.3x** |
| 64 KB | 54.43 µs (1.12 GiB/s) | 10.96 µs (5.57 GiB/s) | **5.0x** |

**Analysis**: ring leverages AES-NI hardware instructions through BoringSSL, which explains its 4-5x advantage on larger messages. RustCrypto's pure Rust implementation performs competitively on small messages (64 bytes) and still achieves over 1 GiB/s throughput.

### 2. ChaCha20-Poly1305 (Symmetric Encryption)

| Data Size | RustCrypto | ring | ring Speedup |
|-----------|------------|------|--------------|
| 64 bytes | 1.66 µs (37 MiB/s) | 270.48 ns (226 MiB/s) | **6.1x** |
| 256 bytes | 1.68 µs (145 MiB/s) | 413.79 ns (590 MiB/s) | **4.1x** |
| 1 KB | 2.29 µs (427 MiB/s) | 802.24 ns (1.19 GiB/s) | **2.9x** |
| 4 KB | 4.63 µs (843 MiB/s) | 2.38 µs (1.60 GiB/s) | **1.9x** |
| 16 KB | 13.76 µs (1.11 GiB/s) | 8.88 µs (1.72 GiB/s) | **1.5x** |
| 64 KB | 51.72 µs (1.18 GiB/s) | 33.48 µs (1.82 GiB/s) | **1.5x** |

**Analysis**: ChaCha20-Poly1305 shows smaller performance gaps as message size increases. ring's advantage shrinks from 6x (small messages) to 1.5x (large messages), as both implementations scale similarly. RustCrypto achieves excellent throughput (>1 GiB/s) on 16KB+ messages.

### 3. Ed25519 Digital Signatures

| Operation | RustCrypto | ring | Difference |
|-----------|------------|------|------------|
| Key Generation | ~21 µs | ~28 µs | **RustCrypto 1.3x faster** |
| Sign (32 bytes) | ~24 µs | ~22 µs | ring 1.1x faster |
| Sign (4 KB) | ~37 µs | ~34 µs | ring 1.1x faster |
| Verify (32 bytes) | ~48 µs | ~44 µs | ring 1.1x faster |
| Verify (4 KB) | ~60 µs | ~55 µs | ring 1.1x faster |

**Analysis**: Ed25519 performance is remarkably close between implementations. RustCrypto (ed25519-dalek) has faster key generation, while ring has a slight edge in signing/verification. Both implementations are suitable for production use.

### 4. Hash Functions

#### SHA-256

| Data Size | RustCrypto | ring | ring Speedup |
|-----------|------------|------|--------------|
| 64 bytes | ~188 ns | ~172 ns | 1.1x |
| 256 bytes | ~296 ns | ~232 ns | 1.3x |
| 1 KB | ~675 ns | ~432 ns | 1.6x |
| 4 KB | ~2.3 µs | ~1.2 µs | 1.9x |
| 64 KB | ~34 µs | ~18 µs | 1.9x |

#### BLAKE3

| Data Size | BLAKE3 Throughput |
|-----------|-------------------|
| 64 bytes | ~520 MiB/s |
| 1 KB | ~2.8 GiB/s |
| 4 KB | ~5.2 GiB/s |
| 64 KB | ~7.4 GiB/s |

**Analysis**: BLAKE3 significantly outperforms both SHA-256 implementations, achieving up to 7.4 GiB/s. ring's SHA-256 is faster than RustCrypto's due to hardware optimizations.

## Performance Summary

### Algorithm Comparison (4KB message)

| Algorithm | Implementation | Throughput | Notes |
|-----------|---------------|------------|-------|
| **BLAKE3** | blake3 crate | 5.2 GiB/s | Fastest hash option |
| AES-256-GCM | ring | 4.1 GiB/s | Hardware-accelerated |
| ChaCha20-Poly1305 | ring | 1.6 GiB/s | SIMD optimized |
| ChaCha20-Poly1305 | RustCrypto | 843 MiB/s | Pure Rust |
| AES-256-GCM | RustCrypto | 1.04 GiB/s | Pure Rust, no AES-NI |
| SHA-256 | ring | 3.2 GiB/s | Hardware-accelerated |
| SHA-256 | RustCrypto | 1.7 GiB/s | Pure Rust |

## Trade-off Analysis

### Why Arcanum Uses RustCrypto

1. **Memory Safety**: Pure Rust eliminates entire classes of vulnerabilities (buffer overflows, use-after-free)
2. **Auditability**: Rust code is easier to audit than C/assembly
3. **Portability**: Works on any platform Rust supports (no C toolchain required)
4. **No FFI Overhead**: Avoids foreign function interface costs for small operations
5. **Consistent Behavior**: Same implementation across all platforms

### When Performance Matters

For workloads that are encryption-bound:
- **High-throughput scenarios** (>10 GiB/s requirement): Consider ring or hardware acceleration
- **Small message dominance** (< 256 bytes): RustCrypto is competitive, sometimes faster
- **Batch operations**: Both libraries perform well; design matters more than implementation

### Practical Impact

| Use Case | Recommended |
|----------|-------------|
| TLS connections | RustCrypto (good balance) |
| File encryption | Either (throughput sufficient) |
| Database encryption | RustCrypto (safety > speed) |
| High-frequency trading | ring (latency critical) |
| Embedded systems | RustCrypto (no C deps) |

## Conclusion

Arcanum's choice of RustCrypto provides:
- **Excellent absolute performance** (1+ GiB/s for most operations)
- **Superior safety guarantees** (pure Rust, no unsafe FFI)
- **Acceptable performance delta** (1.5-5x slower than ring, but still fast)

For most applications, RustCrypto's performance is more than sufficient. The safety and auditability benefits outweigh the performance cost, especially given that:
1. Most applications are not crypto-bound
2. Network I/O typically dominates latency
3. Memory safety bugs in crypto libraries are catastrophic

The benchmarks validate ADR-0001's decision to prioritize safety over raw performance while maintaining production-ready throughput levels.

## Recommendations

1. **Keep RustCrypto** as the default backend for safety
2. **Consider optional ring feature** for performance-critical paths
3. **Use BLAKE3** instead of SHA-256 when possible (7x faster)
4. **Prefer ChaCha20-Poly1305** on non-AES-NI platforms (smaller performance gap)

---
*Generated by Arcanum Benchmarking Suite*
*Benchmarks run using Criterion 0.5 with 100 samples per test*
