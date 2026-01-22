# Arcanum Benchmark Report

## Executive Summary

This report provides **full transparency** on Arcanum's cryptographic implementation performance. Arcanum provides specialized optimizations for specific use cases while leveraging excellent reference implementations from the Rust cryptography ecosystem where appropriate.

**Key Design Goals:**
- Batch operations for processing multiple items efficiently
- SIMD optimizations for throughput-critical paths
- Pure Rust implementations for safety and portability

---

## Test Environment

- **CPU**: AMD Ryzen Threadripper PRO 7955WX 16-Cores (32 threads)
- **GPU**: NVIDIA RTX 4500 Ada (Ada Lovelace, sm_89)
- **Platform**: Linux 6.6.87 (WSL2)
- **Rust**: 1.92.0
- **CUDA**: 12.0
- **Date**: 2026-01-21
- **Benchmarking Framework**: Criterion 0.5 + built-in timing tests

---

## BLAKE3 Performance Analysis

### Size-Dependent Performance Characteristics

Arcanum's parallel BLAKE3 implementations use multi-threaded chunk processing, which has different performance characteristics depending on data size:

| Data Size | Arcanum Apex Mono | blake3 crate | Notes |
|-----------|-------------------|--------------|-------|
| 4MB       | 2.16 GiB/s | 7.80 GiB/s  | Threading overhead dominates |
| 16MB      | 4.89 GiB/s | 7.87 GiB/s  | Overhead still significant |
| 64MB      | 1.79 GiB/s | 5.67 GiB/s  | Memory bandwidth effects |
| 128MB     | 2.96 GiB/s | 5.61 GiB/s  | Approaching crossover |
| 256MB     | 4.43 GiB/s | 5.80 GiB/s  | Near parity |
| **512MB** | **7.86 GiB/s** | 5.85 GiB/s | Parallelism benefits realized |

### Understanding the Tradeoffs

The `blake3` crate is an excellent, well-optimized implementation that performs exceptionally across all data sizes. Arcanum's parallel implementations are specifically designed for very large file processing (512MB+) where thread coordination overhead is amortized across enough work to benefit from multi-core parallelism.

### BLAKE3 Batch Hashing

For processing **multiple independent messages simultaneously**, Arcanum provides batch APIs:

| Scenario | Arcanum Batch | Sequential Processing |
|----------|---------------|----------------------|
| 8×256B messages | 2.45 GiB/s | 1.08 GiB/s |
| 8×64B messages | 2.13 GiB/s | ~0.9 GiB/s |

This is useful when hashing many small files or blocks in parallel.

### BLAKE3 Monolithic Compression

At the compression function level, Arcanum's AVX-512 implementation:

| Implementation | Throughput (16KB, 16 chunks) |
|----------------|------------------------------|
| Monolithic     | 7.53 GiB/s |
| Per-Round ASM  | 6.15 GiB/s |

### Recommended Usage

| Use Case | Recommendation | Rationale |
|----------|----------------|-----------|
| Single file <64MB | `blake3` crate | Well-optimized for this range |
| Single file 64-256MB | `blake3` crate | Still more efficient |
| Single file 512MB+ | `hash_apex_monolithic()` | Parallel benefits realized |
| Multiple small files | `hash_batch_8()` | SIMD parallel processing |

---

## ChaCha20-Poly1305 Performance

Arcanum provides a native implementation optimized for throughput:

| Implementation | Throughput (4KB) |
|----------------|------------------|
| Arcanum Native | 1.63 GiB/s (encrypt), 1.66 GiB/s (decrypt) |
| RustCrypto     | 1.11 GiB/s |

Both implementations are correct and secure. Arcanum's implementation uses additional SIMD optimizations that provide higher throughput for bulk encryption workloads.

---

## Poly1305 SIMD Performance

Arcanum provides SIMD-accelerated Poly1305:

| Implementation | Throughput (4KB) |
|----------------|------------------|
| Arcanum SIMD   | 3.44 GiB/s |
| RustCrypto     | 2.44 GiB/s |
| Arcanum scalar | 1.12 GiB/s |

---

## SHA-256 Performance

| Implementation | Throughput (4KB) |
|----------------|------------------|
| RustCrypto (with SHA-NI) | 2.14 GiB/s |
| Arcanum Native | 1.87 GiB/s |

RustCrypto's SHA-256 leverages hardware SHA-NI instructions when available, providing excellent performance. For single-message hashing, it's the recommended choice. Arcanum's batch SHA-256 API (`BatchSha256x4`) provides parallel processing for multiple messages.

---

## Post-Quantum Cryptography Performance

### ML-KEM (FIPS 203) - Key Encapsulation

| Security Level | Keygen | Encapsulate | Decapsulate |
|---------------|--------|-------------|-------------|
| ML-KEM-512 | ~15 µs | ~18 µs | ~20 µs |
| ML-KEM-768 | ~25 µs | ~30 µs | ~35 µs |
| ML-KEM-1024 | ~35 µs | ~45 µs | ~50 µs |

### ML-DSA (FIPS 204) - Digital Signatures

| Security Level | Keygen | Sign | Verify |
|---------------|--------|------|--------|
| ML-DSA-44 | ~140 µs | ~350 µs | ~120 µs |
| ML-DSA-65 | ~197 µs | ~400 µs | ~143 µs |
| ML-DSA-87 | ~324 µs | ~432 µs | ~246 µs |

### SLH-DSA (FIPS 205) - Stateless Hash-Based Signatures

SLH-DSA provides conservative, stateless signatures based on hash functions. The "-f" variants optimize for speed while "-s" variants optimize for signature size.

| Variant | Keygen | Sign | Verify | Signature Size |
|---------|--------|------|--------|----------------|
| SLH-DSA-SHA2-128f | 348 µs | **15.6 ms** | 491 µs | 17,088 bytes |
| SLH-DSA-SHA2-128s | 21.9 ms | **333 ms** | 158 µs | 7,856 bytes |

**Note**: SLH-DSA signing is inherently slow due to its hash-based security model. The "-f" (fast) variant is recommended for most use cases. The "-s" (small) variant is useful when signature size is critical and signing latency is acceptable.

### PQC Algorithm Selection Guide

| Use Case | Recommendation | Rationale |
|----------|----------------|-----------|
| Key exchange | ML-KEM-768 | Balanced security and performance |
| Frequent signing | ML-DSA-65 | Fast signing, reasonable key sizes |
| High-security signing | ML-DSA-87 | NIST Level 5 security |
| Signature archival | SLH-DSA-128s | Conservative, minimal assumptions |
| Real-time signing | SLH-DSA-128f | Faster than -s variant |

---

## HoloCrypt Container Performance

HoloCrypt provides composable multi-layer cryptographic containers combining encryption, commitments, Merkle trees, and signatures.

### Container Seal/Unseal

| Data Size | Seal | Unseal |
|-----------|------|--------|
| 256 B | 17.8 µs | 31.3 µs |
| 1 KB | 23.4 µs | 35.6 µs |
| 4 KB | 42.1 µs | 58.7 µs |
| 16 KB | 98.5 µs | 125.3 µs |
| 64 KB | 352 µs | 428 µs |
| 262 KB | 3.4 ms | 4.5 ms |

### PQC Container (ML-KEM-768 wrapped)

| Data Size | Seal | Unseal |
|-----------|------|--------|
| 256 B | 68.7 µs | 85.2 µs |
| 1 KB | 72.4 µs | 89.6 µs |
| 4 KB | 95.3 µs | 112.8 µs |
| 16 KB | 158.4 µs | 182.1 µs |

### Selective Disclosure (Merkle Proofs)

| Tree Size | Build Tree | Generate Proof | Verify Proof |
|-----------|------------|----------------|--------------|
| 16 chunks | 52.4 µs | 23.1 ns | 0.9 µs |
| 64 chunks | 215.3 µs | 35.7 ns | 1.3 µs |
| 256 chunks | 86.2 µs | 58.4 ns | 1.8 µs |
| 1024 chunks | 345.6 µs | 90.6 ns | 2.2 µs |

Note: Proof generation is O(log n) - extremely fast. Verification scales with proof depth (logarithmic in tree size).

### Property Proofs (Zero-Knowledge)

| Proof Type | Build | Verify |
|------------|-------|--------|
| Range proof (64-bit) | 1.61 ms | 802 µs |
| Greater-than proof | 9.93 ms | ~1 ms |
| Hash preimage proof | 175 ns | ~200 ns |

Range proofs use Bulletproofs internally, providing compact proofs without trusted setup. The ~1.6ms build time enables real-time range proof generation.

### HoloCrypt Use Case Guide

| Scenario | Approach | Performance |
|----------|----------|-------------|
| Simple encryption + signing | `HoloCrypt::seal()` | 17.8 µs (256B) |
| Quantum-resistant containers | `PqcContainer::seal()` | 68.7 µs (256B) |
| Prove ownership of chunk | `MerkleTreeBuilder` + proof | 2.2 µs verify |
| Prove value in range | `PropertyProofBuilder::build_range_proof()` | 1.6 ms |
| Threshold decryption | FROST integration | See threshold benchmarks |

---

## Feature Flags Reference

### arcanum-primitives

| Feature | Description | When to Enable |
|---------|-------------|----------------|
| `default` | std, alloc, simd, sha2, blake3, chacha20poly1305 | Standard usage |
| `simd` | SSE2/AVX2/AVX-512 acceleration | Always on x86_64 |
| `rayon` | Multi-threaded parallel hashing | Large file processing (512MB+) |
| `cuda` | NVIDIA GPU batch hashing | GPU-accelerated workloads |
| `shake` | SHAKE128/SHAKE256 (Keccak XOF) | ML-DSA native |

### arcanum-pqc

| Feature | Description | When to Enable |
|---------|-------------|----------------|
| `ml-kem` | ML-KEM (FIPS 203) key encapsulation | Post-quantum key exchange |
| `ml-dsa` | ML-DSA (FIPS 204) via external crate | Post-quantum signatures |
| `ml-dsa-native` | Native ML-DSA implementation | Avoiding external deps |
| `slh-dsa` | SLH-DSA (FIPS 205) native | Stateless hash-based sigs |
| `simd` | SIMD optimizations | Performance |
| `parallel` | Parallel processing | Large workloads |

### arcanum-holocrypt

| Feature | Description | When to Enable |
|---------|-------------|----------------|
| `full` | All HoloCrypt features | Full container functionality |
| `encryption` | Symmetric encryption layer | Basic containers |
| `merkle` | Merkle tree support | Selective disclosure |
| `zkp` | Zero-knowledge proofs | Property proofs |
| `pqc` | Post-quantum envelope | Quantum resistance |
| `threshold` | Threshold access | k-of-n decryption |
| `signatures` | Digital signatures | Container signing |

---

## CUDA GPU Acceleration

Arcanum provides CUDA-accelerated batch BLAKE3 hashing for GPU workloads. The GPU excels at processing large batches of messages in parallel.

### CUDA Batch Hashing Performance

| Batch Configuration | CUDA (RTX 4500) | CPU Sequential | GPU Advantage |
|---------------------|-----------------|----------------|---------------|
| 1,000 × 256B | 1.05 GiB/s | 1.13 GiB/s | CPU faster (overhead) |
| 1,000 × 1024B | 2.08 GiB/s | 1.17 GiB/s | **1.78× faster** |
| 10,000 × 256B | 2.69 GiB/s | 1.12 GiB/s | **2.4× faster** |
| 10,000 × 1024B | 3.12 GiB/s | 1.17 GiB/s | **2.67× faster** |

### CUDA Optimized Small-Batch Path

For uniform message sizes, the optimized kernel provides higher throughput:

| Batch Configuration | CUDA Optimized |
|---------------------|----------------|
| 10,000 × 64B | 1.78 GiB/s |
| 10,000 × 256B | 3.29 GiB/s |
| 10,000 × 512B | 3.63 GiB/s |
| 10,000 × 1024B | **3.91 GiB/s** |

### When to Use CUDA

| Scenario | Recommendation |
|----------|----------------|
| <1,000 messages | CPU (transfer overhead dominates) |
| 1,000-10,000 small messages | GPU provides 2-3× speedup |
| 10,000+ messages | GPU strongly preferred |
| Variable-length messages | Use general batch API |
| Uniform-length messages | Use optimized small-batch API |

### Setup Requirements

1. NVIDIA GPU with CUDA support
2. CUDA toolkit installed
3. Build the shared library:
   ```bash
   cd crates/arcanum-primitives/src
   nvcc -O3 -arch=sm_89 --shared --compiler-options '-fPIC' blake3_cuda.cu -o libblake3_cuda.so
   ```
4. Enable the `cuda` feature flag
5. Run benchmarks:
   ```bash
   cargo bench -p arcanum-primitives --features "simd,rayon,cuda" -- "BLAKE3-CUDA"
   ```

---

## Benchmark Invocation Reference

```bash
# Run all primitives benchmarks
cargo bench -p arcanum-primitives --features "simd,rayon"

# Run specific benchmark groups
cargo bench -p arcanum-primitives --features "simd,rayon" -- "BLAKE3-Batch"
cargo bench -p arcanum-primitives --features "simd,rayon" -- "Poly1305-SIMD"
cargo bench -p arcanum-primitives --features "simd,rayon" -- "ChaCha20-Poly1305"

# Run PQC benchmarks
cargo bench -p arcanum-pqc --features "ml-kem"
cargo bench -p arcanum-pqc --features "slh-dsa"

# Run HoloCrypt benchmarks
cargo bench -p arcanum-holocrypt

# Run large-scale timing tests
cargo test -p arcanum-primitives --features "simd,rayon" --release -- bench_all_implementations --nocapture
```

---

## Design Philosophy

Arcanum is designed to complement the excellent Rust cryptography ecosystem:

- **RustCrypto** provides well-audited, portable implementations
- **blake3 crate** provides an optimized reference implementation
- **Arcanum** provides specialized optimizations for specific use cases:
  - Batch processing APIs
  - SIMD-accelerated primitives
  - Very large file processing

The goal is to provide the right tool for each job, not to replace existing libraries.

---

## Tradeoffs

| Approach | Strengths | Considerations |
|----------|-----------|----------------|
| Arcanum Batch APIs | Efficient multi-item processing | Requires batching workload |
| Arcanum Parallel BLAKE3 | Excellent for 512MB+ files | Threading overhead at smaller sizes |
| Arcanum SIMD Poly1305 | High throughput | x86_64 specific |
| RustCrypto | Portable, audited, consistent | General-purpose |
| blake3 crate | Optimized across all sizes | Single-item focused |

---

*Generated by Arcanum Benchmarking Suite*
*Benchmark data reflects specific hardware and conditions*
