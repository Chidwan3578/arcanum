# Benchmark Coverage

This document tracks benchmark coverage across all Arcanum crates.

## Summary

| Crate | Benchmark Functions | Status | Notes |
|-------|---------------------|--------|-------|
| arcanum-primitives | 28+ | Tested | Core primitives, BLAKE3, ChaCha20, Poly1305, CUDA |
| arcanum-pqc | 12 | Tested | ML-KEM, ML-DSA, SLH-DSA all tested |
| arcanum-signatures | 11 | Available | Ed25519, P-256 ECDSA |
| arcanum-symmetric | 4 | Available | AES-GCM, ChaCha20-Poly1305 |
| arcanum-asymmetric | 10 | Available | X25519, RSA, ECDH |
| arcanum-hash | 6 | Available | SHA-256, SHA-512, BLAKE3 |
| arcanum-threshold | 3 | Tested | Shamir, FROST, DKG |
| arcanum-zkp | 1 | Tested | Range proofs |

## Detailed Coverage

### arcanum-primitives (Tested)

```bash
cargo bench -p arcanum-primitives --features "simd,rayon"
```

| Benchmark | Feature Gates | Tested |
|-----------|---------------|--------|
| SHA-256 (various sizes) | default | Yes |
| SHA-256 vs RustCrypto | default | Yes |
| SHA-512 (various sizes) | default | Yes |
| BLAKE3 (various sizes) | default | Yes |
| BLAKE3-Parallel | simd | Yes |
| BLAKE3-Turbo | simd | Yes |
| BLAKE3-Hyper | simd, rayon | Yes |
| BLAKE3-ASM | simd | Yes |
| BLAKE3-Ultra | simd, rayon | Yes |
| BLAKE3-Adaptive | simd, rayon | Yes |
| BLAKE3-Apex | simd, rayon | Yes |
| BLAKE3-HyperParallel | simd | Yes |
| BLAKE3-Monolithic | simd | Yes |
| BLAKE3-Batch | simd | Yes |
| BLAKE3-AVX512 | simd | Yes |
| ChaCha20 | default | Yes |
| ChaCha20-Poly1305 | default | Yes |
| Poly1305 | default | Yes |
| Poly1305-SIMD | simd | Yes |
| Batch SHA-256 | default | Yes |
| Fused ChaCha20-Poly1305 | default | Yes |
| Merkle Tree | default | Yes |
| Large-scale ChaCha20-Poly1305 | default | Yes |
| BLAKE3-CUDA batch | cuda | Yes |
| BLAKE3-CUDA small batch | cuda | Yes |

### arcanum-pqc (Tested)

```bash
cargo bench -p arcanum-pqc --features "ml-kem"
cargo bench -p arcanum-pqc --features "ml-dsa"
cargo bench -p arcanum-pqc --features "slh-dsa"
```

| Benchmark | Feature Gates | Tested | Notes |
|-----------|---------------|--------|-------|
| ML-KEM-512 | ml-kem | Yes | |
| ML-KEM-768 | ml-kem | Yes | |
| ML-KEM-1024 | ml-kem | Yes | |
| ML-DSA-44 | ml-dsa | Yes | Via ml-dsa crate |
| ML-DSA-65 | ml-dsa | Yes | Via ml-dsa crate |
| ML-DSA-87 | ml-dsa | Yes | Via ml-dsa crate |
| ML-DSA-Native-44 | ml-dsa-native | No | Requires shake feature |
| ML-DSA-Native-65 | ml-dsa-native | No | Requires shake feature |
| ML-DSA-Native-87 | ml-dsa-native | No | Requires shake feature |
| SLH-DSA-SHA2-128f | slh-dsa | Yes | Fast variant |
| SLH-DSA-SHA2-128s | slh-dsa | Yes | Small signature variant |
| X25519-ML-KEM-768 | hybrid | No | Hybrid scheme |
| KEM-Comparison | ml-kem, hybrid | No | Comparison benchmark |

### arcanum-signatures (Available)

```bash
cargo bench -p arcanum-signatures
```

| Benchmark | Tested |
|-----------|--------|
| Ed25519 keygen | Available |
| Ed25519 sign | Available |
| Ed25519 verify | Available |
| P-256 keygen | Available |
| P-256 sign | Available |
| P-256 verify | Available |
| Algorithm comparison | Available |
| Ed25519 batch verify | Available |
| Ed25519 batch same key | Available |
| Ed25519 batch large messages | Available |
| Ed25519 batch throughput | Available |

### arcanum-symmetric (Available)

```bash
cargo bench -p arcanum-symmetric
```

| Benchmark | Tested |
|-----------|--------|
| AES-256-GCM | Available |
| ChaCha20-Poly1305 | Available |
| Key generation | Available |
| Algorithm comparison | Available |

### arcanum-asymmetric (Available)

```bash
cargo bench -p arcanum-asymmetric
```

| Benchmark | Tested |
|-----------|--------|
| X25519 keygen | Available |
| X25519 DH | Available |
| X25519 triple DH | Available |
| RSA keygen | Available |
| RSA encrypt/decrypt | Available |
| RSA sign/verify | Available |
| ECDH keygen | Available |
| ECDH DH | Available |
| Key exchange comparison | Available |
| Serialization | Available |

### arcanum-hash (Available)

```bash
cargo bench -p arcanum-hash
```

| Benchmark | Tested |
|-----------|--------|
| SHA-256 | Available |
| SHA-512 | Available |
| BLAKE3 | Available |
| Algorithm comparison | Available |
| Large data | Available |
| Small data | Available |

### arcanum-threshold (Tested)

```bash
cargo bench -p arcanum-threshold
```

| Benchmark | Tested |
|-----------|--------|
| Shamir split/reconstruct | Yes |
| FROST rounds | Yes |
| DKG | Yes |

### arcanum-zkp (Tested)

```bash
cargo bench -p arcanum-zkp
```

| Benchmark | Tested |
|-----------|--------|
| Range proofs | Yes |

## CUDA Benchmarks (Tested)

CUDA-accelerated BLAKE3 batch hashing has been benchmarked on RTX 4500 Ada (sm_89).

**Results Summary:**
| Configuration | CUDA Throughput | CPU Sequential | Speedup |
|---------------|-----------------|----------------|---------|
| 10,000 × 1024B (general) | 3.12 GiB/s | 1.17 GiB/s | 2.67× |
| 10,000 × 1024B (optimized) | 3.91 GiB/s | N/A | Best |

**Setup:**
```bash
cd crates/arcanum-primitives/src
nvcc -O3 -arch=sm_89 --shared --compiler-options '-fPIC' blake3_cuda.cu -o libblake3_cuda.so
cargo bench -p arcanum-primitives --features "simd,rayon,cuda" -- "BLAKE3-CUDA"
```

## Running All Benchmarks

```bash
# All primitives (comprehensive)
cargo bench -p arcanum-primitives --features "simd,rayon"

# CUDA benchmarks (requires GPU and libblake3_cuda.so)
cargo bench -p arcanum-primitives --features "simd,rayon,cuda" -- "BLAKE3-CUDA"

# PQC (each feature separately)
cargo bench -p arcanum-pqc --features "ml-kem"
cargo bench -p arcanum-pqc --features "ml-dsa"
cargo bench -p arcanum-pqc --features "slh-dsa"

# Other crates
cargo bench -p arcanum-signatures
cargo bench -p arcanum-symmetric
cargo bench -p arcanum-asymmetric
cargo bench -p arcanum-hash
cargo bench -p arcanum-threshold
cargo bench -p arcanum-zkp
```

## Known Gaps

1. **ML-DSA-Native benchmarks**: Requires `shake` feature (native implementation)
2. **Hybrid KEM benchmarks**: X25519+ML-KEM hybrid not yet benchmarked
3. **Comparative benchmarks**: `benches/comparative/` exists but was not run
4. **SLH-DSA variants**: Only 128-bit security level tested (higher levels available)

## Benchmark Data Locations

Criterion generates reports in:
- `target/criterion/` - HTML reports and data
- Individual benchmark groups have their own directories
