# ML-DSA Optimization TDD Roadmap

**Document ID:** TDD-MLDSA-OPT-001
**Version:** 1.0
**Date:** 2026-01-21
**Status:** Active
**Spec Reference:** SPEC-OPT-MLDSA-001

---

## Overview

This roadmap follows Test-Driven Development methodology for ML-DSA optimizations:

1. **Red Phase**: Write performance tests that assert target metrics (will fail)
2. **Green Phase**: Implement optimizations until tests pass
3. **Refactor**: Clean up while maintaining green tests

---

## Phase 1: Quick Wins

### 1.1 SIMD Polynomial Arithmetic

#### Red Phase Tests

```rust
// tests/optimization_benchmarks.rs

#[test]
fn bench_poly_add_target() {
    // Target: < 50 ns (current ~200 ns)
    let start = Instant::now();
    for _ in 0..1000 {
        poly_add(&a, &b);
    }
    let elapsed = start.elapsed() / 1000;
    assert!(elapsed < Duration::from_nanos(50),
        "poly_add took {:?}, target < 50ns", elapsed);
}

#[test]
fn bench_poly_reduce_target() {
    // Target: < 100 ns (current ~500 ns)
    let start = Instant::now();
    for _ in 0..1000 {
        poly_reduce(&a);
    }
    let elapsed = start.elapsed() / 1000;
    assert!(elapsed < Duration::from_nanos(100),
        "poly_reduce took {:?}, target < 100ns", elapsed);
}
```

#### Green Phase Implementation

| File | Change | Expected Impact |
|------|--------|-----------------|
| `poly.rs` | Add `#[cfg(target_arch = "x86_64")]` SIMD path | 6x speedup |
| `poly.rs` | AVX2 `poly_add_avx2()` | 30 ns target |
| `poly.rs` | AVX2 `poly_reduce_avx2()` | 80 ns target |

#### Acceptance Criteria
- [ ] `poly_add` < 50 ns
- [ ] `poly_sub` < 50 ns
- [ ] `poly_reduce` < 100 ns
- [ ] Fallback path works on non-AVX2

---

### 1.2 Parallel ExpandA (Rayon)

#### Red Phase Tests

```rust
#[test]
fn bench_expand_a_parallel_target() {
    // ML-DSA-65: K=6, L=5 = 30 matrix entries
    // Target: < 40 µs (current ~75 µs)
    let start = Instant::now();
    let _a = expand_a::<Params65>(&rho);
    let elapsed = start.elapsed();
    assert!(elapsed < Duration::from_micros(40),
        "expand_a took {:?}, target < 40µs", elapsed);
}

#[test]
fn bench_expand_a_correctness() {
    // Parallel must produce identical results to sequential
    let a_seq = expand_a_sequential::<Params65>(&rho);
    let a_par = expand_a_parallel::<Params65>(&rho);
    assert_eq!(a_seq, a_par, "Parallel ExpandA differs from sequential");
}
```

#### Green Phase Implementation

| File | Change | Expected Impact |
|------|--------|-----------------|
| `sampling.rs` | Add `rayon` feature gate | - |
| `sampling.rs` | `expand_a_parallel()` with Rayon | 3x speedup |
| `Cargo.toml` | Add `rayon` optional dependency | - |

#### Acceptance Criteria
- [ ] `expand_a` < 40 µs (ML-DSA-65)
- [ ] Identical output to sequential version
- [ ] Works without Rayon (fallback)

---

### 1.3 Cache-Aligned Structures

#### Red Phase Tests

```rust
#[test]
fn test_poly_alignment() {
    let poly = Poly::zero();
    let ptr = poly.coeffs.as_ptr() as usize;
    assert_eq!(ptr % 32, 0, "Poly not 32-byte aligned");
}

#[test]
fn test_polyvec_alignment() {
    let vec = PolyVecK::<6>::default();
    for i in 0..6 {
        let ptr = vec.polys[i].coeffs.as_ptr() as usize;
        assert_eq!(ptr % 32, 0, "PolyVecK[{}] not aligned", i);
    }
}
```

#### Green Phase Implementation

| File | Change | Expected Impact |
|------|--------|-----------------|
| `poly.rs` | `#[repr(align(32))]` on Poly | Cache-friendly |
| `poly.rs` | Aligned allocator for heap polys | 5-10% speedup |

#### Acceptance Criteria
- [ ] All Poly instances 32-byte aligned
- [ ] No performance regression on unaligned fallback

---

## Phase 2: Core Optimizations

### 2.1 AVX2 NTT

#### Red Phase Tests

```rust
#[test]
fn bench_ntt_avx2_target() {
    // Target: < 5 µs (current ~20 µs for ML-DSA-65)
    let mut poly = random_poly();
    let start = Instant::now();
    for _ in 0..100 {
        poly.ntt();
        poly.inv_ntt();
    }
    let elapsed = start.elapsed() / 200; // 200 transforms
    assert!(elapsed < Duration::from_micros(5),
        "NTT took {:?}, target < 5µs", elapsed);
}

#[test]
fn test_ntt_avx2_correctness() {
    // AVX2 NTT must match scalar NTT exactly
    let poly = random_poly();

    let mut scalar = poly.clone();
    ntt_scalar(&mut scalar);

    let mut avx2 = poly.clone();
    ntt_avx2(&mut avx2);

    assert_eq!(scalar.coeffs, avx2.coeffs, "AVX2 NTT differs from scalar");
}

#[test]
fn test_ntt_avx2_roundtrip() {
    let original = random_poly();
    let mut poly = original.clone();

    ntt_avx2(&mut poly);
    inv_ntt_avx2(&mut poly);

    // Should be identical after NTT->InvNTT
    for i in 0..256 {
        assert_eq!(original.coeffs[i], poly.coeffs[i],
            "Roundtrip failed at coeff {}", i);
    }
}
```

#### Green Phase Implementation

| File | Change | Expected Impact |
|------|--------|-----------------|
| `ntt.rs` | `ntt_avx2()` with layer merging | 5x speedup |
| `ntt.rs` | `inv_ntt_avx2()` matching | 5x speedup |
| `ntt.rs` | Precomputed ZETAS in SIMD layout | Better cache |
| `ntt.rs` | Montgomery mul with `vpmulld` | Vectorized reduce |

#### Acceptance Criteria
- [ ] NTT < 5 µs
- [ ] InvNTT < 5 µs
- [ ] Bit-exact match with scalar implementation
- [ ] All KAT tests still pass

---

### 2.2 Batch NTT

#### Red Phase Tests

```rust
#[test]
fn bench_batch_ntt_target() {
    // Process 4 polynomials: target < 8 µs total (< 2 µs each)
    let mut polys = [Poly::zero(); 4];
    for p in &mut polys { *p = random_poly(); }

    let start = Instant::now();
    for _ in 0..100 {
        ntt_batch_4(&mut polys);
    }
    let elapsed = start.elapsed() / 100;
    assert!(elapsed < Duration::from_micros(8),
        "Batch NTT took {:?}, target < 8µs for 4 polys", elapsed);
}

#[test]
fn test_batch_ntt_correctness() {
    let mut polys = [random_poly(), random_poly(), random_poly(), random_poly()];
    let expected: Vec<_> = polys.iter().map(|p| {
        let mut c = p.clone();
        ntt_scalar(&mut c);
        c
    }).collect();

    ntt_batch_4(&mut polys);

    for (i, (got, want)) in polys.iter().zip(expected.iter()).enumerate() {
        assert_eq!(got.coeffs, want.coeffs, "Batch NTT[{}] differs", i);
    }
}
```

#### Green Phase Implementation

| File | Change | Expected Impact |
|------|--------|-----------------|
| `ntt.rs` | `ntt_batch_4()` interleaved processing | 3x throughput |
| `ntt.rs` | `inv_ntt_batch_4()` matching | 3x throughput |
| `poly.rs` | Use batch NTT in `PolyVecK::ntt()` | Automatic benefit |

#### Acceptance Criteria
- [ ] Batch-4 NTT < 8 µs total
- [ ] Identical results to individual NTTs
- [ ] Integrated into PolyVecK operations

---

## Phase 3: Advanced Optimizations

### 3.1 SIMD Keccak (4-way)

#### Red Phase Tests

```rust
#[test]
fn bench_shake256_4way_target() {
    // Process 4 independent SHAKE256 instances
    // Target: < 2 µs per instance (current ~6 µs)
    let inputs = [b"input1", b"input2", b"input3", b"input4"];
    let mut outputs = [[0u8; 136]; 4];

    let start = Instant::now();
    for _ in 0..1000 {
        shake256_4way(&inputs, &mut outputs);
    }
    let elapsed = start.elapsed() / 4000; // 4000 total hashes
    assert!(elapsed < Duration::from_micros(2),
        "SHAKE256 4-way took {:?}/hash, target < 2µs", elapsed);
}

#[test]
fn test_shake256_4way_correctness() {
    let inputs = [b"test1", b"test2", b"test3", b"test4"];
    let mut outputs_4way = [[0u8; 64]; 4];
    shake256_4way(&inputs, &mut outputs_4way);

    // Compare with individual SHAKE256
    for (i, input) in inputs.iter().enumerate() {
        let mut expected = [0u8; 64];
        Shake256::digest(*input, &mut expected);
        assert_eq!(outputs_4way[i], expected, "4-way SHAKE[{}] differs", i);
    }
}
```

#### Green Phase Implementation

| File | Change | Expected Impact |
|------|--------|-----------------|
| `shake.rs` | `KeccakState4` for 4-way parallel | Core structure |
| `shake.rs` | AVX2 Keccak-f[1600] x4 | 3.75x speedup |
| `sampling.rs` | Use 4-way in `expand_a` | Combined benefit |

#### Acceptance Criteria
- [ ] 4-way SHAKE256 < 8 µs for 4 instances
- [ ] Bit-exact output matching sequential
- [ ] Integrated into ExpandA

---

## Integration Tests

### End-to-End Performance Targets

```rust
#[test]
fn bench_mldsa65_keygen_mvo() {
    // Minimum Viable Optimization target
    let start = Instant::now();
    for _ in 0..100 {
        let _ = MlDsa65::generate_keypair();
    }
    let elapsed = start.elapsed() / 100;
    assert!(elapsed < Duration::from_micros(100),
        "keygen {:?} > 100µs MVO target", elapsed);
}

#[test]
fn bench_mldsa65_sign_mvo() {
    let (sk, _) = MlDsa65::generate_keypair();
    let msg = b"benchmark message";

    let start = Instant::now();
    for _ in 0..100 {
        let _ = MlDsa65::sign(&sk, msg);
    }
    let elapsed = start.elapsed() / 100;
    assert!(elapsed < Duration::from_micros(150),
        "sign {:?} > 150µs MVO target", elapsed);
}

#[test]
fn bench_mldsa65_verify_mvo() {
    let (sk, vk) = MlDsa65::generate_keypair();
    let msg = b"benchmark message";
    let sig = MlDsa65::sign(&sk, msg);

    let start = Instant::now();
    for _ in 0..100 {
        let _ = MlDsa65::verify(&vk, msg, &sig);
    }
    let elapsed = start.elapsed() / 100;
    assert!(elapsed < Duration::from_micros(80),
        "verify {:?} > 80µs MVO target", elapsed);
}
```

---

## Test File Structure

```
crates/arcanum-pqc/
├── src/ml_dsa/
│   ├── ntt.rs              # Add AVX2 NTT
│   ├── ntt_avx2.rs         # NEW: AVX2 implementation
│   ├── poly.rs             # Add SIMD poly ops
│   ├── poly_avx2.rs        # NEW: AVX2 poly operations
│   └── sampling.rs         # Add parallel ExpandA
│
├── tests/
│   ├── kat_vectors.rs      # Existing KAT tests
│   └── optimization_benchmarks.rs  # NEW: Performance targets
│
└── benches/
    └── pqc_benchmarks.rs   # Criterion benchmarks (already exists)
```

---

## Execution Order

### Week 1: Phase 1 (Quick Wins)
1. Write Red Phase tests for poly arithmetic
2. Implement AVX2 poly_add/sub/reduce → Green
3. Write Red Phase tests for ExpandA parallel
4. Implement Rayon ExpandA → Green
5. Add cache alignment → Green
6. **Checkpoint**: Run full benchmark, document results

### Week 2: Phase 2 (Core)
1. Write Red Phase tests for AVX2 NTT
2. Implement AVX2 NTT/InvNTT → Green
3. Write Red Phase tests for Batch NTT
4. Implement Batch NTT → Green
5. **Checkpoint**: Run full benchmark, compare to spec estimates

### Week 3: Phase 3 (Advanced)
1. Write Red Phase tests for SIMD Keccak
2. Implement 4-way Keccak → Green
3. Integrate into ExpandA
4. **Final Review**: Compare to all acceptance criteria

---

## Success Metrics

| Phase | Test | Current | Target | Status |
|-------|------|---------|--------|--------|
| 1.1 | poly_add | ~200 ns | < 50 ns | ⬜ Red |
| 1.2 | expand_a | ~75 µs | < 40 µs | ⬜ Red |
| 1.3 | alignment | unaligned | 32-byte | ⬜ Red |
| 2.1 | ntt | ~20 µs | < 5 µs | ⬜ Red |
| 2.2 | batch_ntt_4 | ~80 µs | < 8 µs | ⬜ Red |
| 3.1 | shake_4way | ~24 µs | < 8 µs | ⬜ Red |
| E2E | keygen | 188 µs | < 100 µs | ⬜ Red |
| E2E | sign | 223 µs | < 150 µs | ⬜ Red |
| E2E | verify | 155 µs | < 80 µs | ⬜ Red |

---

*TDD Principle: Write the test first, watch it fail, then implement just enough to pass.*
