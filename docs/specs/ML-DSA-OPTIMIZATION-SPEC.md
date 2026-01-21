# ML-DSA Optimization Specification

**Document ID:** SPEC-OPT-MLDSA-001
**Version:** 1.0
**Date:** 2026-01-21
**Author:** Arcanum Development Team
**Status:** Draft

---

## 1. Executive Summary

This specification defines optimization strategies for Arcanum's native ML-DSA (FIPS 204) implementation. The goal is to achieve performance parity with tier-1 implementations (libcrux/pqc-combo) while maintaining pure Rust safety guarantees.

### Current vs Target Performance (ML-DSA-65)

| Operation | Current | Target | Required Speedup |
|-----------|---------|--------|------------------|
| keygen    | 188 µs  | 40 µs  | 4.7x |
| sign      | 223 µs  | 90 µs  | 2.5x |
| verify    | 155 µs  | 40 µs  | 3.9x |

### Peer Benchmarks (Reference)

| Implementation | keygen | sign | verify | Notes |
|----------------|--------|------|--------|-------|
| **Ours (current)** | 188 µs | 223 µs | 155 µs | Pure Rust, no SIMD |
| pqc-combo/libcrux | 30 µs | 80 µs | 29 µs | AVX2/NEON optimized |
| itzmeanjan C++ (Intel) | 93 µs | 604 µs | 95 µs | Reference-style |
| itzmeanjan C++ (ARM) | 126 µs | 879 µs | 134 µs | Graviton4 |

---

## 2. Profiling Analysis

### 2.1 Theoretical Cost Breakdown (ML-DSA-65)

Based on FIPS 204 algorithm analysis:

| Component | KeyGen | Sign | Verify | Optimization Priority |
|-----------|--------|------|--------|----------------------|
| **ExpandA (SHAKE128)** | 40% | 15% | 15% | HIGH |
| **NTT/InvNTT** | 25% | 35% | 40% | HIGH |
| **Poly arithmetic** | 15% | 20% | 25% | MEDIUM |
| **SampleInBall** | - | 5% | 5% | LOW |
| **ExpandMask** | - | 10% | - | MEDIUM |
| **Hint/Rounding** | 5% | 10% | 10% | LOW |
| **Packing/Unpacking** | 15% | 5% | 5% | LOW |

### 2.2 Hotspot Identification

1. **NTT Butterfly Operations** - 256 coefficients × log₂(256) = 2048 butterflies per transform
2. **Matrix-Vector Multiplication** - K×L matrix × L-vector = K×L NTTs + K polynomial additions
3. **SHAKE XOF** - ExpandA generates K×L×256×3 bytes ≈ 115KB for ML-DSA-65

---

## 3. Optimization Strategies

### 3.1 AVX2 NTT (Priority: HIGH)

**Rationale:** NTT is the dominant operation in ML-DSA. AVX2 can process 8 coefficients simultaneously.

**Approach:** Vectorized Cooley-Tukey with layer merging

```
Layer 0-3: Use vpmulld for 8-way parallel butterfly
Layer 4-7: Transpose and continue 8-way operations
```

**Expected Gains:**
| Parameter Set | Current NTT | Estimated AVX2 | Speedup |
|---------------|-------------|----------------|---------|
| ML-DSA-44 | ~15 µs | ~3 µs | 5x |
| ML-DSA-65 | ~20 µs | ~4 µs | 5x |
| ML-DSA-87 | ~25 µs | ~5 µs | 5x |

**Implementation Notes:**
- Use `_mm256_mullo_epi32` for coefficient multiplication
- Montgomery reduction via `_mm256_srli_epi64` and mask operations
- Precompute ZETAS in bit-reversed order for sequential access
- Cache-align polynomial arrays (32-byte for AVX2)

**Risk:** Medium - Requires careful Montgomery arithmetic in SIMD

### 3.2 Parallel ExpandA (Priority: HIGH)

**Rationale:** ExpandA generates K×L independent matrix entries. Each can be computed in parallel.

**Approach:**
- Option A: Rayon parallel iteration (simple, ~2-4x speedup)
- Option B: Batch SHAKE (process multiple XOF instances with SIMD Keccak)

**Expected Gains (ML-DSA-65, K=6, L=5 = 30 entries):**
| Approach | Current | Estimated | Speedup |
|----------|---------|-----------|---------|
| Sequential | 75 µs | 75 µs | 1x |
| Rayon (4 threads) | - | 25 µs | 3x |
| SIMD Keccak (4-way) | - | 20 µs | 3.75x |

**Implementation Notes:**
- Lesson from BLAKE3: Rayon grain size matters (256 chunks optimal for L2)
- For ExpandA, each entry is independent - perfect for Rayon
- Consider hybrid: Rayon + SIMD Keccak for maximum throughput

**Risk:** Low - Simple parallelization pattern

### 3.3 SIMD Polynomial Arithmetic (Priority: MEDIUM)

**Rationale:** Coefficient-wise operations (add, sub, reduce) are trivially vectorizable.

**Approach:** Replace scalar loops with AVX2 operations

```rust
// Current: 256 scalar iterations
for i in 0..256 {
    result.coeffs[i] = (a.coeffs[i] + b.coeffs[i]) % Q;
}

// Optimized: 32 AVX2 iterations
for i in 0..32 {
    let va = _mm256_loadu_si256(&a.coeffs[i*8]);
    let vb = _mm256_loadu_si256(&b.coeffs[i*8]);
    let vr = _mm256_add_epi32(va, vb);
    // Conditional reduce...
}
```

**Expected Gains:**
| Operation | Current | Estimated | Speedup |
|-----------|---------|-----------|---------|
| poly_add | ~200 ns | ~30 ns | 6.7x |
| poly_sub | ~200 ns | ~30 ns | 6.7x |
| poly_reduce | ~500 ns | ~80 ns | 6.3x |

**Risk:** Low - Straightforward vectorization

### 3.4 Batch NTT (Priority: MEDIUM)

**Rationale:** ML-DSA processes multiple polynomials (L=7 for ML-DSA-87). Batch processing amortizes overhead.

**Approach:** Process 4 or 8 polynomials simultaneously using interleaved SIMD

**Expected Gains:**
| Batch Size | Per-Poly NTT | Per-Poly Batch | Speedup |
|------------|--------------|----------------|---------|
| 1 (current) | 20 µs | 20 µs | 1x |
| 4 | - | 6 µs | 3.3x |
| 8 | - | 4 µs | 5x |

**Risk:** Medium - Increased code complexity

### 3.5 SIMD SHAKE/Keccak (Priority: MEDIUM-HIGH)

**Rationale:** SHAKE is used extensively in keygen (ExpandA) and sign (ExpandMask). SIMD Keccak can process 4 instances in parallel.

**Approach:** 4-way parallel Keccak using AVX2 (KeccakP1600times4)

**Expected Gains:**
| Component | Current | Estimated | Speedup |
|-----------|---------|-----------|---------|
| ExpandA (ML-DSA-65) | 75 µs | 20 µs | 3.75x |
| ExpandMask | 20 µs | 6 µs | 3.3x |

**Implementation Notes:**
- Reference: XKCP (eXtended Keccak Code Package) has optimized AVX2 Keccak
- Each ExpandA row (L entries) can use 4-way parallel SHAKE
- Combine with Rayon for row-level parallelism

**Risk:** High - Complex implementation, but high payoff

---

## 4. Implementation Phases

### Phase 1: Quick Wins (1-2x speedup)
**Estimated Total Improvement: 1.5-2x**

1. **SIMD Polynomial Arithmetic**
   - Expected: 6x faster poly ops
   - Impact on overall: ~15-20% speedup

2. **Parallel ExpandA (Rayon)**
   - Expected: 3x faster ExpandA
   - Impact on overall: ~20-30% speedup

3. **Cache-Aligned Structures**
   - Align Poly arrays to 32 bytes
   - Expected: 5-10% speedup

### Phase 2: Core Optimizations (3-4x speedup)
**Estimated Total Improvement: 3-4x**

4. **AVX2 NTT**
   - Expected: 5x faster NTT
   - Impact on overall: ~40-50% additional speedup

5. **Batch NTT for Vector Operations**
   - Expected: 3x faster vector NTT
   - Impact on overall: ~20% additional speedup

### Phase 3: Advanced Optimizations (5-6x speedup)
**Estimated Total Improvement: 5-6x**

6. **SIMD Keccak (4-way)**
   - Expected: 3.75x faster SHAKE
   - Impact on overall: ~30% additional speedup

7. **Monolithic Signing Loop**
   - Reduce function call overhead in rejection loop
   - Expected: 10-15% additional speedup

---

## 5. Estimated Results

### 5.1 Conservative Estimates (Phase 1+2 only)

| Operation | Current | Phase 1 | Phase 2 | Speedup |
|-----------|---------|---------|---------|---------|
| ML-DSA-65 keygen | 188 µs | 130 µs | 55 µs | 3.4x |
| ML-DSA-65 sign | 223 µs | 160 µs | 70 µs | 3.2x |
| ML-DSA-65 verify | 155 µs | 110 µs | 45 µs | 3.4x |

### 5.2 Optimistic Estimates (All Phases)

| Operation | Current | Target | Achievable |
|-----------|---------|--------|------------|
| ML-DSA-65 keygen | 188 µs | 40 µs | 45-55 µs |
| ML-DSA-65 sign | 223 µs | 90 µs | 60-80 µs |
| ML-DSA-65 verify | 155 µs | 40 µs | 35-45 µs |

### 5.3 Comparison with Peers (Post-Optimization)

| Implementation | keygen | sign | verify |
|----------------|--------|------|--------|
| pqc-combo/libcrux | 30 µs | 80 µs | 29 µs |
| **Arcanum (projected)** | 45-55 µs | 60-80 µs | 35-45 µs |
| Gap | 1.5-1.8x | 0.75-1x | 1.2-1.5x |

**Analysis:** We can likely match or beat libcrux on signing (which is dominated by NTT) but keygen/verify may remain 1.5x slower due to SHAKE overhead.

---

## 6. Lessons Learned (From Arcanum Optimization History)

Per `/docs/OPTIMIZATION-LESSONS.md`:

### DO:
- ✅ Use intrinsics, not inline assembly (6% faster)
- ✅ Trust LLVM for instruction scheduling
- ✅ Keep hot loops simple (no adaptive branches)
- ✅ Check alignment before SIMD streaming stores
- ✅ Use Rayon with appropriate grain sizes

### DON'T:
- ❌ Try to outsmart CPU OOO execution (43% regression)
- ❌ Add branches to hot loops for marginal gains
- ❌ Use horizontal SIMD for sequential algorithms (60% slower)
- ❌ Assume user buffers are aligned

---

## 7. Acceptance Criteria

### Minimum Viable Optimization (MVO)
- [ ] ML-DSA-65 keygen ≤ 100 µs (1.9x speedup)
- [ ] ML-DSA-65 sign ≤ 150 µs (1.5x speedup)
- [ ] ML-DSA-65 verify ≤ 80 µs (1.9x speedup)
- [ ] All existing tests pass
- [ ] 0% verification failure rate maintained

### Target Performance
- [ ] ML-DSA-65 keygen ≤ 60 µs (3.1x speedup)
- [ ] ML-DSA-65 sign ≤ 90 µs (2.5x speedup)
- [ ] ML-DSA-65 verify ≤ 50 µs (3.1x speedup)
- [ ] Competitive with libcrux within 2x

### Stretch Goal
- [ ] ML-DSA-65 keygen ≤ 45 µs
- [ ] ML-DSA-65 sign ≤ 70 µs
- [ ] ML-DSA-65 verify ≤ 40 µs

---

## 8. Feature Flags

```toml
[features]
# Default: portable implementation
default = ["std"]

# SIMD acceleration (AVX2/NEON)
simd = ["std"]

# Multi-threaded operations
rayon = ["dep:rayon", "std"]

# Combined optimization
optimized = ["simd", "rayon"]
```

---

## 9. Testing Requirements

1. **Correctness Tests**
   - All existing KAT tests must pass
   - ACVP compliance maintained
   - 0% verification failure rate

2. **Performance Regression Tests**
   - Benchmark before/after each optimization
   - Document results in commit messages
   - Alert if regression >5%

3. **Platform Coverage**
   - x86_64 with AVX2
   - x86_64 without AVX2 (fallback)
   - aarch64 (future NEON support)

---

## 10. Appendix: Technical References

### A. ML-DSA Algorithm Complexity

| Operation | NTTs | InvNTTs | SHAKE Calls | Poly Ops |
|-----------|------|---------|-------------|----------|
| KeyGen | K×L | K | K×L + 1 | K×L + K |
| Sign | 2K×L | K + L | 2 | Complex |
| Verify | K×L | K | 1 | K×L + K |

### B. AVX2 Instruction Reference

| Instruction | Use Case | Throughput |
|-------------|----------|------------|
| `vpmulld` | 32-bit multiply | 0.5 CPI |
| `vpaddd` | 32-bit add | 0.33 CPI |
| `vpand` | Bitwise AND | 0.33 CPI |
| `vpsrld` | Logical shift | 0.5 CPI |
| `vpshufb` | Byte shuffle | 1 CPI |

### C. Montgomery Arithmetic in SIMD

```rust
// Montgomery reduction: x * R^(-1) mod Q
fn montgomery_reduce_avx2(x: __m256i) -> __m256i {
    let qinv = _mm256_set1_epi32(QINV as i32);
    let q = _mm256_set1_epi32(Q as i32);

    // t = (x * QINV) mod 2^32
    let t = _mm256_mullo_epi32(x, qinv);

    // x + t*Q (high 32 bits)
    let tq = _mm256_mul_epi32(t, q);  // 64-bit result
    let tq_hi = _mm256_srli_epi64(tq, 32);

    // ... additional masking for correct lane handling
}
```

---

*Document Version History:*
- v1.0 (2026-01-21): Initial specification
