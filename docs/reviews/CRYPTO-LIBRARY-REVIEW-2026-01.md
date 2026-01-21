# Arcanum Cryptographic Library Review

**Date**: January 2026
**Reviewer**: Claude (Opus 4.5)
**Scope**: Full library review with focus on post-quantum implementations
**Branch**: `claude/review-crypto-library-K6HtK`

---

## Executive Summary

Arcanum is a well-architected Rust cryptographic library implementing both classical and post-quantum primitives. The codebase demonstrates careful attention to security fundamentals: constant-time operations, proper memory zeroization, and comprehensive test coverage. The library's transparency about its audit status in `SECURITY.md` is commendable.

The custom **Arcanum-DSA** variant requires scrutiny. While the SIMD optimization rationale is sound, parameter modifications to standardized algorithms carry inherent risk and should be clearly communicated to users.

**Overall Assessment**: Suitable for evaluation, research, and non-critical applications. Production use in high-security contexts should await formal audit.

---

## 1. Architecture Review

### 1.1 Crate Structure

The 12-crate modular design is well-organized:

| Crate | Purpose | Risk Level |
|-------|---------|------------|
| `arcanum-core` | Secure memory, traits | Low |
| `arcanum-primitives` | Native SIMD implementations | Medium |
| `arcanum-pqc` | ML-KEM, ML-DSA, SLH-DSA, **Arcanum-DSA** | High |
| `arcanum-symmetric` | AES-GCM, ChaCha20-Poly1305 | Medium |
| `arcanum-signatures` | Ed25519, ECDSA | Medium |
| Others | Supporting infrastructure | Low |

**Strength**: Clear separation of concerns. Each crate has a focused responsibility.

**Observation**: The `arcanum-pqc` crate mixes NIST-standardized implementations (ML-DSA) with the custom Arcanum-DSA variant. Consider clearer API-level separation to prevent accidental use of non-standard algorithms when FIPS compliance is required.

### 1.2 Dependency Management

The library uses established dependencies (RustCrypto ecosystem, `zeroize`, `subtle`) which reduces implementation risk for classical algorithms. The post-quantum implementations are notably native Rust without external PQC library dependencies.

---

## 2. ML-DSA Implementation Analysis

### 2.1 FIPS 204 Compliance

The ML-DSA implementation in `crates/arcanum-pqc/src/ml_dsa/` follows the FIPS 204 specification:

**Correct implementations observed:**
- NTT with proper Montgomery arithmetic (`ntt.rs:80-86`)
- ZETAS array matches reference implementation (`ntt.rs:34-67`)
- Power2Round and Decompose algorithms (`rounding.rs:41-51, 86-109`)
- Rejection sampling loop structure (`sign.rs:98-268`)

**Code reference**: The signing algorithm correctly implements the FIPS 204 rejection loop:
```
sign.rs:178-201 - Norm checks for z and r₀
sign.rs:217-228 - ct₀ norm check
sign.rs:254-257 - Hint weight check
```

### 2.2 Side-Channel Considerations

**Constant-time operations** (correctly implemented):
- Montgomery reduction uses arithmetic, not branches (`ntt.rs:80-86`)
- `cond_reduce` uses arithmetic masking (`ntt.rs:107-110`)
- `power2round`, `decompose`, and `use_hint` use arithmetic masking (`rounding.rs`)

**Variable-time operations** (documented as acceptable per FIPS 204):
- Rejection sampling loop iteration count
- `ExpandA`, `SampleInBall` (operate on public data)

**Addressed**: The `decompose` function was updated to use constant-time arithmetic
masking instead of data-dependent branches, providing defense-in-depth for
intermediate computations involving secret values.

### 2.3 Test Coverage

The test infrastructure is comprehensive:
- **KAT vectors**: 27,625 lines in `tests/kat_vectors.rs`
- **Unit tests**: Each module has inline tests
- **Roundtrip tests**: Sign/verify across all parameter sets

**Gap identified**: No explicit ACVP (Automated Cryptographic Validation Protocol) test harness, though the documentation claims ACVP validation. Consider adding the actual ACVP response files.

---

## 3. Arcanum-DSA Analysis (Critical)

### 3.1 Parameter Modifications

Arcanum-DSA modifies ML-DSA parameters to optimize for 4-way SIMD:

| Variant | ML-DSA | Arcanum-DSA | Change |
|---------|--------|-------------|--------|
| Level 2 | K=4, L=4 | K=4, L=4 | None |
| Level 3 | K=6, L=5 | K=7, L=4 | **K+1, L-1** |
| Level 5 | K=8, L=7 | K=8, L=8 | **L+1** |

### 3.2 Security Dimension Analysis

The documentation at `arcanum_dsa/mod.rs:42-47` claims security equivalence based on lattice dimension N×(K+L):

| Variant | Arcanum Dimension | ML-DSA Dimension | Margin |
|---------|-------------------|------------------|--------|
| Arcanum-44 | 2048 | 2048 | 0% |
| Arcanum-65 | 2816 | 2816 | 0% |
| Arcanum-87 | 4096 | 3840 | +7% |

**Assessment**: The dimension-based security argument is **partially correct but incomplete**.

Security of lattice signatures depends on multiple factors:
1. **Lattice dimension** (preserved) ✓
2. **Secret distribution** (η unchanged) ✓
3. **Challenge weight** (τ unchanged) ✓
4. **Rejection bound** (β = τ×η, unchanged) ✓
5. **Signature distribution** (affected by K/L ratio) ⚠️

### 3.3 Arcanum-65 Specific Concerns

The Arcanum-65 variant (K=7, L=4 vs ML-DSA-65's K=6, L=5) deserves careful consideration:

**Claimed benefits** (from `params.rs:107-124`):
- 20% less ExpandMask work (L=4 vs L=5)
- Perfect 4-way SIMD batching
- 19% smaller signatures (2670 vs 3309 bytes)

**Technical accuracy**: These claims are mathematically correct.

**Security consideration**: Reducing L from 5 to 4 changes the masking polynomial distribution. The masking polynomial y has L components sampled from [-γ₁+1, γ₁]. With L=4 instead of L=5:
- The response vector z = y + cs₁ has 4 components instead of 5
- This changes the statistical properties of the signature

While the lattice dimension is preserved (256×11 = 2816 for both), the **signature distribution** is different. The security proof may need re-examination for this parameter set.

**Recommendation**:
1. Commission a cryptographic review specifically for Arcanum-65 parameters
2. Add explicit warning in documentation that this is a non-standard parameter set
3. Consider whether the performance benefit (est. 20% signing speedup) justifies the deviation from NIST standard

### 3.4 Compile-Time Validation

The parameter validation at `params.rs:234-279` is well-implemented:
```rust
const fn validate_params<P: ArcanumDsaParams>() {
    const_assert(P::L % 4 == 0, "L must be multiple of 4 for SIMD");
    const_assert(P::DIMENSION >= P::ML_DSA_EQUIVALENT_DIM, ...);
    const_assert(P::BETA == (P::TAU * P::ETA) as u32, ...);
    // ... etc
}
```

This prevents accidental parameter misconfiguration at compile time.

---

## 4. Implementation Quality

### 4.1 Memory Safety

**Strengths**:
- Uses Rust's ownership system throughout
- `SecureVec` and `SecretBytes` types in `arcanum-core` provide zeroization
- No `unsafe` code in core cryptographic operations (except SIMD paths)

**SIMD unsafe code** (`ntt_avx2.rs`, `poly_simd.rs`):
- Properly gated behind `#[cfg(all(feature = "simd", target_arch = "x86_64"))]`
- Uses `#[allow(unsafe_code)]` explicitly, making unsafe blocks auditable

### 4.2 Error Handling

The `MlDsaError` enum at `ml_dsa/mod.rs:238-248` is appropriately minimal:
```rust
pub enum MlDsaError {
    VerificationFailed,
    InvalidKey,
    InvalidSignature,
    InternalError,
}
```

**Note**: Error messages don't leak sensitive information. This is correct.

### 4.3 Code Documentation

Documentation quality is high:
- Module-level documentation explains algorithms
- Security considerations documented inline
- Cross-references to FIPS specifications

---

## 5. Identified Issues

### 5.1 High Priority

| Issue | Location | Severity | Status |
|-------|----------|----------|--------|
| Arcanum-65 non-standard parameters | `arcanum_dsa/params.rs` | Medium | Open - Recommend cryptographic review |
| ACVP claim accuracy | `SECURITY.md` | Low | **RESOLVED** - Clarified as ACVP-style methodology |

### 5.2 Medium Priority

| Issue | Location | Severity | Status |
|-------|----------|----------|--------|
| `decompose` uses branching on data | `rounding.rs` | Low | **RESOLVED** - Now uses constant-time arithmetic masking |
| `TODO` comments in key parsing | `ml_dsa/mod.rs:112-114` | Low | **RESOLVED** - Proper FIPS 204 key byte extraction implemented |

### 5.3 Observations (Not Issues)

- The SECURITY.md transparency is exemplary
- Test coverage is substantial but fuzzing is explicitly noted as missing
- The library correctly uses `getrandom` for entropy
- Dependabot configured for automated dependency security monitoring

---

## 6. Recommendations

### For Maintainers

1. **Arcanum-DSA Positioning**: Consider whether Arcanum-DSA should be:
   - A clearly-marked experimental module
   - Behind a feature flag (`experimental-dsa`)
   - Accompanied by a threat model document

2. **ACVP Integration**: Add actual ACVP test vectors to demonstrate FIPS compliance

3. **Fuzzing Campaign**: The SECURITY.md notes this is missing. Consider OSS-Fuzz integration

### For Users

1. **For FIPS compliance**: Use `MlDsa44/65/87`, not `ArcanumDsa*` variants

2. **For performance-critical non-FIPS contexts**: Arcanum-DSA may be appropriate if you accept:
   - Non-standard parameters
   - Need for independent security analysis

3. **For production**: Wait for formal audit or conduct your own

---

## 7. Conclusion

Arcanum demonstrates strong engineering practices for a cryptographic library. The NIST PQC implementations (ML-DSA, ML-KEM, SLH-DSA) follow specifications correctly with appropriate test coverage.

The Arcanum-DSA custom variant is technically interesting but represents a deviation from standardized parameters. The security argument based on preserved lattice dimension is reasonable but not complete. This variant should be treated as experimental until independently validated.

The library's self-awareness about its audit status and the comprehensive SECURITY.md disclosure demonstrates the kind of responsible approach that builds long-term trust in the cryptographic community.

---

**Document Hash**: This review covers commits up to `6b4ec7e` (updated with resolutions)
**Methodology**: Static code review, documentation analysis, test examination
