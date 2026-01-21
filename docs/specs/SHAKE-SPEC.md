# SHAKE (SHA-3 XOF) Implementation Specification

**Version**: 1.0.0
**Status**: Draft
**Target**: arcanum-primitives
**Standards**: FIPS 202 (SHA-3), NIST SP 800-185 (SHA-3 Derived Functions)
**Date**: 2026-01-20

---

## 1. Executive Summary

This specification defines the implementation of SHAKE128 and SHAKE256 (Extendable-Output Functions based on Keccak) for the Arcanum primitives library. SHAKE is required for ML-DSA (FIPS 204) and other post-quantum algorithms.

### 1.1 Why Native Implementation?

- **ML-DSA Dependency**: SHAKE128/256 are required for all ML-DSA hash functions
- **No External Dependencies**: Maintains arcanum-primitives' zero-dependency philosophy
- **XOF Support**: Native support for arbitrary-length output (critical for ML-DSA sampling)
- **Consistency**: Follows established SHA-2/BLAKE3 patterns in arcanum-primitives
- **Future PQC**: Other PQC algorithms (ML-KEM native) will also need SHAKE

### 1.2 Scope

| Function | Security | Rate | Capacity | Output |
|----------|----------|------|----------|--------|
| SHAKE128 | 128-bit | 168 bytes | 32 bytes | Arbitrary (XOF) |
| SHAKE256 | 256-bit | 136 bytes | 64 bytes | Arbitrary (XOF) |

### 1.3 Consumers

| Consumer | Uses | Functions |
|----------|------|-----------|
| ML-DSA | Matrix expansion, sampling | SHAKE128, SHAKE256 |
| ML-KEM (native) | Future native implementation | SHAKE128, SHAKE256 |
| cSHAKE | Customizable SHAKE | SHAKE128, SHAKE256 |

---

## 2. Algorithm Overview

### 2.1 Keccak Sponge Construction

SHAKE is built on the Keccak-p[1600,24] permutation using the sponge construction:

```
Keccak Sponge
┌────────────────────────────────────────────────────────────────┐
│                     1600-bit State                              │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ rate (r bits) │ capacity (c bits)                        │  │
│  │  absorb/squeeze│  security margin                        │  │
│  └──────────────────────────────────────────────────────────┘  │
├────────────────────────────────────────────────────────────────┤
│                    Absorb Phase                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ For each r-bit block of padded input:                     │  │
│  │   1. XOR block into first r bits of state                 │  │
│  │   2. Apply Keccak-p permutation                           │  │
│  └──────────────────────────────────────────────────────────┘  │
├────────────────────────────────────────────────────────────────┤
│                    Squeeze Phase (XOF)                          │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ Until output_len bytes produced:                          │  │
│  │   1. Extract first r bits of state as output              │  │
│  │   2. If more output needed, apply Keccak-p permutation    │  │
│  └──────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────┘
```

### 2.2 Keccak-p[1600,24] Permutation

The permutation consists of 24 rounds, each applying 5 step mappings:

```
Round(A, RC) = ι(χ(π(ρ(θ(A)))), RC)

Where:
  θ (theta)  - Column parity mixing
  ρ (rho)    - Lane rotation
  π (pi)     - Lane permutation
  χ (chi)    - Non-linear mixing
  ι (iota)   - Round constant addition
```

### 2.3 Domain Separation

FIPS 202 uses domain separation via padding suffix:

| Function | Suffix | Padding |
|----------|--------|---------|
| SHA3-256 | 01 | 10*1 |
| SHAKE128 | 1111 | 10*1 |
| SHAKE256 | 1111 | 10*1 |

For SHAKE: `pad(M) = M || 1111 || 10*1` (pad to rate boundary)

---

## 3. Parameter Definitions

### 3.1 SHAKE128

```rust
pub const SHAKE128_RATE: usize = 168;      // r = 1344 bits = 168 bytes
pub const SHAKE128_CAPACITY: usize = 32;   // c = 256 bits = 32 bytes
pub const SHAKE128_SECURITY: usize = 128;  // 128-bit security
```

### 3.2 SHAKE256

```rust
pub const SHAKE256_RATE: usize = 136;      // r = 1088 bits = 136 bytes
pub const SHAKE256_CAPACITY: usize = 64;   // c = 512 bits = 64 bytes
pub const SHAKE256_SECURITY: usize = 256;  // 256-bit security
```

### 3.3 Keccak State

```rust
/// Keccak 1600-bit state as 5×5 array of 64-bit lanes
pub type KeccakState = [[u64; 5]; 5];

/// State size in bytes
pub const STATE_SIZE: usize = 200;  // 1600 bits = 200 bytes

/// Number of rounds
pub const ROUNDS: usize = 24;
```

---

## 4. API Design

### 4.1 Core Types

```rust
/// SHAKE128 XOF (Extendable Output Function)
pub struct Shake128 {
    state: KeccakState,
    buffer: [u8; SHAKE128_RATE],
    buffer_len: usize,
    squeezed: bool,
}

/// SHAKE256 XOF
pub struct Shake256 {
    state: KeccakState,
    buffer: [u8; SHAKE256_RATE],
    buffer_len: usize,
    squeezed: bool,
}

/// SHAKE128 in squeeze (XOF) mode
pub struct Shake128Reader {
    state: KeccakState,
    buffer: [u8; SHAKE128_RATE],
    buffer_pos: usize,
}

/// SHAKE256 in squeeze mode
pub struct Shake256Reader {
    state: KeccakState,
    buffer: [u8; SHAKE256_RATE],
    buffer_pos: usize,
}
```

### 4.2 API Methods

```rust
impl Shake128 {
    /// Create new SHAKE128 instance
    pub fn new() -> Self;

    /// Absorb data into the sponge
    pub fn update(&mut self, data: &[u8]);

    /// Finalize absorb phase and return XOF reader
    /// Consumes self - cannot absorb more after this
    pub fn finalize_xof(self) -> Shake128Reader;

    /// Convenience: absorb and squeeze fixed output
    pub fn digest(data: &[u8], output: &mut [u8]);
}

impl Shake128Reader {
    /// Squeeze arbitrary bytes from XOF
    /// Can be called multiple times for streaming output
    pub fn squeeze(&mut self, output: &mut [u8]);
}

impl Shake256 {
    pub fn new() -> Self;
    pub fn update(&mut self, data: &[u8]);
    pub fn finalize_xof(self) -> Shake256Reader;
    pub fn digest(data: &[u8], output: &mut [u8]);
}

impl Shake256Reader {
    pub fn squeeze(&mut self, output: &mut [u8]);
}
```

### 4.3 Usage Examples

```rust
// Simple hashing with fixed output
let mut output = [0u8; 32];
Shake256::digest(b"input data", &mut output);

// Streaming absorb
let mut shake = Shake256::new();
shake.update(b"part 1");
shake.update(b"part 2");
let mut reader = shake.finalize_xof();

// Streaming squeeze (XOF)
let mut out1 = [0u8; 64];
let mut out2 = [0u8; 128];
reader.squeeze(&mut out1);  // First 64 bytes
reader.squeeze(&mut out2);  // Next 128 bytes

// ML-DSA style: squeeze polynomials
for i in 0..256 {
    let mut bytes = [0u8; 3];
    reader.squeeze(&mut bytes);
    // Parse coefficient from bytes...
}
```

---

## 5. Implementation Details

### 5.1 Keccak-p Permutation

```rust
/// Round constants for ι step
const RC: [u64; 24] = [
    0x0000000000000001, 0x0000000000008082,
    0x800000000000808a, 0x8000000080008000,
    0x000000000000808b, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009,
    0x000000000000008a, 0x0000000000000088,
    0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b,
    0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080,
    0x000000000000800a, 0x800000008000000a,
    0x8000000080008081, 0x8000000000008080,
    0x0000000080000001, 0x8000000080008008,
];

/// Rotation offsets for ρ step (FIPS 202 Table 2)
const RHO: [[u32; 5]; 5] = [
    [0, 1, 62, 28, 27],
    [36, 44, 6, 55, 20],
    [3, 10, 43, 25, 39],
    [41, 45, 15, 21, 8],
    [18, 2, 61, 56, 14],
];

/// Keccak-p[1600,24] permutation
pub fn keccak_p(state: &mut KeccakState) {
    for round in 0..24 {
        // θ step
        theta(state);
        // ρ and π steps (combined for efficiency)
        rho_pi(state);
        // χ step
        chi(state);
        // ι step
        iota(state, round);
    }
}
```

### 5.2 Step Functions

```rust
/// θ (theta) - column parity mixing
fn theta(a: &mut KeccakState) {
    let mut c = [0u64; 5];

    // Compute column parities
    for x in 0..5 {
        c[x] = a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4];
    }

    // Compute D and XOR into state
    for x in 0..5 {
        let d = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
        for y in 0..5 {
            a[x][y] ^= d;
        }
    }
}

/// ρ (rho) and π (pi) - rotation and permutation (combined)
fn rho_pi(a: &mut KeccakState) {
    let mut b = [[0u64; 5]; 5];

    for x in 0..5 {
        for y in 0..5 {
            b[y][(2 * x + 3 * y) % 5] = a[x][y].rotate_left(RHO[x][y]);
        }
    }

    *a = b;
}

/// χ (chi) - non-linear mixing
fn chi(a: &mut KeccakState) {
    for y in 0..5 {
        let t = [a[0][y], a[1][y], a[2][y], a[3][y], a[4][y]];
        for x in 0..5 {
            a[x][y] = t[x] ^ ((!t[(x + 1) % 5]) & t[(x + 2) % 5]);
        }
    }
}

/// ι (iota) - round constant addition
fn iota(a: &mut KeccakState, round: usize) {
    a[0][0] ^= RC[round];
}
```

### 5.3 Absorb and Squeeze

```rust
impl Shake256 {
    /// Absorb a single block
    fn absorb_block(&mut self, block: &[u8]) {
        debug_assert_eq!(block.len(), SHAKE256_RATE);

        // XOR block into state (rate portion only)
        let state_bytes = state_to_bytes(&self.state);
        for i in 0..SHAKE256_RATE {
            state_bytes[i] ^= block[i];
        }
        bytes_to_state(&state_bytes, &mut self.state);

        // Apply permutation
        keccak_p(&mut self.state);
    }

    /// Finalize padding and prepare for squeezing
    fn finalize_absorb(&mut self) {
        // Add SHAKE domain separator (0x1F) and padding
        self.buffer[self.buffer_len] = 0x1F;  // 11111 in SHAKE
        self.buffer_len += 1;

        // Pad with zeros
        for i in self.buffer_len..SHAKE256_RATE {
            self.buffer[i] = 0;
        }

        // Set final padding bit
        self.buffer[SHAKE256_RATE - 1] |= 0x80;

        // Absorb final block
        self.absorb_block(&self.buffer);
    }
}

impl Shake256Reader {
    /// Squeeze bytes from the sponge
    pub fn squeeze(&mut self, output: &mut [u8]) {
        let mut offset = 0;

        while offset < output.len() {
            // Use buffered output first
            if self.buffer_pos < SHAKE256_RATE {
                let available = SHAKE256_RATE - self.buffer_pos;
                let to_copy = core::cmp::min(available, output.len() - offset);
                output[offset..offset + to_copy]
                    .copy_from_slice(&self.buffer[self.buffer_pos..self.buffer_pos + to_copy]);
                self.buffer_pos += to_copy;
                offset += to_copy;
            }

            // If more output needed, squeeze another block
            if offset < output.len() {
                keccak_p(&mut self.state);
                state_to_bytes_into(&self.state, &mut self.buffer);
                self.buffer_pos = 0;
            }
        }
    }
}
```

---

## 6. Constant-Time Requirements

### 6.1 Analysis

| Operation | Timing Risk | Assessment |
|-----------|-------------|------------|
| Keccak permutation | None | Fixed operations on all lanes |
| XOR operations | None | Constant time |
| Rotation | None | Fixed rotation counts |
| Chi step (~AND) | None | Bitwise operations |
| Buffer indexing | Low | Linear access patterns |

**Conclusion**: Keccak is inherently constant-time. No special measures needed beyond avoiding early exits.

### 6.2 Verification

```rust
#[test]
fn test_shake_constant_time() {
    // Keccak processes all state regardless of input
    // No data-dependent branches in permutation
    // Verify by inspection and timing analysis
}
```

---

## 7. Test Strategy

### 7.1 Test Hierarchy

```
Level 1: Unit Tests
├── keccak_permutation_known_answer
├── theta_step_test
├── rho_pi_step_test
├── chi_step_test
├── iota_step_test
└── padding_test

Level 2: Integration Tests
├── shake128_empty_input
├── shake128_short_input
├── shake128_long_input
├── shake256_empty_input
├── shake256_short_input
├── shake256_long_input
├── xof_streaming_test
└── absorb_streaming_test

Level 3: KAT Tests (NIST CAVP)
├── shake128_short_msg
├── shake128_long_msg
├── shake128_variable_out
├── shake256_short_msg
├── shake256_long_msg
└── shake256_variable_out

Level 4: Cross-Validation
└── compare_with_sha3_crate (dev-dependency)
```

### 7.2 NIST Test Vectors

```rust
#[test]
fn test_shake128_short_msg() {
    // NIST CAVP SHAKE128 ShortMsg vectors
    // Len = 0: Output = 7F9C2BA4E88F827D...
    let mut output = [0u8; 32];
    Shake128::digest(&[], &mut output);
    assert_eq!(
        hex::encode(&output),
        "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"
    );
}

#[test]
fn test_shake256_short_msg() {
    // NIST CAVP SHAKE256 ShortMsg vectors
    // Len = 0: Output = 46B9DD2B0BA88D13...
    let mut output = [0u8; 32];
    Shake256::digest(&[], &mut output);
    assert_eq!(
        hex::encode(&output),
        "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"
    );
}
```

---

## 8. Performance Targets

### 8.1 Reference Benchmarks

Based on optimized C implementations:

| Function | Speed | Notes |
|----------|-------|-------|
| Keccak-p | ~10 cycles/byte | AVX2 optimized |
| SHAKE128 absorb | ~6 cycles/byte | Rate = 168 bytes |
| SHAKE256 absorb | ~7.5 cycles/byte | Rate = 136 bytes |

### 8.2 Arcanum Targets

**Phase 1** (Pure Rust):

| Operation | Target | Notes |
|-----------|--------|-------|
| Keccak-p permutation | < 2 µs | 24 rounds |
| SHAKE256 (64 bytes in, 32 out) | < 3 µs | Single squeeze |
| SHAKE128 (32 bytes in, 168 out) | < 3 µs | Full rate output |

**Phase 2** (SIMD optimization):

| Operation | Target | Notes |
|-----------|--------|-------|
| Keccak-p permutation | < 1 µs | AVX2 θ/χ steps |
| Throughput | > 500 MB/s | Long message absorb |

---

## 9. Module Structure

```
crates/arcanum-primitives/src/
├── shake.rs              # Main module, public API
├── keccak.rs             # Keccak-p permutation
└── tests/
    └── shake_tests.rs    # KAT and unit tests
```

Or combined:

```
crates/arcanum-primitives/src/
└── shake.rs              # All in one file (~600 lines)
```

---

## 10. Implementation Phases

### Phase 1: Core Implementation

**Deliverables**:
- [ ] Keccak-p[1600,24] permutation
- [ ] SHAKE128 with XOF support
- [ ] SHAKE256 with XOF support
- [ ] NIST KAT tests passing

**Exit Criteria**:
- All CAVP test vectors pass
- API matches specification
- no_std compatible

### Phase 2: Integration

**Deliverables**:
- [ ] Feature flag `shake` in Cargo.toml
- [ ] Integration with arcanum-pqc
- [ ] ML-DSA dependency unblocked

**Exit Criteria**:
- ML-DSA tests using native SHAKE pass
- Benchmark baseline established

### Phase 3: Optimization (Optional)

**Deliverables**:
- [ ] AVX2 Keccak-p implementation
- [ ] Parallel lane processing
- [ ] Performance benchmarks

**Exit Criteria**:
- Meets Phase 2 performance targets
- No regression in functionality

---

## 11. Cargo.toml Changes

```toml
# crates/arcanum-primitives/Cargo.toml

[features]
default = ["std", "alloc", "simd", "sha2", "blake3", "chacha20poly1305"]
std = ["alloc"]
alloc = []

# Algorithm features
sha2 = []
blake3 = []
chacha20 = []
poly1305 = []
chacha20poly1305 = ["chacha20", "poly1305"]
shake = []  # <-- NEW: SHAKE128/SHAKE256 (Keccak-based XOF)

# ... rest unchanged ...

[dev-dependencies]
# ... existing deps ...
sha3 = "0.10"  # <-- NEW: Reference for KAT validation
```

---

## 12. Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Incorrect permutation | Medium | High | Extensive KAT testing |
| Padding bugs | Medium | High | Test edge cases |
| Performance issues | Low | Medium | Early benchmarking |
| API ergonomics | Low | Low | Follow SHA-2 patterns |

---

## 13. References

1. FIPS 202: SHA-3 Standard
   https://csrc.nist.gov/pubs/fips/202/final

2. NIST CAVP Test Vectors
   https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program

3. Keccak Team Reference
   https://keccak.team/keccak.html

4. The Keccak Sponge Function Family
   https://keccak.team/files/Keccak-reference-3.0.pdf

5. FIPS 204 (ML-DSA) - Primary Consumer
   https://csrc.nist.gov/pubs/fips/204/final

---

*Document Status: Ready for Implementation*
*Next Step: TDD Scaffold → Red Phase → Green Phase*
*Estimated LOC: ~600-800 (excluding tests)*
