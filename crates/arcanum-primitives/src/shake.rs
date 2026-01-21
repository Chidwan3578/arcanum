//! SHAKE128 and SHAKE256 Extendable-Output Functions (XOF)
//!
//! Implementation of FIPS 202 SHAKE based on Keccak sponge construction.
//!
//! **Status**: TDD Scaffold (Red Phase) - Implementation pending.
//!
//! ## Overview
//!
//! SHAKE (Secure Hash Algorithm Keccak) provides extendable output functions
//! that can produce arbitrary-length output, making them ideal for:
//! - Key derivation
//! - Random number generation
//! - Expanding seeds into larger structures (ML-DSA matrices)
//!
//! ## Security Levels
//!
//! | Function | Security | Rate | Output |
//! |----------|----------|------|--------|
//! | SHAKE128 | 128-bit | 168 bytes | Arbitrary |
//! | SHAKE256 | 256-bit | 136 bytes | Arbitrary |
//!
//! ## Example (Future API)
//!
//! ```ignore
//! use arcanum_primitives::shake::{Shake256, Shake256Reader};
//!
//! // Simple hashing with fixed output
//! let mut output = [0u8; 32];
//! Shake256::digest(b"input data", &mut output);
//!
//! // Streaming absorb and squeeze (XOF mode)
//! let mut shake = Shake256::new();
//! shake.update(b"seed");
//! let mut reader = shake.finalize_xof();
//!
//! let mut bytes = [0u8; 64];
//! reader.squeeze(&mut bytes);  // First 64 bytes
//! reader.squeeze(&mut bytes);  // Next 64 bytes (different!)
//! ```

#![allow(dead_code)]
// Allow unsafe code when SIMD is enabled for optimized Keccak
#![cfg_attr(all(feature = "simd", target_arch = "x86_64"), allow(unsafe_code))]

// Import AVX2 Keccak when available
#[cfg(all(feature = "simd", target_arch = "x86_64"))]
use crate::keccak_avx2::{has_avx2, keccak_p_avx2};

// ═══════════════════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════════════════

/// Keccak state size in bytes (1600 bits)
pub const STATE_SIZE: usize = 200;

/// Number of rounds in Keccak-p[1600,24]
pub const ROUNDS: usize = 24;

/// SHAKE128 rate in bytes (1344 bits)
pub const SHAKE128_RATE: usize = 168;

/// SHAKE256 rate in bytes (1088 bits)
pub const SHAKE256_RATE: usize = 136;

/// SHAKE domain separator byte
const SHAKE_DOMAIN_SEP: u8 = 0x1F;

/// Final padding byte
const PADDING_END: u8 = 0x80;

/// Round constants for ι (iota) step
const RC: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808a,
    0x8000000080008000,
    0x000000000000808b,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008a,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000a,
    0x000000008000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

/// Rotation offsets for ρ (rho) step (FIPS 202 Table 2)
/// Indexed as RHO[x][y] where (x,y) are the lane coordinates
const RHO: [[u32; 5]; 5] = [
    // x=0: r[0,0]=0, r[0,1]=36, r[0,2]=3, r[0,3]=41, r[0,4]=18
    [0, 36, 3, 41, 18],
    // x=1: r[1,0]=1, r[1,1]=44, r[1,2]=10, r[1,3]=45, r[1,4]=2
    [1, 44, 10, 45, 2],
    // x=2: r[2,0]=62, r[2,1]=6, r[2,2]=43, r[2,3]=15, r[2,4]=61
    [62, 6, 43, 15, 61],
    // x=3: r[3,0]=28, r[3,1]=55, r[3,2]=25, r[3,3]=21, r[3,4]=56
    [28, 55, 25, 21, 56],
    // x=4: r[4,0]=27, r[4,1]=20, r[4,2]=39, r[4,3]=8, r[4,4]=14
    [27, 20, 39, 8, 14],
];

// ═══════════════════════════════════════════════════════════════════════════════
// Keccak State
// ═══════════════════════════════════════════════════════════════════════════════

/// Keccak 1600-bit state as 5×5 array of 64-bit lanes
pub type KeccakState = [[u64; 5]; 5];

/// Create zero-initialized Keccak state
fn new_state() -> KeccakState {
    [[0u64; 5]; 5]
}

// ═══════════════════════════════════════════════════════════════════════════════
// Keccak-p Permutation
// ═══════════════════════════════════════════════════════════════════════════════

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

/// ρ (rho) and π (pi) - rotation and permutation (combined for efficiency)
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

/// Keccak-p[1600,24] permutation
///
/// Uses AVX2 SIMD when the `simd` feature is enabled and hardware supports it.
pub fn keccak_p(state: &mut KeccakState) {
    #[cfg(all(feature = "simd", target_arch = "x86_64"))]
    {
        if has_avx2() {
            unsafe {
                keccak_p_avx2(state);
            }
            return;
        }
    }

    // Scalar fallback
    for round in 0..ROUNDS {
        theta(state);
        rho_pi(state);
        chi(state);
        iota(state, round);
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// State Conversion Utilities
// ═══════════════════════════════════════════════════════════════════════════════

/// Convert byte slice to Keccak state (little-endian lanes)
fn bytes_to_state(bytes: &[u8], state: &mut KeccakState) {
    debug_assert!(bytes.len() <= STATE_SIZE);

    for i in 0..25 {
        let x = i % 5;
        let y = i / 5;
        let offset = i * 8;

        if offset + 8 <= bytes.len() {
            state[x][y] = u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
        } else if offset < bytes.len() {
            // Partial lane
            let mut lane_bytes = [0u8; 8];
            lane_bytes[..bytes.len() - offset].copy_from_slice(&bytes[offset..]);
            state[x][y] = u64::from_le_bytes(lane_bytes);
        }
    }
}

/// XOR byte slice into state (for absorb)
fn xor_bytes_into_state(bytes: &[u8], state: &mut KeccakState) {
    debug_assert!(bytes.len() <= STATE_SIZE);

    for i in 0..bytes.len().min(STATE_SIZE) / 8 {
        let x = i % 5;
        let y = i / 5;
        let offset = i * 8;

        if offset + 8 <= bytes.len() {
            let lane = u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
            state[x][y] ^= lane;
        }
    }

    // Handle remaining bytes (partial lane)
    let full_lanes = bytes.len() / 8;
    let remaining = bytes.len() % 8;
    if remaining > 0 {
        let x = full_lanes % 5;
        let y = full_lanes / 5;
        let offset = full_lanes * 8;
        let mut lane_bytes = [0u8; 8];
        lane_bytes[..remaining].copy_from_slice(&bytes[offset..]);
        state[x][y] ^= u64::from_le_bytes(lane_bytes);
    }
}

/// Extract bytes from state (for squeeze)
fn state_to_bytes(state: &KeccakState, bytes: &mut [u8]) {
    debug_assert!(bytes.len() <= STATE_SIZE);

    for i in 0..bytes.len().min(STATE_SIZE) / 8 {
        let x = i % 5;
        let y = i / 5;
        let offset = i * 8;

        if offset + 8 <= bytes.len() {
            bytes[offset..offset + 8].copy_from_slice(&state[x][y].to_le_bytes());
        }
    }

    // Handle remaining bytes
    let full_lanes = bytes.len() / 8;
    let remaining = bytes.len() % 8;
    if remaining > 0 {
        let x = full_lanes % 5;
        let y = full_lanes / 5;
        let offset = full_lanes * 8;
        let lane_bytes = state[x][y].to_le_bytes();
        bytes[offset..].copy_from_slice(&lane_bytes[..remaining]);
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// SHAKE128
// ═══════════════════════════════════════════════════════════════════════════════

/// SHAKE128 Extendable-Output Function (128-bit security)
#[derive(Clone)]
pub struct Shake128 {
    state: KeccakState,
    buffer: [u8; SHAKE128_RATE],
    buffer_len: usize,
}

impl Shake128 {
    /// Create new SHAKE128 instance
    pub fn new() -> Self {
        Self {
            state: new_state(),
            buffer: [0u8; SHAKE128_RATE],
            buffer_len: 0,
        }
    }

    /// Absorb data into the sponge
    pub fn update(&mut self, data: &[u8]) {
        let mut offset = 0;

        // Fill buffer and process full blocks
        while offset < data.len() {
            let space = SHAKE128_RATE - self.buffer_len;
            let to_copy = core::cmp::min(space, data.len() - offset);

            self.buffer[self.buffer_len..self.buffer_len + to_copy]
                .copy_from_slice(&data[offset..offset + to_copy]);
            self.buffer_len += to_copy;
            offset += to_copy;

            if self.buffer_len == SHAKE128_RATE {
                xor_bytes_into_state(&self.buffer, &mut self.state);
                keccak_p(&mut self.state);
                self.buffer_len = 0;
            }
        }
    }

    /// Finalize absorb phase and return XOF reader
    pub fn finalize_xof(mut self) -> Shake128Reader {
        // Apply SHAKE padding: domain separator + pad10*1
        self.buffer[self.buffer_len] = SHAKE_DOMAIN_SEP;
        for i in self.buffer_len + 1..SHAKE128_RATE {
            self.buffer[i] = 0;
        }
        self.buffer[SHAKE128_RATE - 1] |= PADDING_END;

        // Absorb final block
        xor_bytes_into_state(&self.buffer, &mut self.state);
        keccak_p(&mut self.state);

        // Create reader with first squeeze block ready
        let mut reader_buffer = [0u8; SHAKE128_RATE];
        state_to_bytes(&self.state, &mut reader_buffer);

        Shake128Reader {
            state: self.state,
            buffer: reader_buffer,
            buffer_pos: 0,
        }
    }

    /// Convenience: hash data and produce fixed-length output
    pub fn digest(data: &[u8], output: &mut [u8]) {
        let mut shake = Self::new();
        shake.update(data);
        let mut reader = shake.finalize_xof();
        reader.squeeze(output);
    }
}

impl Default for Shake128 {
    fn default() -> Self {
        Self::new()
    }
}

/// SHAKE128 XOF reader for streaming output
#[derive(Clone)]
pub struct Shake128Reader {
    state: KeccakState,
    buffer: [u8; SHAKE128_RATE],
    buffer_pos: usize,
}

impl Shake128Reader {
    /// Squeeze arbitrary bytes from the XOF
    pub fn squeeze(&mut self, output: &mut [u8]) {
        let mut offset = 0;

        while offset < output.len() {
            // Use buffered output
            if self.buffer_pos < SHAKE128_RATE {
                let available = SHAKE128_RATE - self.buffer_pos;
                let to_copy = core::cmp::min(available, output.len() - offset);
                output[offset..offset + to_copy]
                    .copy_from_slice(&self.buffer[self.buffer_pos..self.buffer_pos + to_copy]);
                self.buffer_pos += to_copy;
                offset += to_copy;
            }

            // Squeeze another block if needed
            if offset < output.len() {
                keccak_p(&mut self.state);
                state_to_bytes(&self.state, &mut self.buffer);
                self.buffer_pos = 0;
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// SHAKE256
// ═══════════════════════════════════════════════════════════════════════════════

/// SHAKE256 Extendable-Output Function (256-bit security)
#[derive(Clone)]
pub struct Shake256 {
    state: KeccakState,
    buffer: [u8; SHAKE256_RATE],
    buffer_len: usize,
}

impl Shake256 {
    /// Create new SHAKE256 instance
    pub fn new() -> Self {
        Self {
            state: new_state(),
            buffer: [0u8; SHAKE256_RATE],
            buffer_len: 0,
        }
    }

    /// Absorb data into the sponge
    pub fn update(&mut self, data: &[u8]) {
        let mut offset = 0;

        while offset < data.len() {
            let space = SHAKE256_RATE - self.buffer_len;
            let to_copy = core::cmp::min(space, data.len() - offset);

            self.buffer[self.buffer_len..self.buffer_len + to_copy]
                .copy_from_slice(&data[offset..offset + to_copy]);
            self.buffer_len += to_copy;
            offset += to_copy;

            if self.buffer_len == SHAKE256_RATE {
                xor_bytes_into_state(&self.buffer, &mut self.state);
                keccak_p(&mut self.state);
                self.buffer_len = 0;
            }
        }
    }

    /// Finalize absorb phase and return XOF reader
    pub fn finalize_xof(mut self) -> Shake256Reader {
        // Apply SHAKE padding
        self.buffer[self.buffer_len] = SHAKE_DOMAIN_SEP;
        for i in self.buffer_len + 1..SHAKE256_RATE {
            self.buffer[i] = 0;
        }
        self.buffer[SHAKE256_RATE - 1] |= PADDING_END;

        // Absorb final block
        xor_bytes_into_state(&self.buffer, &mut self.state);
        keccak_p(&mut self.state);

        // Create reader
        let mut reader_buffer = [0u8; SHAKE256_RATE];
        state_to_bytes(&self.state, &mut reader_buffer);

        Shake256Reader {
            state: self.state,
            buffer: reader_buffer,
            buffer_pos: 0,
        }
    }

    /// Convenience: hash data and produce fixed-length output
    pub fn digest(data: &[u8], output: &mut [u8]) {
        let mut shake = Self::new();
        shake.update(data);
        let mut reader = shake.finalize_xof();
        reader.squeeze(output);
    }
}

impl Default for Shake256 {
    fn default() -> Self {
        Self::new()
    }
}

/// SHAKE256 XOF reader for streaming output
#[derive(Clone)]
pub struct Shake256Reader {
    state: KeccakState,
    buffer: [u8; SHAKE256_RATE],
    buffer_pos: usize,
}

impl Shake256Reader {
    /// Squeeze arbitrary bytes from the XOF
    pub fn squeeze(&mut self, output: &mut [u8]) {
        let mut offset = 0;

        while offset < output.len() {
            if self.buffer_pos < SHAKE256_RATE {
                let available = SHAKE256_RATE - self.buffer_pos;
                let to_copy = core::cmp::min(available, output.len() - offset);
                output[offset..offset + to_copy]
                    .copy_from_slice(&self.buffer[self.buffer_pos..self.buffer_pos + to_copy]);
                self.buffer_pos += to_copy;
                offset += to_copy;
            }

            if offset < output.len() {
                keccak_p(&mut self.state);
                state_to_bytes(&self.state, &mut self.buffer);
                self.buffer_pos = 0;
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ─────────────────────────────────────────────────────────────────────────
    // Keccak Permutation Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_keccak_p_zero_state() {
        // Permutation of zero state should produce non-zero state
        let mut state = new_state();
        keccak_p(&mut state);

        let mut all_zero = true;
        for x in 0..5 {
            for y in 0..5 {
                if state[x][y] != 0 {
                    all_zero = false;
                }
            }
        }
        assert!(!all_zero, "Permutation of zero state should be non-zero");
    }

    #[test]
    fn test_keccak_p_deterministic() {
        let mut state1 = new_state();
        let mut state2 = new_state();

        state1[0][0] = 0x123456789ABCDEF0;
        state2[0][0] = 0x123456789ABCDEF0;

        keccak_p(&mut state1);
        keccak_p(&mut state2);

        assert_eq!(state1, state2, "Permutation should be deterministic");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // SHAKE128 Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_shake128_empty_input() {
        // NIST CAVP: SHAKE128("") = 7F9C2BA4E88F827D616045507605853E...
        let mut output = [0u8; 32];
        Shake128::digest(&[], &mut output);

        // Expected first 32 bytes of SHAKE128("")
        let expected = [
            0x7f, 0x9c, 0x2b, 0xa4, 0xe8, 0x8f, 0x82, 0x7d, 0x61, 0x60, 0x45, 0x50, 0x76, 0x05,
            0x85, 0x3e, 0xd7, 0x3b, 0x80, 0x93, 0xf6, 0xef, 0xbc, 0x88, 0xeb, 0x1a, 0x6e, 0xac,
            0xfa, 0x66, 0xef, 0x26,
        ];

        assert_eq!(output, expected, "SHAKE128 empty input mismatch");
    }

    #[test]
    fn test_shake128_short_input() {
        // Test with "abc"
        let mut output = [0u8; 32];
        Shake128::digest(b"abc", &mut output);

        // Verify output is not zero (basic sanity)
        assert!(
            output.iter().any(|&b| b != 0),
            "Output should not be all zeros"
        );
    }

    #[test]
    fn test_shake128_streaming() {
        // Single update vs multiple updates should produce same result
        let mut output1 = [0u8; 64];
        let mut output2 = [0u8; 64];

        // Single update
        Shake128::digest(b"hello world", &mut output1);

        // Multiple updates
        let mut shake = Shake128::new();
        shake.update(b"hello ");
        shake.update(b"world");
        let mut reader = shake.finalize_xof();
        reader.squeeze(&mut output2);

        assert_eq!(output1, output2, "Streaming should match single update");
    }

    #[test]
    fn test_shake128_xof_continuity() {
        // Squeezing in chunks should equal squeezing all at once
        let mut shake = Shake128::new();
        shake.update(b"test");
        let mut reader1 = shake.finalize_xof();

        let mut shake = Shake128::new();
        shake.update(b"test");
        let mut reader2 = shake.finalize_xof();

        // Squeeze 200 bytes at once
        let mut all_at_once = [0u8; 200];
        reader1.squeeze(&mut all_at_once);

        // Squeeze in chunks
        let mut in_chunks = [0u8; 200];
        reader2.squeeze(&mut in_chunks[0..50]);
        reader2.squeeze(&mut in_chunks[50..100]);
        reader2.squeeze(&mut in_chunks[100..150]);
        reader2.squeeze(&mut in_chunks[150..200]);

        assert_eq!(all_at_once, in_chunks, "XOF chunks should match continuous");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // SHAKE256 Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_shake256_empty_input() {
        // NIST CAVP: SHAKE256("") = 46B9DD2B0BA88D13233B3FEB743EEB24...
        let mut output = [0u8; 32];
        Shake256::digest(&[], &mut output);

        let expected = [
            0x46, 0xb9, 0xdd, 0x2b, 0x0b, 0xa8, 0x8d, 0x13, 0x23, 0x3b, 0x3f, 0xeb, 0x74, 0x3e,
            0xeb, 0x24, 0x3f, 0xcd, 0x52, 0xea, 0x62, 0xb8, 0x1b, 0x82, 0xb5, 0x0c, 0x27, 0x64,
            0x6e, 0xd5, 0x76, 0x2f,
        ];

        assert_eq!(output, expected, "SHAKE256 empty input mismatch");
    }

    #[test]
    fn test_shake256_short_input() {
        let mut output = [0u8; 32];
        Shake256::digest(b"abc", &mut output);
        assert!(
            output.iter().any(|&b| b != 0),
            "Output should not be all zeros"
        );
    }

    #[test]
    fn test_shake256_streaming() {
        let mut output1 = [0u8; 64];
        let mut output2 = [0u8; 64];

        Shake256::digest(b"hello world", &mut output1);

        let mut shake = Shake256::new();
        shake.update(b"hello ");
        shake.update(b"world");
        let mut reader = shake.finalize_xof();
        reader.squeeze(&mut output2);

        assert_eq!(output1, output2, "Streaming should match single update");
    }

    #[test]
    fn test_shake256_xof_continuity() {
        let mut shake = Shake256::new();
        shake.update(b"test");
        let mut reader1 = shake.finalize_xof();

        let mut shake = Shake256::new();
        shake.update(b"test");
        let mut reader2 = shake.finalize_xof();

        let mut all_at_once = [0u8; 200];
        reader1.squeeze(&mut all_at_once);

        let mut in_chunks = [0u8; 200];
        reader2.squeeze(&mut in_chunks[0..50]);
        reader2.squeeze(&mut in_chunks[50..100]);
        reader2.squeeze(&mut in_chunks[100..150]);
        reader2.squeeze(&mut in_chunks[150..200]);

        assert_eq!(all_at_once, in_chunks, "XOF chunks should match continuous");
    }

    #[test]
    fn test_shake256_long_output() {
        // Test requesting more than one rate block of output
        let mut output = [0u8; 300]; // > 136 bytes
        Shake256::digest(b"seed", &mut output);

        // Verify output spans multiple blocks (not just repeated)
        assert_ne!(
            &output[0..136],
            &output[136..272],
            "Different blocks should differ"
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Cross-Validation Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_shake128_vs_shake256_differ() {
        // Same input should produce different output
        let mut out128 = [0u8; 32];
        let mut out256 = [0u8; 32];

        Shake128::digest(b"test", &mut out128);
        Shake256::digest(b"test", &mut out256);

        assert_ne!(out128, out256, "SHAKE128 and SHAKE256 should differ");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Edge Case Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_shake_rate_boundary() {
        // Test input exactly at rate boundary
        let input = vec![0x42u8; SHAKE256_RATE];
        let mut output = [0u8; 32];
        Shake256::digest(&input, &mut output);
        assert!(output.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_shake_multiple_rate_blocks() {
        // Test input spanning multiple rate blocks
        let input = vec![0xAB; SHAKE256_RATE * 3 + 50];
        let mut output = [0u8; 64];
        Shake256::digest(&input, &mut output);
        assert!(output.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_shake_single_byte_updates() {
        // Byte-by-byte updates should work
        let data = b"test data for shake";
        let mut output1 = [0u8; 32];
        let mut output2 = [0u8; 32];

        Shake256::digest(data, &mut output1);

        let mut shake = Shake256::new();
        for &byte in data.iter() {
            shake.update(&[byte]);
        }
        let mut reader = shake.finalize_xof();
        reader.squeeze(&mut output2);

        assert_eq!(output1, output2, "Byte-by-byte should match bulk");
    }
}
