//! Batch cryptographic operations using SIMD parallelism.
//!
//! This module provides APIs for processing multiple independent inputs
//! simultaneously, leveraging SIMD lanes for true parallelism within a
//! single thread.
//!
//! # Why Batch Processing?
//!
//! Traditional crypto libraries optimize for single-message throughput.
//! But many real-world scenarios involve processing multiple independent
//! inputs:
//!
//! - **Merkle trees**: Hash thousands of leaves
//! - **Password verification**: Check multiple credentials
//! - **Signature verification**: Validate transaction batches
//! - **File deduplication**: Hash many chunks
//!
//! By processing 4-8 messages in parallel using SIMD, we can achieve
//! 3-6x throughput improvement over sequential hashing.
//!
//! # Example
//!
//! ```ignore
//! use arcanum_primitives::batch::{BatchSha256, BatchHasher};
//!
//! // Hash 4 messages simultaneously
//! let messages = [
//!     b"message 1".as_slice(),
//!     b"message 2".as_slice(),
//!     b"message 3".as_slice(),
//!     b"message 4".as_slice(),
//! ];
//!
//! let hashes = BatchSha256::hash_batch(&messages);
//! // Returns [hash1, hash2, hash3, hash4] - computed in parallel!
//! ```
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────┐
//! │                    Input Messages                        │
//! │  [msg1]    [msg2]    [msg3]    [msg4]                   │
//! └────┬─────────┬─────────┬─────────┬──────────────────────┘
//!      │         │         │         │
//!      ▼         ▼         ▼         ▼
//! ┌─────────────────────────────────────────────────────────┐
//! │              SIMD Registers (256-bit AVX2)              │
//! │  ┌────────┬────────┬────────┬────────┐                 │
//! │  │ state1 │ state2 │ state3 │ state4 │  ← 4 parallel   │
//! │  └────────┴────────┴────────┴────────┘    hash states  │
//! └─────────────────────────────────────────────────────────┘
//!      │         │         │         │
//!      ▼         ▼         ▼         ▼
//! ┌─────────────────────────────────────────────────────────┐
//! │                   Output Hashes                          │
//! │  [hash1]   [hash2]   [hash3]   [hash4]                  │
//! └─────────────────────────────────────────────────────────┘
//! ```

use crate::ct::ct_zeroize;

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

// ═══════════════════════════════════════════════════════════════════════════════
// BATCH HASHER TRAIT
// ═══════════════════════════════════════════════════════════════════════════════

/// Trait for batch hashing operations.
///
/// Implementations process multiple independent messages in parallel
/// using SIMD instructions.
pub trait BatchHasher: Sized {
    /// Number of parallel lanes (messages processed simultaneously)
    const LANES: usize;

    /// Output size in bytes per hash
    const OUTPUT_SIZE: usize;

    /// Algorithm name
    const ALGORITHM: &'static str;

    /// Hash multiple messages with different lengths, padding shorter ones.
    ///
    /// This is useful when messages have varying lengths - shorter messages
    /// are processed alongside longer ones without blocking.
    #[cfg(feature = "alloc")]
    fn hash_batch_varied(messages: &[&[u8]]) -> Vec<[u8; 32]>;
}

// ═══════════════════════════════════════════════════════════════════════════════
// BATCH SHA-256 (4-WAY PARALLEL)
// ═══════════════════════════════════════════════════════════════════════════════

/// SHA-256 round constants
const K256: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// SHA-256 initial hash values
const H256_INIT: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// 4-way parallel SHA-256 hasher.
///
/// Processes 4 independent messages simultaneously using SIMD.
/// Each SIMD lane holds one complete SHA-256 state.
pub struct BatchSha256x4 {
    /// 4 parallel hash states [h0..h7] for each lane
    /// Layout: state[i][lane] where i is state index, lane is 0-3
    state: [[u32; 4]; 8],
    /// 4 parallel buffers for partial blocks
    buffers: [[u8; 64]; 4],
    /// Buffer lengths for each lane
    buffer_lens: [usize; 4],
    /// Total bytes processed per lane
    total_lens: [u64; 4],
}

impl Default for BatchSha256x4 {
    fn default() -> Self {
        Self::new()
    }
}

impl BatchSha256x4 {
    /// Create a new 4-way parallel SHA-256 hasher.
    pub fn new() -> Self {
        Self {
            state: [
                [H256_INIT[0]; 4],
                [H256_INIT[1]; 4],
                [H256_INIT[2]; 4],
                [H256_INIT[3]; 4],
                [H256_INIT[4]; 4],
                [H256_INIT[5]; 4],
                [H256_INIT[6]; 4],
                [H256_INIT[7]; 4],
            ],
            buffers: [[0u8; 64]; 4],
            buffer_lens: [0; 4],
            total_lens: [0; 4],
        }
    }

    /// Update lane with data.
    pub fn update_lane(&mut self, lane: usize, data: &[u8]) {
        assert!(lane < 4, "lane must be 0-3");

        let mut offset = 0;
        self.total_lens[lane] = self.total_lens[lane].wrapping_add(data.len() as u64);

        // Fill buffer if partially filled
        if self.buffer_lens[lane] > 0 {
            let space = 64 - self.buffer_lens[lane];
            let to_copy = data.len().min(space);
            self.buffers[lane][self.buffer_lens[lane]..self.buffer_lens[lane] + to_copy]
                .copy_from_slice(&data[..to_copy]);
            self.buffer_lens[lane] += to_copy;
            offset = to_copy;

            if self.buffer_lens[lane] == 64 {
                self.compress_single_lane(lane);
                self.buffer_lens[lane] = 0;
            }
        }

        // Process full blocks
        while offset + 64 <= data.len() {
            self.buffers[lane].copy_from_slice(&data[offset..offset + 64]);
            self.compress_single_lane(lane);
            offset += 64;
        }

        // Buffer remainder
        if offset < data.len() {
            let remainder = data.len() - offset;
            self.buffers[lane][..remainder].copy_from_slice(&data[offset..]);
            self.buffer_lens[lane] = remainder;
        }
    }

    /// Update all 4 lanes with data slices.
    ///
    /// This is the preferred method - it enables parallel compression
    /// when all lanes have full blocks ready.
    pub fn update_all(&mut self, data: [&[u8]; 4]) {
        for (lane, d) in data.iter().enumerate() {
            self.update_lane(lane, d);
        }
    }

    /// Compress a single lane (fallback for unaligned updates).
    fn compress_single_lane(&mut self, lane: usize) {
        let block = self.buffers[lane];

        // Message schedule
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes(block[i * 4..(i + 1) * 4].try_into().unwrap());
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        // Working variables for this lane
        let mut a = self.state[0][lane];
        let mut b = self.state[1][lane];
        let mut c = self.state[2][lane];
        let mut d = self.state[3][lane];
        let mut e = self.state[4][lane];
        let mut f = self.state[5][lane];
        let mut g = self.state[6][lane];
        let mut h = self.state[7][lane];

        // 64 rounds
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K256[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        // Update state for this lane
        self.state[0][lane] = self.state[0][lane].wrapping_add(a);
        self.state[1][lane] = self.state[1][lane].wrapping_add(b);
        self.state[2][lane] = self.state[2][lane].wrapping_add(c);
        self.state[3][lane] = self.state[3][lane].wrapping_add(d);
        self.state[4][lane] = self.state[4][lane].wrapping_add(e);
        self.state[5][lane] = self.state[5][lane].wrapping_add(f);
        self.state[6][lane] = self.state[6][lane].wrapping_add(g);
        self.state[7][lane] = self.state[7][lane].wrapping_add(h);
    }

    /// Finalize and return all 4 hashes.
    pub fn finalize(mut self) -> [[u8; 32]; 4] {
        let mut output = [[0u8; 32]; 4];

        for lane in 0..4 {
            // Padding
            let bit_len = self.total_lens[lane] * 8;
            self.buffers[lane][self.buffer_lens[lane]] = 0x80;
            self.buffer_lens[lane] += 1;

            if self.buffer_lens[lane] > 56 {
                // Need two blocks
                self.buffers[lane][self.buffer_lens[lane]..64].fill(0);
                self.compress_single_lane(lane);
                self.buffers[lane].fill(0);
            } else {
                self.buffers[lane][self.buffer_lens[lane]..56].fill(0);
            }

            // Append length in bits (big-endian)
            self.buffers[lane][56..64].copy_from_slice(&bit_len.to_be_bytes());
            self.compress_single_lane(lane);

            // Output
            for (i, &word) in self.state.iter().enumerate() {
                output[lane][i * 4..(i + 1) * 4].copy_from_slice(&word[lane].to_be_bytes());
            }
        }

        // Zeroize sensitive data
        for buf in &mut self.buffers {
            ct_zeroize(buf);
        }

        output
    }

    /// Hash 4 messages in parallel (convenience method).
    ///
    /// When the `simd` feature is enabled on x86_64, this uses:
    /// - SHA-NI hardware acceleration when available (fastest)
    /// - SSE2 software SIMD fallback otherwise
    #[cfg(all(target_arch = "x86_64", feature = "simd", feature = "std"))]
    pub fn hash_parallel(messages: [&[u8]; 4]) -> [[u8; 32]; 4] {
        if crate::sha2_simd::has_sha_ni() {
            // SHA-NI is ~3-4x faster than SSE2 software SIMD
            Self::hash_parallel_sha_ni(messages)
        } else {
            // Use SSE2 software SIMD
            unsafe { Self::hash_parallel_simd(messages) }
        }
    }

    /// Hash 4 messages in parallel (SIMD without std for runtime detection).
    #[cfg(all(target_arch = "x86_64", feature = "simd", not(feature = "std")))]
    pub fn hash_parallel(messages: [&[u8]; 4]) -> [[u8; 32]; 4] {
        // Without std, can't do runtime detection - use SSE2 SIMD
        unsafe { Self::hash_parallel_simd(messages) }
    }

    /// Hash 4 messages in parallel (portable fallback).
    #[cfg(not(all(target_arch = "x86_64", feature = "simd")))]
    pub fn hash_parallel(messages: [&[u8]; 4]) -> [[u8; 32]; 4] {
        let mut hasher = Self::new();
        hasher.update_all(messages);
        hasher.finalize()
    }

    /// SHA-NI accelerated batch hashing.
    ///
    /// Uses hardware SHA-256 instructions for each message.
    /// Since SHA-NI provides ~3x speedup per hash, this beats SSE2 SIMD.
    #[cfg(all(target_arch = "x86_64", feature = "simd", feature = "std"))]
    fn hash_parallel_sha_ni(messages: [&[u8]; 4]) -> [[u8; 32]; 4] {
        use crate::sha2::Sha256;
        [
            Sha256::hash(messages[0]),
            Sha256::hash(messages[1]),
            Sha256::hash(messages[2]),
            Sha256::hash(messages[3]),
        ]
    }

    /// SIMD-accelerated parallel hashing for 4 messages.
    ///
    /// Uses SSE2 intrinsics to process 4 SHA-256 states simultaneously.
    /// For messages with similar lengths, this provides ~2-3x speedup.
    #[cfg(all(target_arch = "x86_64", feature = "simd"))]
    #[target_feature(enable = "sse2")]
    unsafe fn hash_parallel_simd(messages: [&[u8]; 4]) -> [[u8; 32]; 4] {
        use core::arch::x86_64::*;

        let lens = [
            messages[0].len(),
            messages[1].len(),
            messages[2].len(),
            messages[3].len(),
        ];

        // Calculate total blocks needed for each message (including padding)
        let blocks_needed: [usize; 4] = [
            Self::blocks_for_len(lens[0]),
            Self::blocks_for_len(lens[1]),
            Self::blocks_for_len(lens[2]),
            Self::blocks_for_len(lens[3]),
        ];

        let max_blocks = blocks_needed.iter().copied().max().unwrap_or(1);

        // Initialize SIMD state
        let mut h = [
            _mm_set1_epi32(H256_INIT[0] as i32),
            _mm_set1_epi32(H256_INIT[1] as i32),
            _mm_set1_epi32(H256_INIT[2] as i32),
            _mm_set1_epi32(H256_INIT[3] as i32),
            _mm_set1_epi32(H256_INIT[4] as i32),
            _mm_set1_epi32(H256_INIT[5] as i32),
            _mm_set1_epi32(H256_INIT[6] as i32),
            _mm_set1_epi32(H256_INIT[7] as i32),
        ];

        // Store results for lanes that finish early
        let mut results: [Option<[u8; 32]>; 4] = [None, None, None, None];

        for block_idx in 0..max_blocks {
            let offset = block_idx * 64;
            let mut blocks = [[0u8; 64]; 4];

            for lane in 0..4 {
                if results[lane].is_some() {
                    // Lane already done - dummy block won't affect saved result
                    continue;
                }

                let msg = messages[lane];
                let msg_len = lens[lane];
                let full_data_blocks = msg_len / 64;
                let remaining = msg_len % 64;
                let needs_extra_block = remaining >= 56;
                let total_blocks = blocks_needed[lane];

                if block_idx < full_data_blocks {
                    // Full block of message data
                    blocks[lane].copy_from_slice(&msg[offset..offset + 64]);
                } else if block_idx == full_data_blocks {
                    // Block containing end of message + start of padding
                    if remaining > 0 {
                        blocks[lane][..remaining].copy_from_slice(&msg[offset..]);
                    }
                    blocks[lane][remaining] = 0x80;

                    if !needs_extra_block {
                        // Room for length in this block
                        let bit_len = (msg_len as u64) * 8;
                        blocks[lane][56..64].copy_from_slice(&bit_len.to_be_bytes());
                    }
                } else if block_idx == full_data_blocks + 1 && needs_extra_block {
                    // Extra block for length only (0x80 was in previous block)
                    let bit_len = (msg_len as u64) * 8;
                    blocks[lane][56..64].copy_from_slice(&bit_len.to_be_bytes());
                }
                // else: lane needs fewer blocks, use zeros (already initialized)

                // Check if this lane is done after this block
                if block_idx == total_blocks - 1 {
                    // This lane will be complete after compression
                    // We'll extract its result after the compress
                }
            }

            // Compress 4 blocks in parallel
            Self::compress_4_blocks_simd(&mut h, &blocks);

            // Extract results for lanes that just finished
            for lane in 0..4 {
                if results[lane].is_none() && block_idx == blocks_needed[lane] - 1 {
                    let mut result = [0u8; 32];
                    for i in 0..8 {
                        let mut tmp = [0i32; 4];
                        _mm_storeu_si128(tmp.as_mut_ptr() as *mut __m128i, h[i]);
                        let bytes = (tmp[lane] as u32).to_be_bytes();
                        result[i * 4..i * 4 + 4].copy_from_slice(&bytes);
                    }
                    results[lane] = Some(result);
                }
            }
        }

        // Extract final output
        let mut output = [[0u8; 32]; 4];
        for lane in 0..4 {
            output[lane] = results[lane].unwrap_or_else(|| {
                // Should not happen, but fallback to extracting from state
                let mut result = [0u8; 32];
                for i in 0..8 {
                    let mut tmp = [0i32; 4];
                    _mm_storeu_si128(tmp.as_mut_ptr() as *mut __m128i, h[i]);
                    let bytes = (tmp[lane] as u32).to_be_bytes();
                    result[i * 4..i * 4 + 4].copy_from_slice(&bytes);
                }
                result
            });
        }

        output
    }

    /// Calculate number of SHA-256 blocks needed for a message of given length.
    #[cfg(all(target_arch = "x86_64", feature = "simd"))]
    #[inline]
    fn blocks_for_len(len: usize) -> usize {
        // Need room for 1 byte (0x80) + 8 bytes (length) = 9 bytes of padding
        // Block size is 64 bytes, so 55 bytes of data max in final block
        let data_blocks = len / 64;
        let remaining = len % 64;

        if remaining < 56 {
            // Fits in one more block
            data_blocks + 1
        } else {
            // Need an extra block for length
            data_blocks + 2
        }
    }

    /// SIMD compress 4 blocks in parallel.
    #[cfg(all(target_arch = "x86_64", feature = "simd"))]
    #[inline]
    #[target_feature(enable = "sse2")]
    unsafe fn compress_4_blocks_simd(
        h: &mut [core::arch::x86_64::__m128i; 8],
        blocks: &[[u8; 64]; 4],
    ) {
        use core::arch::x86_64::*;

        // Load and transpose message schedules
        let mut w: [__m128i; 64] = [_mm_setzero_si128(); 64];

        for i in 0..16 {
            let w0 = u32::from_be_bytes(blocks[0][i * 4..i * 4 + 4].try_into().unwrap());
            let w1 = u32::from_be_bytes(blocks[1][i * 4..i * 4 + 4].try_into().unwrap());
            let w2 = u32::from_be_bytes(blocks[2][i * 4..i * 4 + 4].try_into().unwrap());
            let w3 = u32::from_be_bytes(blocks[3][i * 4..i * 4 + 4].try_into().unwrap());
            w[i] = _mm_set_epi32(w3 as i32, w2 as i32, w1 as i32, w0 as i32);
        }

        // Extend message schedule
        for i in 16..64 {
            // sigma0(w[i-15])
            let x = w[i - 15];
            let s0 = _mm_xor_si128(
                _mm_xor_si128(
                    _mm_or_si128(_mm_srli_epi32(x, 7), _mm_slli_epi32(x, 25)),
                    _mm_or_si128(_mm_srli_epi32(x, 18), _mm_slli_epi32(x, 14)),
                ),
                _mm_srli_epi32(x, 3),
            );

            // sigma1(w[i-2])
            let x = w[i - 2];
            let s1 = _mm_xor_si128(
                _mm_xor_si128(
                    _mm_or_si128(_mm_srli_epi32(x, 17), _mm_slli_epi32(x, 15)),
                    _mm_or_si128(_mm_srli_epi32(x, 19), _mm_slli_epi32(x, 13)),
                ),
                _mm_srli_epi32(x, 10),
            );

            w[i] = _mm_add_epi32(_mm_add_epi32(w[i - 16], s0), _mm_add_epi32(w[i - 7], s1));
        }

        // Working variables
        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        let mut f = h[5];
        let mut g = h[6];
        let mut hh = h[7];

        // 64 rounds
        for i in 0..64 {
            let k = _mm_set1_epi32(K256[i] as i32);

            // big Sigma1(e)
            let s1 = _mm_xor_si128(
                _mm_xor_si128(
                    _mm_or_si128(_mm_srli_epi32(e, 6), _mm_slli_epi32(e, 26)),
                    _mm_or_si128(_mm_srli_epi32(e, 11), _mm_slli_epi32(e, 21)),
                ),
                _mm_or_si128(_mm_srli_epi32(e, 25), _mm_slli_epi32(e, 7)),
            );

            // ch = (e & f) ^ (~e & g)
            let ch = _mm_xor_si128(_mm_and_si128(e, f), _mm_andnot_si128(e, g));

            // temp1 = h + S1 + ch + k + w[i]
            let temp1 = _mm_add_epi32(
                _mm_add_epi32(_mm_add_epi32(hh, s1), ch),
                _mm_add_epi32(k, w[i]),
            );

            // big Sigma0(a)
            let s0 = _mm_xor_si128(
                _mm_xor_si128(
                    _mm_or_si128(_mm_srli_epi32(a, 2), _mm_slli_epi32(a, 30)),
                    _mm_or_si128(_mm_srli_epi32(a, 13), _mm_slli_epi32(a, 19)),
                ),
                _mm_or_si128(_mm_srli_epi32(a, 22), _mm_slli_epi32(a, 10)),
            );

            // maj = (a & b) ^ (a & c) ^ (b & c)
            let maj = _mm_xor_si128(
                _mm_xor_si128(_mm_and_si128(a, b), _mm_and_si128(a, c)),
                _mm_and_si128(b, c),
            );

            let temp2 = _mm_add_epi32(s0, maj);

            hh = g;
            g = f;
            f = e;
            e = _mm_add_epi32(d, temp1);
            d = c;
            c = b;
            b = a;
            a = _mm_add_epi32(temp1, temp2);
        }

        // Add to state
        h[0] = _mm_add_epi32(h[0], a);
        h[1] = _mm_add_epi32(h[1], b);
        h[2] = _mm_add_epi32(h[2], c);
        h[3] = _mm_add_epi32(h[3], d);
        h[4] = _mm_add_epi32(h[4], e);
        h[5] = _mm_add_epi32(h[5], f);
        h[6] = _mm_add_epi32(h[6], g);
        h[7] = _mm_add_epi32(h[7], hh);
    }
}

impl BatchHasher for BatchSha256x4 {
    const LANES: usize = 4;
    const OUTPUT_SIZE: usize = 32;
    const ALGORITHM: &'static str = "SHA-256x4";

    #[cfg(feature = "alloc")]
    fn hash_batch_varied(messages: &[&[u8]]) -> Vec<[u8; 32]> {
        let mut results = Vec::with_capacity(messages.len());

        // Process in batches of 4
        let chunks = messages.chunks(4);
        for chunk in chunks {
            if chunk.len() == 4 {
                let hashes = Self::hash_parallel([chunk[0], chunk[1], chunk[2], chunk[3]]);
                results.extend_from_slice(&hashes);
            } else {
                // Handle remainder with padding
                let mut padded: [&[u8]; 4] = [&[]; 4];
                for (i, msg) in chunk.iter().enumerate() {
                    padded[i] = msg;
                }
                let hashes = Self::hash_parallel(padded);
                for i in 0..chunk.len() {
                    results.push(hashes[i]);
                }
            }
        }

        results
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// SIMD-ACCELERATED BATCH SHA-256 (SSE2/AVX2)
// ═══════════════════════════════════════════════════════════════════════════════

/// SIMD-accelerated 4-way parallel SHA-256 compression.
///
/// Uses SSE2 intrinsics to process 4 SHA-256 states simultaneously.
/// Each `__m128i` register holds one state word across all 4 lanes.
#[cfg(all(target_arch = "x86_64", feature = "simd"))]
pub mod simd {
    #[cfg(target_arch = "x86_64")]
    use core::arch::x86_64::*;

    use super::{H256_INIT, K256};

    /// Check if SSE2 is available (always true on x86_64).
    #[inline]
    pub fn is_sse2_available() -> bool {
        true // SSE2 is baseline for x86_64
    }

    /// SIMD state for 4-way parallel SHA-256.
    /// Each __m128i holds [lane0, lane1, lane2, lane3] for one state word.
    #[repr(align(16))]
    pub struct SimdSha256x4State {
        h: [__m128i; 8], // h0-h7 across all 4 lanes
    }

    impl SimdSha256x4State {
        /// Initialize state with SHA-256 IV for all 4 lanes.
        #[inline]
        #[target_feature(enable = "sse2")]
        pub unsafe fn new() -> Self {
            Self {
                h: [
                    _mm_set1_epi32(H256_INIT[0] as i32),
                    _mm_set1_epi32(H256_INIT[1] as i32),
                    _mm_set1_epi32(H256_INIT[2] as i32),
                    _mm_set1_epi32(H256_INIT[3] as i32),
                    _mm_set1_epi32(H256_INIT[4] as i32),
                    _mm_set1_epi32(H256_INIT[5] as i32),
                    _mm_set1_epi32(H256_INIT[6] as i32),
                    _mm_set1_epi32(H256_INIT[7] as i32),
                ],
            }
        }

        /// Compress 4 blocks in parallel (one block per lane).
        /// `blocks` contains 4 x 64-byte blocks, one for each lane.
        #[inline]
        #[target_feature(enable = "sse2")]
        pub unsafe fn compress_4_blocks(&mut self, blocks: &[[u8; 64]; 4]) {
            // Load and transpose message schedules for all 4 lanes
            let mut w: [__m128i; 64] = [_mm_setzero_si128(); 64];

            // Load first 16 words from each block
            for i in 0..16 {
                let w0 = u32::from_be_bytes(blocks[0][i * 4..i * 4 + 4].try_into().unwrap());
                let w1 = u32::from_be_bytes(blocks[1][i * 4..i * 4 + 4].try_into().unwrap());
                let w2 = u32::from_be_bytes(blocks[2][i * 4..i * 4 + 4].try_into().unwrap());
                let w3 = u32::from_be_bytes(blocks[3][i * 4..i * 4 + 4].try_into().unwrap());
                w[i] = _mm_set_epi32(w3 as i32, w2 as i32, w1 as i32, w0 as i32);
            }

            // Extend message schedule (w[16..64])
            for i in 16..64 {
                // sigma0(w[i-15])
                let s0 = simd_sigma0(w[i - 15]);
                // sigma1(w[i-2])
                let s1 = simd_sigma1(w[i - 2]);
                // w[i] = w[i-16] + s0 + w[i-7] + s1
                w[i] = _mm_add_epi32(_mm_add_epi32(w[i - 16], s0), _mm_add_epi32(w[i - 7], s1));
            }

            // Working variables
            let mut a = self.h[0];
            let mut b = self.h[1];
            let mut c = self.h[2];
            let mut d = self.h[3];
            let mut e = self.h[4];
            let mut f = self.h[5];
            let mut g = self.h[6];
            let mut h = self.h[7];

            // 64 rounds
            for i in 0..64 {
                let k = _mm_set1_epi32(K256[i] as i32);

                // S1 = (e >>> 6) ^ (e >>> 11) ^ (e >>> 25)
                let s1 = simd_big_sigma1(e);

                // ch = (e & f) ^ (~e & g)
                let ch = _mm_xor_si128(_mm_and_si128(e, f), _mm_andnot_si128(e, g));

                // temp1 = h + S1 + ch + k + w[i]
                let temp1 = _mm_add_epi32(
                    _mm_add_epi32(_mm_add_epi32(h, s1), ch),
                    _mm_add_epi32(k, w[i]),
                );

                // S0 = (a >>> 2) ^ (a >>> 13) ^ (a >>> 22)
                let s0 = simd_big_sigma0(a);

                // maj = (a & b) ^ (a & c) ^ (b & c)
                let maj = _mm_xor_si128(
                    _mm_xor_si128(_mm_and_si128(a, b), _mm_and_si128(a, c)),
                    _mm_and_si128(b, c),
                );

                // temp2 = S0 + maj
                let temp2 = _mm_add_epi32(s0, maj);

                // Update working variables
                h = g;
                g = f;
                f = e;
                e = _mm_add_epi32(d, temp1);
                d = c;
                c = b;
                b = a;
                a = _mm_add_epi32(temp1, temp2);
            }

            // Add to state
            self.h[0] = _mm_add_epi32(self.h[0], a);
            self.h[1] = _mm_add_epi32(self.h[1], b);
            self.h[2] = _mm_add_epi32(self.h[2], c);
            self.h[3] = _mm_add_epi32(self.h[3], d);
            self.h[4] = _mm_add_epi32(self.h[4], e);
            self.h[5] = _mm_add_epi32(self.h[5], f);
            self.h[6] = _mm_add_epi32(self.h[6], g);
            self.h[7] = _mm_add_epi32(self.h[7], h);
        }

        /// Extract final hashes from SIMD state.
        #[inline]
        #[target_feature(enable = "sse2")]
        pub unsafe fn finalize(self) -> [[u8; 32]; 4] {
            let mut output = [[0u8; 32]; 4];

            // Extract each lane
            for i in 0..8 {
                // Extract 4 u32 values from __m128i
                let mut tmp = [0i32; 4];
                _mm_storeu_si128(tmp.as_mut_ptr() as *mut __m128i, self.h[i]);

                // Store as big-endian bytes
                for lane in 0..4 {
                    let bytes = (tmp[lane] as u32).to_be_bytes();
                    output[lane][i * 4..i * 4 + 4].copy_from_slice(&bytes);
                }
            }

            output
        }
    }

    /// SIMD sigma0: (x >>> 7) ^ (x >>> 18) ^ (x >> 3)
    #[inline]
    #[target_feature(enable = "sse2")]
    unsafe fn simd_sigma0(x: __m128i) -> __m128i {
        let r7 = _mm_or_si128(_mm_srli_epi32(x, 7), _mm_slli_epi32(x, 25));
        let r18 = _mm_or_si128(_mm_srli_epi32(x, 18), _mm_slli_epi32(x, 14));
        let s3 = _mm_srli_epi32(x, 3);
        _mm_xor_si128(_mm_xor_si128(r7, r18), s3)
    }

    /// SIMD sigma1: (x >>> 17) ^ (x >>> 19) ^ (x >> 10)
    #[inline]
    #[target_feature(enable = "sse2")]
    unsafe fn simd_sigma1(x: __m128i) -> __m128i {
        let r17 = _mm_or_si128(_mm_srli_epi32(x, 17), _mm_slli_epi32(x, 15));
        let r19 = _mm_or_si128(_mm_srli_epi32(x, 19), _mm_slli_epi32(x, 13));
        let s10 = _mm_srli_epi32(x, 10);
        _mm_xor_si128(_mm_xor_si128(r17, r19), s10)
    }

    /// SIMD big Sigma0: (a >>> 2) ^ (a >>> 13) ^ (a >>> 22)
    #[inline]
    #[target_feature(enable = "sse2")]
    unsafe fn simd_big_sigma0(x: __m128i) -> __m128i {
        let r2 = _mm_or_si128(_mm_srli_epi32(x, 2), _mm_slli_epi32(x, 30));
        let r13 = _mm_or_si128(_mm_srli_epi32(x, 13), _mm_slli_epi32(x, 19));
        let r22 = _mm_or_si128(_mm_srli_epi32(x, 22), _mm_slli_epi32(x, 10));
        _mm_xor_si128(_mm_xor_si128(r2, r13), r22)
    }

    /// SIMD big Sigma1: (e >>> 6) ^ (e >>> 11) ^ (e >>> 25)
    #[inline]
    #[target_feature(enable = "sse2")]
    unsafe fn simd_big_sigma1(x: __m128i) -> __m128i {
        let r6 = _mm_or_si128(_mm_srli_epi32(x, 6), _mm_slli_epi32(x, 26));
        let r11 = _mm_or_si128(_mm_srli_epi32(x, 11), _mm_slli_epi32(x, 21));
        let r25 = _mm_or_si128(_mm_srli_epi32(x, 25), _mm_slli_epi32(x, 7));
        _mm_xor_si128(_mm_xor_si128(r6, r11), r25)
    }

    /// Hash 4 single-block messages using SIMD.
    /// Each message must be exactly 64 bytes (one SHA-256 block).
    #[target_feature(enable = "sse2")]
    pub unsafe fn hash_4_blocks(blocks: &[[u8; 64]; 4]) -> [[u8; 32]; 4] {
        let mut state = SimdSha256x4State::new();
        state.compress_4_blocks(blocks);

        // For single-block messages, we need to add padding
        // This is a simplified version - full impl would handle arbitrary lengths
        let mut padded_blocks = [[0u8; 64]; 4];
        for i in 0..4 {
            // Standard SHA-256 padding for 64-byte message
            padded_blocks[i][0] = 0x80;
            // Length = 512 bits = 0x200
            padded_blocks[i][62] = 0x02;
            padded_blocks[i][63] = 0x00;
        }
        state.compress_4_blocks(&padded_blocks);

        state.finalize()
    }
}

/// 8-way parallel SHA-256 using AVX2.
///
/// Processes 8 independent messages simultaneously using 256-bit SIMD.
/// Each 256-bit register holds 8 x 32-bit SHA-256 state words.
///
/// # Performance
///
/// When AVX2 is available, this provides ~2x throughput vs 4-way SSE2.
/// Falls back to 2x BatchSha256x4 on systems without AVX2.
#[cfg(all(target_arch = "x86_64", feature = "simd", feature = "std"))]
pub struct BatchSha256x8;

#[cfg(all(target_arch = "x86_64", feature = "simd", feature = "std"))]
impl BatchSha256x8 {
    /// Check if AVX2 is available at runtime.
    #[inline]
    pub fn is_available() -> bool {
        std::is_x86_feature_detected!("avx2")
    }

    /// Hash 8 messages in parallel using AVX2.
    ///
    /// Uses true AVX2 8-way parallel processing when available,
    /// otherwise falls back to 2x BatchSha256x4.
    pub fn hash_parallel(messages: [&[u8]; 8]) -> [[u8; 32]; 8] {
        if Self::is_available() {
            unsafe { Self::hash_parallel_avx2(messages) }
        } else {
            Self::hash_parallel_fallback(messages)
        }
    }

    /// Fallback implementation using 2x BatchSha256x4.
    fn hash_parallel_fallback(messages: [&[u8]; 8]) -> [[u8; 32]; 8] {
        let h1 = BatchSha256x4::hash_parallel([messages[0], messages[1], messages[2], messages[3]]);
        let h2 = BatchSha256x4::hash_parallel([messages[4], messages[5], messages[6], messages[7]]);
        [h1[0], h1[1], h1[2], h1[3], h2[0], h2[1], h2[2], h2[3]]
    }

    /// AVX2 accelerated 8-way parallel hashing.
    #[target_feature(enable = "avx2")]
    unsafe fn hash_parallel_avx2(messages: [&[u8]; 8]) -> [[u8; 32]; 8] {
        use core::arch::x86_64::*;

        let lens: [usize; 8] = [
            messages[0].len(),
            messages[1].len(),
            messages[2].len(),
            messages[3].len(),
            messages[4].len(),
            messages[5].len(),
            messages[6].len(),
            messages[7].len(),
        ];

        // Calculate blocks needed for each message
        let blocks_needed: [usize; 8] = [
            Self::blocks_for_len(lens[0]),
            Self::blocks_for_len(lens[1]),
            Self::blocks_for_len(lens[2]),
            Self::blocks_for_len(lens[3]),
            Self::blocks_for_len(lens[4]),
            Self::blocks_for_len(lens[5]),
            Self::blocks_for_len(lens[6]),
            Self::blocks_for_len(lens[7]),
        ];

        let max_blocks = blocks_needed.iter().copied().max().unwrap_or(1);

        // Initialize 8-way state (8 state words x 8 lanes)
        let mut h: [__m256i; 8] = [
            _mm256_set1_epi32(H256_INIT[0] as i32),
            _mm256_set1_epi32(H256_INIT[1] as i32),
            _mm256_set1_epi32(H256_INIT[2] as i32),
            _mm256_set1_epi32(H256_INIT[3] as i32),
            _mm256_set1_epi32(H256_INIT[4] as i32),
            _mm256_set1_epi32(H256_INIT[5] as i32),
            _mm256_set1_epi32(H256_INIT[6] as i32),
            _mm256_set1_epi32(H256_INIT[7] as i32),
        ];

        // Store results for lanes that finish early
        let mut results: [Option<[u8; 32]>; 8] = [None; 8];

        for block_idx in 0..max_blocks {
            let offset = block_idx * 64;
            let mut blocks = [[0u8; 64]; 8];

            // Prepare blocks for all 8 lanes
            for lane in 0..8 {
                if results[lane].is_some() {
                    continue;
                }

                let msg = messages[lane];
                let msg_len = lens[lane];
                let full_data_blocks = msg_len / 64;
                let remaining = msg_len % 64;
                let needs_extra_block = remaining >= 56;

                if block_idx < full_data_blocks {
                    blocks[lane].copy_from_slice(&msg[offset..offset + 64]);
                } else if block_idx == full_data_blocks {
                    if remaining > 0 {
                        blocks[lane][..remaining].copy_from_slice(&msg[offset..]);
                    }
                    blocks[lane][remaining] = 0x80;

                    if !needs_extra_block {
                        let bit_len = (msg_len as u64) * 8;
                        blocks[lane][56..64].copy_from_slice(&bit_len.to_be_bytes());
                    }
                } else if block_idx == full_data_blocks + 1 && needs_extra_block {
                    let bit_len = (msg_len as u64) * 8;
                    blocks[lane][56..64].copy_from_slice(&bit_len.to_be_bytes());
                }
            }

            // Compress 8 blocks in parallel using AVX2
            Self::compress_8_blocks_avx2(&mut h, &blocks);

            // Extract results for lanes that just finished
            for lane in 0..8 {
                if results[lane].is_none() && block_idx == blocks_needed[lane] - 1 {
                    let mut result = [0u8; 32];
                    for i in 0..8 {
                        let mut tmp = core::mem::MaybeUninit::<__m256i>::uninit();
                        _mm256_storeu_si256(tmp.as_mut_ptr(), h[i]);
                        let words: [i32; 8] = core::mem::transmute(tmp.assume_init());
                        let bytes = (words[lane] as u32).to_be_bytes();
                        result[i * 4..i * 4 + 4].copy_from_slice(&bytes);
                    }
                    results[lane] = Some(result);
                }
            }
        }

        // Collect final results
        let mut output = [[0u8; 32]; 8];
        for lane in 0..8 {
            output[lane] = results[lane].unwrap_or_else(|| {
                let mut result = [0u8; 32];
                for i in 0..8 {
                    let mut tmp = core::mem::MaybeUninit::<__m256i>::uninit();
                    unsafe { _mm256_storeu_si256(tmp.as_mut_ptr(), h[i]) };
                    let words: [i32; 8] = unsafe { core::mem::transmute(tmp.assume_init()) };
                    let bytes = (words[lane] as u32).to_be_bytes();
                    result[i * 4..i * 4 + 4].copy_from_slice(&bytes);
                }
                result
            });
        }

        output
    }

    /// Calculate number of SHA-256 blocks needed for a message of given length.
    #[inline]
    fn blocks_for_len(len: usize) -> usize {
        let data_blocks = len / 64;
        let remaining = len % 64;
        if remaining < 56 {
            data_blocks + 1
        } else {
            data_blocks + 2
        }
    }

    /// AVX2 compress 8 blocks in parallel.
    #[target_feature(enable = "avx2")]
    #[inline]
    unsafe fn compress_8_blocks_avx2(
        h: &mut [core::arch::x86_64::__m256i; 8],
        blocks: &[[u8; 64]; 8],
    ) {
        use core::arch::x86_64::*;

        // Load and transpose message schedules (8 lanes)
        let mut w: [__m256i; 64] = [_mm256_setzero_si256(); 64];

        for i in 0..16 {
            // Load word i from all 8 blocks (AVX2 uses _mm256_set_epi32 with lanes in reverse order)
            w[i] = _mm256_set_epi32(
                u32::from_be_bytes(blocks[7][i * 4..i * 4 + 4].try_into().unwrap()) as i32,
                u32::from_be_bytes(blocks[6][i * 4..i * 4 + 4].try_into().unwrap()) as i32,
                u32::from_be_bytes(blocks[5][i * 4..i * 4 + 4].try_into().unwrap()) as i32,
                u32::from_be_bytes(blocks[4][i * 4..i * 4 + 4].try_into().unwrap()) as i32,
                u32::from_be_bytes(blocks[3][i * 4..i * 4 + 4].try_into().unwrap()) as i32,
                u32::from_be_bytes(blocks[2][i * 4..i * 4 + 4].try_into().unwrap()) as i32,
                u32::from_be_bytes(blocks[1][i * 4..i * 4 + 4].try_into().unwrap()) as i32,
                u32::from_be_bytes(blocks[0][i * 4..i * 4 + 4].try_into().unwrap()) as i32,
            );
        }

        // Extend message schedule w[16..64]
        for i in 16..64 {
            // sigma0(w[i-15])
            let x = w[i - 15];
            let s0 = _mm256_xor_si256(
                _mm256_xor_si256(
                    _mm256_or_si256(_mm256_srli_epi32(x, 7), _mm256_slli_epi32(x, 25)),
                    _mm256_or_si256(_mm256_srli_epi32(x, 18), _mm256_slli_epi32(x, 14)),
                ),
                _mm256_srli_epi32(x, 3),
            );

            // sigma1(w[i-2])
            let x = w[i - 2];
            let s1 = _mm256_xor_si256(
                _mm256_xor_si256(
                    _mm256_or_si256(_mm256_srli_epi32(x, 17), _mm256_slli_epi32(x, 15)),
                    _mm256_or_si256(_mm256_srli_epi32(x, 19), _mm256_slli_epi32(x, 13)),
                ),
                _mm256_srli_epi32(x, 10),
            );

            w[i] = _mm256_add_epi32(
                _mm256_add_epi32(w[i - 16], s0),
                _mm256_add_epi32(w[i - 7], s1),
            );
        }

        // Working variables
        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        let mut f = h[5];
        let mut g = h[6];
        let mut hh = h[7];

        // 64 rounds
        for i in 0..64 {
            let k = _mm256_set1_epi32(K256[i] as i32);

            // big Sigma1(e) = (e >>> 6) ^ (e >>> 11) ^ (e >>> 25)
            let s1 = _mm256_xor_si256(
                _mm256_xor_si256(
                    _mm256_or_si256(_mm256_srli_epi32(e, 6), _mm256_slli_epi32(e, 26)),
                    _mm256_or_si256(_mm256_srli_epi32(e, 11), _mm256_slli_epi32(e, 21)),
                ),
                _mm256_or_si256(_mm256_srli_epi32(e, 25), _mm256_slli_epi32(e, 7)),
            );

            // ch = (e & f) ^ (~e & g)
            let ch = _mm256_xor_si256(_mm256_and_si256(e, f), _mm256_andnot_si256(e, g));

            // temp1 = h + S1 + ch + k + w[i]
            let temp1 = _mm256_add_epi32(
                _mm256_add_epi32(_mm256_add_epi32(hh, s1), ch),
                _mm256_add_epi32(k, w[i]),
            );

            // big Sigma0(a) = (a >>> 2) ^ (a >>> 13) ^ (a >>> 22)
            let s0 = _mm256_xor_si256(
                _mm256_xor_si256(
                    _mm256_or_si256(_mm256_srli_epi32(a, 2), _mm256_slli_epi32(a, 30)),
                    _mm256_or_si256(_mm256_srli_epi32(a, 13), _mm256_slli_epi32(a, 19)),
                ),
                _mm256_or_si256(_mm256_srli_epi32(a, 22), _mm256_slli_epi32(a, 10)),
            );

            // maj = (a & b) ^ (a & c) ^ (b & c)
            let maj = _mm256_xor_si256(
                _mm256_xor_si256(_mm256_and_si256(a, b), _mm256_and_si256(a, c)),
                _mm256_and_si256(b, c),
            );

            let temp2 = _mm256_add_epi32(s0, maj);

            hh = g;
            g = f;
            f = e;
            e = _mm256_add_epi32(d, temp1);
            d = c;
            c = b;
            b = a;
            a = _mm256_add_epi32(temp1, temp2);
        }

        // Add to state
        h[0] = _mm256_add_epi32(h[0], a);
        h[1] = _mm256_add_epi32(h[1], b);
        h[2] = _mm256_add_epi32(h[2], c);
        h[3] = _mm256_add_epi32(h[3], d);
        h[4] = _mm256_add_epi32(h[4], e);
        h[5] = _mm256_add_epi32(h[5], f);
        h[6] = _mm256_add_epi32(h[6], g);
        h[7] = _mm256_add_epi32(h[7], hh);
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 16-WAY PARALLEL SHA-256 (AVX-512)
// ═══════════════════════════════════════════════════════════════════════════════

/// 16-way parallel SHA-256 using AVX-512.
///
/// Processes 16 independent messages simultaneously using 512-bit SIMD.
/// Each 512-bit register holds 16 x 32-bit SHA-256 state words.
///
/// # Performance
///
/// When AVX-512 is available, this provides ~4x throughput vs 4-way SSE2.
/// Falls back to 4x BatchSha256x4 on systems without AVX-512.
#[cfg(all(target_arch = "x86_64", feature = "simd", feature = "std"))]
pub struct BatchSha256x16;

#[cfg(all(target_arch = "x86_64", feature = "simd", feature = "std"))]
impl BatchSha256x16 {
    /// Check if AVX-512F is available at runtime.
    #[inline]
    pub fn is_available() -> bool {
        std::is_x86_feature_detected!("avx512f")
    }

    /// Hash 16 messages in parallel.
    ///
    /// Uses AVX-512 when available, otherwise falls back to 4x BatchSha256x4.
    pub fn hash_parallel(messages: [&[u8]; 16]) -> [[u8; 32]; 16] {
        if Self::is_available() {
            // Use AVX-512 16-way parallel path
            unsafe { Self::hash_parallel_avx512(messages) }
        } else {
            // Fallback: 4x 4-way
            Self::hash_parallel_fallback(messages)
        }
    }

    /// Fallback implementation using 4x BatchSha256x4.
    fn hash_parallel_fallback(messages: [&[u8]; 16]) -> [[u8; 32]; 16] {
        let h0 = BatchSha256x4::hash_parallel([messages[0], messages[1], messages[2], messages[3]]);
        let h1 = BatchSha256x4::hash_parallel([messages[4], messages[5], messages[6], messages[7]]);
        let h2 =
            BatchSha256x4::hash_parallel([messages[8], messages[9], messages[10], messages[11]]);
        let h3 =
            BatchSha256x4::hash_parallel([messages[12], messages[13], messages[14], messages[15]]);
        [
            h0[0], h0[1], h0[2], h0[3], h1[0], h1[1], h1[2], h1[3], h2[0], h2[1], h2[2], h2[3],
            h3[0], h3[1], h3[2], h3[3],
        ]
    }

    /// AVX-512 accelerated 16-way parallel hashing.
    #[target_feature(enable = "avx512f")]
    unsafe fn hash_parallel_avx512(messages: [&[u8]; 16]) -> [[u8; 32]; 16] {
        use core::arch::x86_64::*;

        let lens: [usize; 16] = [
            messages[0].len(),
            messages[1].len(),
            messages[2].len(),
            messages[3].len(),
            messages[4].len(),
            messages[5].len(),
            messages[6].len(),
            messages[7].len(),
            messages[8].len(),
            messages[9].len(),
            messages[10].len(),
            messages[11].len(),
            messages[12].len(),
            messages[13].len(),
            messages[14].len(),
            messages[15].len(),
        ];

        // Calculate blocks needed for each message
        let blocks_needed: [usize; 16] = [
            Self::blocks_for_len(lens[0]),
            Self::blocks_for_len(lens[1]),
            Self::blocks_for_len(lens[2]),
            Self::blocks_for_len(lens[3]),
            Self::blocks_for_len(lens[4]),
            Self::blocks_for_len(lens[5]),
            Self::blocks_for_len(lens[6]),
            Self::blocks_for_len(lens[7]),
            Self::blocks_for_len(lens[8]),
            Self::blocks_for_len(lens[9]),
            Self::blocks_for_len(lens[10]),
            Self::blocks_for_len(lens[11]),
            Self::blocks_for_len(lens[12]),
            Self::blocks_for_len(lens[13]),
            Self::blocks_for_len(lens[14]),
            Self::blocks_for_len(lens[15]),
        ];

        let max_blocks = blocks_needed.iter().copied().max().unwrap_or(1);

        // Initialize 16-way state (8 state words x 16 lanes)
        let mut h: [__m512i; 8] = [
            _mm512_set1_epi32(H256_INIT[0] as i32),
            _mm512_set1_epi32(H256_INIT[1] as i32),
            _mm512_set1_epi32(H256_INIT[2] as i32),
            _mm512_set1_epi32(H256_INIT[3] as i32),
            _mm512_set1_epi32(H256_INIT[4] as i32),
            _mm512_set1_epi32(H256_INIT[5] as i32),
            _mm512_set1_epi32(H256_INIT[6] as i32),
            _mm512_set1_epi32(H256_INIT[7] as i32),
        ];

        // Store results for lanes that finish early
        let mut results: [Option<[u8; 32]>; 16] = [None; 16];

        for block_idx in 0..max_blocks {
            let offset = block_idx * 64;
            let mut blocks = [[0u8; 64]; 16];

            // Prepare blocks for all 16 lanes
            for lane in 0..16 {
                if results[lane].is_some() {
                    continue;
                }

                let msg = messages[lane];
                let msg_len = lens[lane];
                let full_data_blocks = msg_len / 64;
                let remaining = msg_len % 64;
                let needs_extra_block = remaining >= 56;

                if block_idx < full_data_blocks {
                    blocks[lane].copy_from_slice(&msg[offset..offset + 64]);
                } else if block_idx == full_data_blocks {
                    if remaining > 0 {
                        blocks[lane][..remaining].copy_from_slice(&msg[offset..]);
                    }
                    blocks[lane][remaining] = 0x80;

                    if !needs_extra_block {
                        let bit_len = (msg_len as u64) * 8;
                        blocks[lane][56..64].copy_from_slice(&bit_len.to_be_bytes());
                    }
                } else if block_idx == full_data_blocks + 1 && needs_extra_block {
                    let bit_len = (msg_len as u64) * 8;
                    blocks[lane][56..64].copy_from_slice(&bit_len.to_be_bytes());
                }
            }

            // Compress 16 blocks in parallel using AVX-512
            Self::compress_16_blocks_avx512(&mut h, &blocks);

            // Extract results for lanes that just finished
            for lane in 0..16 {
                if results[lane].is_none() && block_idx == blocks_needed[lane] - 1 {
                    let mut result = [0u8; 32];
                    for i in 0..8 {
                        let mut tmp = core::mem::MaybeUninit::<__m512i>::uninit();
                        _mm512_storeu_si512(tmp.as_mut_ptr(), h[i]);
                        let words: [i32; 16] = core::mem::transmute(tmp.assume_init());
                        let bytes = (words[lane] as u32).to_be_bytes();
                        result[i * 4..i * 4 + 4].copy_from_slice(&bytes);
                    }
                    results[lane] = Some(result);
                }
            }
        }

        // Collect final results
        let mut output = [[0u8; 32]; 16];
        for lane in 0..16 {
            output[lane] = results[lane].unwrap_or_else(|| {
                let mut result = [0u8; 32];
                for i in 0..8 {
                    let mut tmp = core::mem::MaybeUninit::<__m512i>::uninit();
                    unsafe { _mm512_storeu_si512(tmp.as_mut_ptr(), h[i]) };
                    let words: [i32; 16] = unsafe { core::mem::transmute(tmp.assume_init()) };
                    let bytes = (words[lane] as u32).to_be_bytes();
                    result[i * 4..i * 4 + 4].copy_from_slice(&bytes);
                }
                result
            });
        }

        output
    }

    /// Calculate number of SHA-256 blocks needed for a message of given length.
    #[inline]
    fn blocks_for_len(len: usize) -> usize {
        let data_blocks = len / 64;
        let remaining = len % 64;
        if remaining < 56 {
            data_blocks + 1
        } else {
            data_blocks + 2
        }
    }

    /// AVX-512 compress 16 blocks in parallel.
    #[target_feature(enable = "avx512f")]
    #[inline]
    unsafe fn compress_16_blocks_avx512(
        h: &mut [core::arch::x86_64::__m512i; 8],
        blocks: &[[u8; 64]; 16],
    ) {
        use core::arch::x86_64::*;

        // Load and transpose message schedules (16 lanes)
        let mut w: [__m512i; 64] = [_mm512_setzero_si512(); 64];

        for i in 0..16 {
            // Load word i from all 16 blocks
            w[i] = _mm512_set_epi32(
                u32::from_be_bytes(blocks[15][i * 4..i * 4 + 4].try_into().unwrap()) as i32,
                u32::from_be_bytes(blocks[14][i * 4..i * 4 + 4].try_into().unwrap()) as i32,
                u32::from_be_bytes(blocks[13][i * 4..i * 4 + 4].try_into().unwrap()) as i32,
                u32::from_be_bytes(blocks[12][i * 4..i * 4 + 4].try_into().unwrap()) as i32,
                u32::from_be_bytes(blocks[11][i * 4..i * 4 + 4].try_into().unwrap()) as i32,
                u32::from_be_bytes(blocks[10][i * 4..i * 4 + 4].try_into().unwrap()) as i32,
                u32::from_be_bytes(blocks[9][i * 4..i * 4 + 4].try_into().unwrap()) as i32,
                u32::from_be_bytes(blocks[8][i * 4..i * 4 + 4].try_into().unwrap()) as i32,
                u32::from_be_bytes(blocks[7][i * 4..i * 4 + 4].try_into().unwrap()) as i32,
                u32::from_be_bytes(blocks[6][i * 4..i * 4 + 4].try_into().unwrap()) as i32,
                u32::from_be_bytes(blocks[5][i * 4..i * 4 + 4].try_into().unwrap()) as i32,
                u32::from_be_bytes(blocks[4][i * 4..i * 4 + 4].try_into().unwrap()) as i32,
                u32::from_be_bytes(blocks[3][i * 4..i * 4 + 4].try_into().unwrap()) as i32,
                u32::from_be_bytes(blocks[2][i * 4..i * 4 + 4].try_into().unwrap()) as i32,
                u32::from_be_bytes(blocks[1][i * 4..i * 4 + 4].try_into().unwrap()) as i32,
                u32::from_be_bytes(blocks[0][i * 4..i * 4 + 4].try_into().unwrap()) as i32,
            );
        }

        // Extend message schedule w[16..64]
        for i in 16..64 {
            // sigma0(w[i-15])
            let x = w[i - 15];
            let s0 = _mm512_xor_si512(
                _mm512_xor_si512(
                    _mm512_or_si512(_mm512_srli_epi32(x, 7), _mm512_slli_epi32(x, 25)),
                    _mm512_or_si512(_mm512_srli_epi32(x, 18), _mm512_slli_epi32(x, 14)),
                ),
                _mm512_srli_epi32(x, 3),
            );

            // sigma1(w[i-2])
            let x = w[i - 2];
            let s1 = _mm512_xor_si512(
                _mm512_xor_si512(
                    _mm512_or_si512(_mm512_srli_epi32(x, 17), _mm512_slli_epi32(x, 15)),
                    _mm512_or_si512(_mm512_srli_epi32(x, 19), _mm512_slli_epi32(x, 13)),
                ),
                _mm512_srli_epi32(x, 10),
            );

            w[i] = _mm512_add_epi32(
                _mm512_add_epi32(w[i - 16], s0),
                _mm512_add_epi32(w[i - 7], s1),
            );
        }

        // Working variables
        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        let mut f = h[5];
        let mut g = h[6];
        let mut hh = h[7];

        // 64 rounds
        for i in 0..64 {
            let k = _mm512_set1_epi32(K256[i] as i32);

            // big Sigma1(e) = (e >>> 6) ^ (e >>> 11) ^ (e >>> 25)
            let s1 = _mm512_xor_si512(
                _mm512_xor_si512(
                    _mm512_or_si512(_mm512_srli_epi32(e, 6), _mm512_slli_epi32(e, 26)),
                    _mm512_or_si512(_mm512_srli_epi32(e, 11), _mm512_slli_epi32(e, 21)),
                ),
                _mm512_or_si512(_mm512_srli_epi32(e, 25), _mm512_slli_epi32(e, 7)),
            );

            // ch = (e & f) ^ (~e & g)
            let ch = _mm512_xor_si512(_mm512_and_si512(e, f), _mm512_andnot_si512(e, g));

            // temp1 = h + S1 + ch + k + w[i]
            let temp1 = _mm512_add_epi32(
                _mm512_add_epi32(_mm512_add_epi32(hh, s1), ch),
                _mm512_add_epi32(k, w[i]),
            );

            // big Sigma0(a) = (a >>> 2) ^ (a >>> 13) ^ (a >>> 22)
            let s0 = _mm512_xor_si512(
                _mm512_xor_si512(
                    _mm512_or_si512(_mm512_srli_epi32(a, 2), _mm512_slli_epi32(a, 30)),
                    _mm512_or_si512(_mm512_srli_epi32(a, 13), _mm512_slli_epi32(a, 19)),
                ),
                _mm512_or_si512(_mm512_srli_epi32(a, 22), _mm512_slli_epi32(a, 10)),
            );

            // maj = (a & b) ^ (a & c) ^ (b & c)
            let maj = _mm512_xor_si512(
                _mm512_xor_si512(_mm512_and_si512(a, b), _mm512_and_si512(a, c)),
                _mm512_and_si512(b, c),
            );

            let temp2 = _mm512_add_epi32(s0, maj);

            hh = g;
            g = f;
            f = e;
            e = _mm512_add_epi32(d, temp1);
            d = c;
            c = b;
            b = a;
            a = _mm512_add_epi32(temp1, temp2);
        }

        // Add to state
        h[0] = _mm512_add_epi32(h[0], a);
        h[1] = _mm512_add_epi32(h[1], b);
        h[2] = _mm512_add_epi32(h[2], c);
        h[3] = _mm512_add_epi32(h[3], d);
        h[4] = _mm512_add_epi32(h[4], e);
        h[5] = _mm512_add_epi32(h[5], f);
        h[6] = _mm512_add_epi32(h[6], g);
        h[7] = _mm512_add_epi32(h[7], hh);
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// MERKLE TREE HELPER
// ═══════════════════════════════════════════════════════════════════════════════

/// Compute a Merkle tree root using batch hashing.
///
/// This is significantly faster than sequential hashing for large trees.
#[cfg(feature = "alloc")]
pub fn merkle_root_sha256(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    if leaves.len() == 1 {
        return leaves[0];
    }

    let mut current_level: Vec<[u8; 32]> = leaves.to_vec();

    // Pad to even number
    if current_level.len() % 2 == 1 {
        current_level.push(*current_level.last().unwrap());
    }

    while current_level.len() > 1 {
        let mut next_level = Vec::with_capacity(current_level.len() / 2);

        // Process pairs in batches of 4 (8 leaves -> 4 parent hashes)
        let pairs: Vec<_> = current_level.chunks(2).collect();

        for batch in pairs.chunks(4) {
            if batch.len() == 4 {
                // Concatenate pairs for batch hashing
                let mut concat = [[0u8; 64]; 4];
                for (i, pair) in batch.iter().enumerate() {
                    concat[i][..32].copy_from_slice(&pair[0]);
                    concat[i][32..].copy_from_slice(&pair[1]);
                }

                let hashes = BatchSha256x4::hash_parallel([
                    &concat[0][..],
                    &concat[1][..],
                    &concat[2][..],
                    &concat[3][..],
                ]);
                next_level.extend_from_slice(&hashes);
            } else {
                // Handle remainder
                for pair in batch {
                    let mut concat = [0u8; 64];
                    concat[..32].copy_from_slice(&pair[0]);
                    concat[32..].copy_from_slice(&pair[1]);
                    next_level.push(crate::sha2::Sha256::hash(&concat));
                }
            }
        }

        // Pad to even if needed
        if next_level.len() > 1 && next_level.len() % 2 == 1 {
            next_level.push(*next_level.last().unwrap());
        }

        current_level = next_level;
    }

    current_level[0]
}

// ═══════════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_batch_sha256x4_basic() {
        let messages: [&[u8]; 4] = [b"hello", b"world", b"foo", b"bar"];

        let batch_hashes = BatchSha256x4::hash_parallel(messages);

        // Verify each hash matches single-message hash
        for (i, msg) in messages.iter().enumerate() {
            let single_hash = crate::sha2::Sha256::hash(msg);
            assert_eq!(batch_hashes[i], single_hash, "mismatch at index {}", i);
        }
    }

    #[test]
    fn test_batch_sha256x4_empty() {
        let messages: [&[u8]; 4] = [b"", b"", b"", b""];
        let batch_hashes = BatchSha256x4::hash_parallel(messages);

        let expected = crate::sha2::Sha256::hash(b"");
        for hash in &batch_hashes {
            assert_eq!(hash, &expected);
        }
    }

    #[test]
    fn test_batch_sha256x4_varied_lengths() {
        let messages: [&[u8]; 4] = [b"a", b"ab", b"abc", b"abcd"];

        let batch_hashes = BatchSha256x4::hash_parallel(messages);

        for (i, msg) in messages.iter().enumerate() {
            let single_hash = crate::sha2::Sha256::hash(msg);
            assert_eq!(batch_hashes[i], single_hash, "mismatch at index {}", i);
        }
    }

    #[test]
    fn test_batch_sha256x4_large_messages() {
        let msg1 = vec![0xABu8; 1000];
        let msg2 = vec![0xCDu8; 2000];
        let msg3 = vec![0xEFu8; 3000];
        let msg4 = vec![0x12u8; 4000];

        let messages: [&[u8]; 4] = [&msg1, &msg2, &msg3, &msg4];
        let batch_hashes = BatchSha256x4::hash_parallel(messages);

        for (i, msg) in messages.iter().enumerate() {
            let single_hash = crate::sha2::Sha256::hash(msg);
            assert_eq!(batch_hashes[i], single_hash, "mismatch at index {}", i);
        }
    }

    #[test]
    fn test_batch_hasher_trait() {
        let messages: [&[u8]; 4] = [b"one", b"two", b"three", b"four"];
        let hashes = BatchSha256x4::hash_parallel(messages);

        assert_eq!(hashes.len(), 4);
        assert_eq!(BatchSha256x4::LANES, 4);
        assert_eq!(BatchSha256x4::OUTPUT_SIZE, 32);

        // Verify each hash is correct
        for (i, msg) in messages.iter().enumerate() {
            let single = crate::sha2::Sha256::hash(msg);
            assert_eq!(hashes[i], single);
        }
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_batch_varied() {
        let messages: &[&[u8]] = &[b"1", b"2", b"3", b"4", b"5", b"6", b"7"];
        let hashes = BatchSha256x4::hash_batch_varied(messages);

        assert_eq!(hashes.len(), 7);

        for (i, msg) in messages.iter().enumerate() {
            let single = crate::sha2::Sha256::hash(msg);
            assert_eq!(hashes[i], single);
        }
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_merkle_root() {
        // Test with 4 leaves
        let leaves: Vec<[u8; 32]> = (0..4u8).map(|i| crate::sha2::Sha256::hash(&[i])).collect();

        let root = merkle_root_sha256(&leaves);

        // Manually compute expected root
        let mut concat01 = [0u8; 64];
        concat01[..32].copy_from_slice(&leaves[0]);
        concat01[32..].copy_from_slice(&leaves[1]);
        let h01 = crate::sha2::Sha256::hash(&concat01);

        let mut concat23 = [0u8; 64];
        concat23[..32].copy_from_slice(&leaves[2]);
        concat23[32..].copy_from_slice(&leaves[3]);
        let h23 = crate::sha2::Sha256::hash(&concat23);

        let mut concat_root = [0u8; 64];
        concat_root[..32].copy_from_slice(&h01);
        concat_root[32..].copy_from_slice(&h23);
        let expected_root = crate::sha2::Sha256::hash(&concat_root);

        assert_eq!(root, expected_root);
    }

    // AVX-512 16-way tests
    #[cfg(all(target_arch = "x86_64", feature = "simd", feature = "std"))]
    #[test]
    fn test_batch_sha256x16_basic() {
        use super::BatchSha256x16;

        let messages: [&[u8]; 16] = [
            b"hello", b"world", b"foo", b"bar", b"test1", b"test2", b"test3", b"test4", b"msg5",
            b"msg6", b"msg7", b"msg8", b"data9", b"data10", b"data11", b"data12",
        ];

        let batch_hashes = BatchSha256x16::hash_parallel(messages);

        // Verify each hash matches single-message hash
        for (i, msg) in messages.iter().enumerate() {
            let single_hash = crate::sha2::Sha256::hash(msg);
            assert_eq!(batch_hashes[i], single_hash, "mismatch at index {}", i);
        }
    }

    #[cfg(all(target_arch = "x86_64", feature = "simd", feature = "std"))]
    #[test]
    fn test_batch_sha256x16_varied_lengths() {
        use super::BatchSha256x16;

        let msg1 = vec![0xABu8; 100];
        let msg2 = vec![0xCDu8; 200];
        let msg3 = vec![0xEFu8; 64];
        let msg4 = vec![0x12u8; 63];
        let msg5 = vec![0x34u8; 55];
        let msg6 = vec![0x56u8; 56];
        let msg7 = vec![0x78u8; 1];
        let msg8 = vec![0x9Au8; 0];
        let msg9 = vec![0xBCu8; 1000];
        let msg10 = vec![0xDEu8; 500];
        let msg11 = vec![0xF0u8; 128];
        let msg12 = vec![0x11u8; 256];
        let msg13 = vec![0x22u8; 512];
        let msg14 = vec![0x33u8; 1024];
        let msg15 = vec![0x44u8; 2048];
        let msg16 = vec![0x55u8; 4096];

        let messages: [&[u8]; 16] = [
            &msg1, &msg2, &msg3, &msg4, &msg5, &msg6, &msg7, &msg8, &msg9, &msg10, &msg11, &msg12,
            &msg13, &msg14, &msg15, &msg16,
        ];

        let batch_hashes = BatchSha256x16::hash_parallel(messages);

        for (i, msg) in messages.iter().enumerate() {
            let single_hash = crate::sha2::Sha256::hash(msg);
            assert_eq!(batch_hashes[i], single_hash, "mismatch at index {}", i);
        }
    }

    // AVX2 8-way tests
    #[cfg(all(target_arch = "x86_64", feature = "simd", feature = "std"))]
    #[test]
    fn test_batch_sha256x8_basic() {
        use super::BatchSha256x8;

        let messages: [&[u8]; 8] = [
            b"hello", b"world", b"foo", b"bar", b"test1", b"test2", b"test3", b"test4",
        ];

        let batch_hashes = BatchSha256x8::hash_parallel(messages);

        // Verify each hash matches single-message hash
        for (i, msg) in messages.iter().enumerate() {
            let single_hash = crate::sha2::Sha256::hash(msg);
            assert_eq!(batch_hashes[i], single_hash, "mismatch at index {}", i);
        }
    }

    #[cfg(all(target_arch = "x86_64", feature = "simd", feature = "std"))]
    #[test]
    fn test_batch_sha256x8_varied_lengths() {
        use super::BatchSha256x8;

        let msg1 = vec![0xABu8; 100];
        let msg2 = vec![0xCDu8; 200];
        let msg3 = vec![0xEFu8; 64];
        let msg4 = vec![0x12u8; 63];
        let msg5 = vec![0x34u8; 55];
        let msg6 = vec![0x56u8; 56];
        let msg7 = vec![0x78u8; 1];
        let msg8 = vec![0x9Au8; 0];

        let messages: [&[u8]; 8] = [&msg1, &msg2, &msg3, &msg4, &msg5, &msg6, &msg7, &msg8];

        let batch_hashes = BatchSha256x8::hash_parallel(messages);

        for (i, msg) in messages.iter().enumerate() {
            let single_hash = crate::sha2::Sha256::hash(msg);
            assert_eq!(batch_hashes[i], single_hash, "mismatch at index {}", i);
        }
    }

    #[cfg(all(target_arch = "x86_64", feature = "simd", feature = "std"))]
    #[test]
    fn test_batch_sha256x8_large_messages() {
        use super::BatchSha256x8;

        let msg1 = vec![0xABu8; 1000];
        let msg2 = vec![0xCDu8; 2000];
        let msg3 = vec![0xEFu8; 3000];
        let msg4 = vec![0x12u8; 4000];
        let msg5 = vec![0x34u8; 500];
        let msg6 = vec![0x56u8; 1500];
        let msg7 = vec![0x78u8; 2500];
        let msg8 = vec![0x9Au8; 3500];

        let messages: [&[u8]; 8] = [&msg1, &msg2, &msg3, &msg4, &msg5, &msg6, &msg7, &msg8];

        let batch_hashes = BatchSha256x8::hash_parallel(messages);

        for (i, msg) in messages.iter().enumerate() {
            let single_hash = crate::sha2::Sha256::hash(msg);
            assert_eq!(batch_hashes[i], single_hash, "mismatch at index {}", i);
        }
    }

    // SIMD tests (x86_64 only)
    #[cfg(all(target_arch = "x86_64", feature = "simd"))]
    mod simd_tests {
        use super::super::simd::*;

        #[test]
        fn test_simd_compress_matches_portable() {
            // Create 4 identical 64-byte blocks
            let block = [0x61u8; 64]; // 'a' repeated
            let blocks = [block, block, block, block];

            // SIMD compression
            let simd_hashes = unsafe {
                let mut state = SimdSha256x4State::new();
                state.compress_4_blocks(&blocks);

                // Add padding block for 64-byte message
                let mut padded = [[0u8; 64]; 4];
                for p in &mut padded {
                    p[0] = 0x80;
                    // Length = 512 bits in big-endian at bytes 56-63
                    p[62] = 0x02;
                    p[63] = 0x00;
                }
                state.compress_4_blocks(&padded);
                state.finalize()
            };

            // All 4 should be identical (same input)
            assert_eq!(simd_hashes[0], simd_hashes[1]);
            assert_eq!(simd_hashes[1], simd_hashes[2]);
            assert_eq!(simd_hashes[2], simd_hashes[3]);

            // Compare to reference implementation
            let reference = crate::sha2::Sha256::hash(&block);
            assert_eq!(
                simd_hashes[0], reference,
                "SIMD hash doesn't match reference"
            );
        }

        #[test]
        fn test_simd_different_inputs() {
            // Create 4 different 64-byte blocks
            let mut blocks = [[0u8; 64]; 4];
            for (i, block) in blocks.iter_mut().enumerate() {
                block.fill((i as u8) + 0x41); // A, B, C, D
            }

            let simd_hashes = unsafe {
                let mut state = SimdSha256x4State::new();
                state.compress_4_blocks(&blocks);

                let mut padded = [[0u8; 64]; 4];
                for p in &mut padded {
                    p[0] = 0x80;
                    p[62] = 0x02;
                    p[63] = 0x00;
                }
                state.compress_4_blocks(&padded);
                state.finalize()
            };

            // Each should match its reference
            for (i, block) in blocks.iter().enumerate() {
                let reference = crate::sha2::Sha256::hash(block);
                assert_eq!(simd_hashes[i], reference, "SIMD hash {} doesn't match", i);
            }
        }
    }
}
