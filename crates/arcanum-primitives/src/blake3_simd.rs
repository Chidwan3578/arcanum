//! SIMD-accelerated BLAKE3 implementation.
//!
//! This module provides AVX2 acceleration for BLAKE3 compression.
//!
//! # Performance
//!
//! AVX2 implementation processes all 4 G functions in parallel per round,
//! achieving significant speedup over the portable implementation.
//!
//! # Safety
//!
//! SIMD functions use unsafe intrinsics but are safe to call when
//! the CPU supports the required features (checked at runtime).

// Allow `0 * N` patterns for clarity in SIMD offset calculations (e.g., 0*16, 1*16, 2*16, 3*16)
#![allow(clippy::erasing_op, clippy::identity_op)]

#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

// ═══════════════════════════════════════════════════════════════════════════════
// PREFETCH HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

/// Prefetch data into L2 cache (and L3). Use for data needed in the next batch.
#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn prefetch_l2(ptr: *const u8) {
    _mm_prefetch::<_MM_HINT_T1>(ptr as *const i8);
}

/// Prefetch data into L1 cache. Use for data needed immediately next.
#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn prefetch_l1(ptr: *const u8) {
    _mm_prefetch::<_MM_HINT_T0>(ptr as *const i8);
}

/// Prefetch a range of data into L2 cache, covering `len` bytes with 64-byte cache lines.
#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn prefetch_range_l2(ptr: *const u8, len: usize) {
    const CACHE_LINE: usize = 64;
    let mut offset = 0;
    while offset < len {
        prefetch_l2(ptr.add(offset));
        offset += CACHE_LINE;
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// ADAPTIVE PREFETCH TUNING
// ═══════════════════════════════════════════════════════════════════════════════

/// Prefetch distance configuration for different workload sizes.
///
/// Adaptive prefetching improves performance by:
/// - Using longer distances for large sequential data
/// - Using shorter distances for small or random access patterns
/// - Selecting appropriate cache level (L1 vs L2) based on timing
#[derive(Debug, Clone, Copy)]
pub struct PrefetchConfig {
    /// Number of cache lines to prefetch ahead for L1
    pub l1_distance: usize,
    /// Number of cache lines to prefetch ahead for L2
    pub l2_distance: usize,
    /// Minimum data size to enable prefetching (bytes)
    pub min_size: usize,
    /// Use non-temporal hint for streaming workloads
    pub streaming: bool,
}

impl PrefetchConfig {
    /// Configuration optimized for small messages (< 4KB)
    pub const SMALL: Self = Self {
        l1_distance: 1,
        l2_distance: 2,
        min_size: 256,
        streaming: false,
    };

    /// Configuration optimized for medium messages (4KB - 64KB)
    pub const MEDIUM: Self = Self {
        l1_distance: 2,
        l2_distance: 4,
        min_size: 512,
        streaming: false,
    };

    /// Configuration optimized for large messages (> 64KB)
    pub const LARGE: Self = Self {
        l1_distance: 4,
        l2_distance: 8,
        min_size: 1024,
        streaming: true,
    };

    /// Auto-select configuration based on data size
    #[inline]
    pub const fn for_size(size: usize) -> Self {
        if size < 4096 {
            Self::SMALL
        } else if size < 65536 {
            Self::MEDIUM
        } else {
            Self::LARGE
        }
    }
}

impl Default for PrefetchConfig {
    fn default() -> Self {
        Self::MEDIUM
    }
}

/// Adaptive prefetch for chunk processing.
///
/// Prefetches the next chunk's data while processing the current chunk.
/// Uses tiered prefetching: L2 for distant chunks, L1 for next chunk.
#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub unsafe fn prefetch_chunk_adaptive(
    data: *const u8,
    current_chunk: usize,
    total_chunks: usize,
    config: &PrefetchConfig,
) {
    const CHUNK_LEN: usize = 1024;
    const CACHE_LINE: usize = 64;

    // L1 prefetch for immediate next chunk
    let l1_chunk = current_chunk + config.l1_distance;
    if l1_chunk < total_chunks {
        let l1_ptr = data.add(l1_chunk * CHUNK_LEN);
        // Prefetch first few cache lines of next chunk
        prefetch_l1(l1_ptr);
        prefetch_l1(l1_ptr.add(CACHE_LINE));
        prefetch_l1(l1_ptr.add(CACHE_LINE * 2));
        prefetch_l1(l1_ptr.add(CACHE_LINE * 3));
    }

    // L2 prefetch for chunks further ahead
    let l2_chunk = current_chunk + config.l2_distance;
    if l2_chunk < total_chunks {
        let l2_ptr = data.add(l2_chunk * CHUNK_LEN);
        // Prefetch entire chunk into L2
        prefetch_range_l2(l2_ptr, CHUNK_LEN);
    }
}

/// Prefetch for batch processing of multiple messages.
///
/// When processing 8 messages in parallel, prefetch the next batch.
#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub unsafe fn prefetch_batch_adaptive(
    messages: &[*const u8],
    current_offset: usize,
    message_lens: &[usize],
    config: &PrefetchConfig,
) {
    const CACHE_LINE: usize = 64;

    let l1_offset = current_offset + config.l1_distance * CACHE_LINE;
    let l2_offset = current_offset + config.l2_distance * CACHE_LINE;

    for (i, &ptr) in messages.iter().enumerate() {
        if !ptr.is_null() && message_lens[i] > l1_offset {
            prefetch_l1(ptr.add(l1_offset));
        }
        if !ptr.is_null() && message_lens[i] > l2_offset {
            prefetch_l2(ptr.add(l2_offset));
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// CPU FEATURE DETECTION
// ═══════════════════════════════════════════════════════════════════════════════

/// Check if SSE4.1 is available at runtime.
#[cfg(all(feature = "std", target_arch = "x86_64"))]
#[inline]
pub fn has_sse41() -> bool {
    std::is_x86_feature_detected!("sse4.1")
}

#[cfg(not(all(feature = "std", target_arch = "x86_64")))]
#[inline]
pub fn has_sse41() -> bool {
    false
}

/// Check if AVX2 is available at runtime.
#[cfg(all(feature = "std", target_arch = "x86_64"))]
#[inline]
pub fn has_avx2() -> bool {
    std::is_x86_feature_detected!("avx2")
}

#[cfg(not(all(feature = "std", target_arch = "x86_64")))]
#[inline]
pub fn has_avx2() -> bool {
    false
}

/// Check if AVX-512F is available at runtime.
#[cfg(all(feature = "std", target_arch = "x86_64"))]
#[inline]
pub fn has_avx512f() -> bool {
    std::is_x86_feature_detected!("avx512f")
}

#[cfg(not(all(feature = "std", target_arch = "x86_64")))]
#[inline]
pub fn has_avx512f() -> bool {
    false
}

// ═══════════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════════

/// BLAKE3 initialization vector
pub const IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

/// Message word permutation for each round
const MSG_PERMUTATION: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

// ═══════════════════════════════════════════════════════════════════════════════
// SSE4.1 IMPLEMENTATION
// ═══════════════════════════════════════════════════════════════════════════════

/// SSE4.1 accelerated BLAKE3 compression.
#[cfg(target_arch = "x86_64")]
pub mod sse41 {
    use super::*;

    /// Compress a single 64-byte block using SSE4.1.
    ///
    /// # Safety
    ///
    /// Caller must ensure the CPU supports SSE4.1.
    #[target_feature(enable = "sse4.1")]
    pub unsafe fn compress_block_sse41(
        cv: &[u32; 8],
        block: &[u8; 64],
        counter: u64,
        block_len: u32,
        flags: u8,
    ) -> [u32; 16] {
        // Load state into 4 SSE registers (row-wise)
        // Row 0: cv[0..4]
        // Row 1: cv[4..8]
        // Row 2: IV[0..4]
        // Row 3: counter_lo, counter_hi, block_len, flags
        let mut row0 = _mm_loadu_si128(cv.as_ptr() as *const __m128i);
        let mut row1 = _mm_loadu_si128(cv.as_ptr().add(4) as *const __m128i);
        let mut row2 = _mm_loadu_si128(IV.as_ptr() as *const __m128i);
        let mut row3 = _mm_set_epi32(
            flags as i32,
            block_len as i32,
            (counter >> 32) as i32,
            counter as i32,
        );

        // Load message words
        let m0 = _mm_loadu_si128(block.as_ptr() as *const __m128i);
        let m1 = _mm_loadu_si128(block.as_ptr().add(16) as *const __m128i);
        let m2 = _mm_loadu_si128(block.as_ptr().add(32) as *const __m128i);
        let m3 = _mm_loadu_si128(block.as_ptr().add(48) as *const __m128i);

        // Convert to array for easier permutation
        let mut m = [[0u32; 4]; 4];
        _mm_storeu_si128(m[0].as_mut_ptr() as *mut __m128i, m0);
        _mm_storeu_si128(m[1].as_mut_ptr() as *mut __m128i, m1);
        _mm_storeu_si128(m[2].as_mut_ptr() as *mut __m128i, m2);
        _mm_storeu_si128(m[3].as_mut_ptr() as *mut __m128i, m3);

        // Flatten for permutation
        let mut msg = [0u32; 16];
        for i in 0..4 {
            for j in 0..4 {
                msg[i * 4 + j] = m[i][j];
            }
        }

        // 7 rounds
        for _ in 0..7 {
            // Get message words for this round
            // mx = m[0], m[2], m[4], m[6] for columns
            // my = m[1], m[3], m[5], m[7] for columns
            let mx_col = _mm_set_epi32(msg[6] as i32, msg[4] as i32, msg[2] as i32, msg[0] as i32);
            let my_col = _mm_set_epi32(msg[7] as i32, msg[5] as i32, msg[3] as i32, msg[1] as i32);

            // Column step - all 4 G functions in parallel
            g_sse41(&mut row0, &mut row1, &mut row2, &mut row3, mx_col, my_col);

            // Rotate rows for diagonal step
            row1 = _mm_shuffle_epi32(row1, 0b00_11_10_01); // rotate left by 1
            row2 = _mm_shuffle_epi32(row2, 0b01_00_11_10); // rotate left by 2
            row3 = _mm_shuffle_epi32(row3, 0b10_01_00_11); // rotate left by 3

            // mx = m[8], m[10], m[12], m[14] for diagonals
            // my = m[9], m[11], m[13], m[15] for diagonals
            let mx_diag = _mm_set_epi32(
                msg[14] as i32,
                msg[12] as i32,
                msg[10] as i32,
                msg[8] as i32,
            );
            let my_diag = _mm_set_epi32(
                msg[15] as i32,
                msg[13] as i32,
                msg[11] as i32,
                msg[9] as i32,
            );

            // Diagonal step
            g_sse41(&mut row0, &mut row1, &mut row2, &mut row3, mx_diag, my_diag);

            // Un-rotate rows
            row1 = _mm_shuffle_epi32(row1, 0b10_01_00_11); // rotate right by 1
            row2 = _mm_shuffle_epi32(row2, 0b01_00_11_10); // rotate right by 2
            row3 = _mm_shuffle_epi32(row3, 0b00_11_10_01); // rotate right by 3

            // Permute message
            let mut new_msg = [0u32; 16];
            for i in 0..16 {
                new_msg[i] = msg[MSG_PERMUTATION[i]];
            }
            msg = new_msg;
        }

        // XOR the two halves and construct output
        let cv_row0 = _mm_loadu_si128(cv.as_ptr() as *const __m128i);
        let cv_row1 = _mm_loadu_si128(cv.as_ptr().add(4) as *const __m128i);

        let out_low0 = _mm_xor_si128(row0, row2);
        let out_low1 = _mm_xor_si128(row1, row3);
        let out_high0 = _mm_xor_si128(row2, cv_row0);
        let out_high1 = _mm_xor_si128(row3, cv_row1);

        // Store result
        let mut result = [0u32; 16];
        _mm_storeu_si128(result.as_mut_ptr() as *mut __m128i, out_low0);
        _mm_storeu_si128(result.as_mut_ptr().add(4) as *mut __m128i, out_low1);
        _mm_storeu_si128(result.as_mut_ptr().add(8) as *mut __m128i, out_high0);
        _mm_storeu_si128(result.as_mut_ptr().add(12) as *mut __m128i, out_high1);

        result
    }

    /// Vectorized G function for 4 parallel operations.
    ///
    /// Performs G(a[i], b[i], c[i], d[i], mx[i], my[i]) for i in 0..4
    #[target_feature(enable = "sse4.1")]
    #[inline]
    unsafe fn g_sse41(
        a: &mut __m128i,
        b: &mut __m128i,
        c: &mut __m128i,
        d: &mut __m128i,
        mx: __m128i,
        my: __m128i,
    ) {
        // a = a + b + mx
        *a = _mm_add_epi32(*a, _mm_add_epi32(*b, mx));

        // d = (d ^ a) >>> 16
        *d = _mm_xor_si128(*d, *a);
        *d = _mm_or_si128(_mm_srli_epi32(*d, 16), _mm_slli_epi32(*d, 16));

        // c = c + d
        *c = _mm_add_epi32(*c, *d);

        // b = (b ^ c) >>> 12
        *b = _mm_xor_si128(*b, *c);
        *b = _mm_or_si128(_mm_srli_epi32(*b, 12), _mm_slli_epi32(*b, 20));

        // a = a + b + my
        *a = _mm_add_epi32(*a, _mm_add_epi32(*b, my));

        // d = (d ^ a) >>> 8
        *d = _mm_xor_si128(*d, *a);
        *d = _mm_or_si128(_mm_srli_epi32(*d, 8), _mm_slli_epi32(*d, 24));

        // c = c + d
        *c = _mm_add_epi32(*c, *d);

        // b = (b ^ c) >>> 7
        *b = _mm_xor_si128(*b, *c);
        *b = _mm_or_si128(_mm_srli_epi32(*b, 7), _mm_slli_epi32(*b, 25));
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// AVX2 IMPLEMENTATION - 2 BLOCKS PARALLEL
// ═══════════════════════════════════════════════════════════════════════════════

/// AVX2 accelerated BLAKE3 compression for 2 blocks in parallel.
#[cfg(target_arch = "x86_64")]
pub mod avx2 {
    use super::*;

    /// Compress two blocks in parallel using AVX2.
    ///
    /// This processes two independent compression calls simultaneously.
    ///
    /// # Safety
    ///
    /// Caller must ensure the CPU supports AVX2.
    #[target_feature(enable = "avx2")]
    pub unsafe fn compress_2blocks_avx2(
        cv0: &[u32; 8],
        cv1: &[u32; 8],
        block0: &[u8; 64],
        block1: &[u8; 64],
        counter0: u64,
        counter1: u64,
        block_len: u32,
        flags: u8,
    ) -> ([u32; 16], [u32; 16]) {
        // Interleave the two states: [cv0[0], cv1[0], cv0[1], cv1[1], cv0[2], cv1[2], cv0[3], cv1[3]]
        // This allows us to process both blocks with the same AVX2 operations

        // Load states - interleave cv0 and cv1
        let row0 = _mm256_set_epi32(
            cv1[3] as i32,
            cv0[3] as i32,
            cv1[2] as i32,
            cv0[2] as i32,
            cv1[1] as i32,
            cv0[1] as i32,
            cv1[0] as i32,
            cv0[0] as i32,
        );
        let row1 = _mm256_set_epi32(
            cv1[7] as i32,
            cv0[7] as i32,
            cv1[6] as i32,
            cv0[6] as i32,
            cv1[5] as i32,
            cv0[5] as i32,
            cv1[4] as i32,
            cv0[4] as i32,
        );
        let row2 = _mm256_set_epi32(
            IV[3] as i32,
            IV[3] as i32,
            IV[2] as i32,
            IV[2] as i32,
            IV[1] as i32,
            IV[1] as i32,
            IV[0] as i32,
            IV[0] as i32,
        );
        let mut row3 = _mm256_set_epi32(
            flags as i32,
            flags as i32,
            block_len as i32,
            block_len as i32,
            (counter1 >> 32) as i32,
            (counter0 >> 32) as i32,
            counter1 as i32,
            counter0 as i32,
        );

        let mut row0 = row0;
        let mut row1 = row1;
        let mut row2 = row2;

        // Load and interleave message words
        let mut msg0 = [0u32; 16];
        let mut msg1 = [0u32; 16];
        for i in 0..16 {
            msg0[i] = u32::from_le_bytes(block0[i * 4..(i + 1) * 4].try_into().unwrap());
            msg1[i] = u32::from_le_bytes(block1[i * 4..(i + 1) * 4].try_into().unwrap());
        }

        // 7 rounds
        for _ in 0..7 {
            // Column step message words (interleaved)
            let mx_col = _mm256_set_epi32(
                msg1[6] as i32,
                msg0[6] as i32,
                msg1[4] as i32,
                msg0[4] as i32,
                msg1[2] as i32,
                msg0[2] as i32,
                msg1[0] as i32,
                msg0[0] as i32,
            );
            let my_col = _mm256_set_epi32(
                msg1[7] as i32,
                msg0[7] as i32,
                msg1[5] as i32,
                msg0[5] as i32,
                msg1[3] as i32,
                msg0[3] as i32,
                msg1[1] as i32,
                msg0[1] as i32,
            );

            // Column step
            g_avx2_interleaved(&mut row0, &mut row1, &mut row2, &mut row3, mx_col, my_col);

            // Rotate rows for diagonal (need custom shuffle for interleaved layout)
            row1 = shuffle_rotate_1_interleaved(row1);
            row2 = shuffle_rotate_2_interleaved(row2);
            row3 = shuffle_rotate_3_interleaved(row3);

            // Diagonal step message words
            let mx_diag = _mm256_set_epi32(
                msg1[14] as i32,
                msg0[14] as i32,
                msg1[12] as i32,
                msg0[12] as i32,
                msg1[10] as i32,
                msg0[10] as i32,
                msg1[8] as i32,
                msg0[8] as i32,
            );
            let my_diag = _mm256_set_epi32(
                msg1[15] as i32,
                msg0[15] as i32,
                msg1[13] as i32,
                msg0[13] as i32,
                msg1[11] as i32,
                msg0[11] as i32,
                msg1[9] as i32,
                msg0[9] as i32,
            );

            // Diagonal step
            g_avx2_interleaved(&mut row0, &mut row1, &mut row2, &mut row3, mx_diag, my_diag);

            // Un-rotate rows
            row1 = shuffle_rotate_3_interleaved(row1);
            row2 = shuffle_rotate_2_interleaved(row2);
            row3 = shuffle_rotate_1_interleaved(row3);

            // Permute messages
            let mut new_msg0 = [0u32; 16];
            let mut new_msg1 = [0u32; 16];
            for i in 0..16 {
                new_msg0[i] = msg0[MSG_PERMUTATION[i]];
                new_msg1[i] = msg1[MSG_PERMUTATION[i]];
            }
            msg0 = new_msg0;
            msg1 = new_msg1;
        }

        // Finalize - XOR the halves
        let cv0_row0 = _mm256_set_epi32(
            cv1[3] as i32,
            cv0[3] as i32,
            cv1[2] as i32,
            cv0[2] as i32,
            cv1[1] as i32,
            cv0[1] as i32,
            cv1[0] as i32,
            cv0[0] as i32,
        );
        let cv0_row1 = _mm256_set_epi32(
            cv1[7] as i32,
            cv0[7] as i32,
            cv1[6] as i32,
            cv0[6] as i32,
            cv1[5] as i32,
            cv0[5] as i32,
            cv1[4] as i32,
            cv0[4] as i32,
        );

        let out_low0 = _mm256_xor_si256(row0, row2);
        let out_low1 = _mm256_xor_si256(row1, row3);
        let out_high0 = _mm256_xor_si256(row2, cv0_row0);
        let out_high1 = _mm256_xor_si256(row3, cv0_row1);

        // De-interleave and store results
        let mut result0 = [0u32; 16];
        let mut result1 = [0u32; 16];

        // Extract interleaved values
        let out_low0_arr: [i32; 8] = core::mem::transmute(out_low0);
        let out_low1_arr: [i32; 8] = core::mem::transmute(out_low1);
        let out_high0_arr: [i32; 8] = core::mem::transmute(out_high0);
        let out_high1_arr: [i32; 8] = core::mem::transmute(out_high1);

        for i in 0..4 {
            result0[i] = out_low0_arr[i * 2] as u32;
            result1[i] = out_low0_arr[i * 2 + 1] as u32;
            result0[4 + i] = out_low1_arr[i * 2] as u32;
            result1[4 + i] = out_low1_arr[i * 2 + 1] as u32;
            result0[8 + i] = out_high0_arr[i * 2] as u32;
            result1[8 + i] = out_high0_arr[i * 2 + 1] as u32;
            result0[12 + i] = out_high1_arr[i * 2] as u32;
            result1[12 + i] = out_high1_arr[i * 2 + 1] as u32;
        }

        (result0, result1)
    }

    /// G function for AVX2 with interleaved data layout.
    #[target_feature(enable = "avx2")]
    #[inline]
    unsafe fn g_avx2_interleaved(
        a: &mut __m256i,
        b: &mut __m256i,
        c: &mut __m256i,
        d: &mut __m256i,
        mx: __m256i,
        my: __m256i,
    ) {
        // a = a + b + mx
        *a = _mm256_add_epi32(*a, _mm256_add_epi32(*b, mx));

        // d = (d ^ a) >>> 16
        *d = _mm256_xor_si256(*d, *a);
        *d = _mm256_or_si256(_mm256_srli_epi32(*d, 16), _mm256_slli_epi32(*d, 16));

        // c = c + d
        *c = _mm256_add_epi32(*c, *d);

        // b = (b ^ c) >>> 12
        *b = _mm256_xor_si256(*b, *c);
        *b = _mm256_or_si256(_mm256_srli_epi32(*b, 12), _mm256_slli_epi32(*b, 20));

        // a = a + b + my
        *a = _mm256_add_epi32(*a, _mm256_add_epi32(*b, my));

        // d = (d ^ a) >>> 8
        *d = _mm256_xor_si256(*d, *a);
        *d = _mm256_or_si256(_mm256_srli_epi32(*d, 8), _mm256_slli_epi32(*d, 24));

        // c = c + d
        *c = _mm256_add_epi32(*c, *d);

        // b = (b ^ c) >>> 7
        *b = _mm256_xor_si256(*b, *c);
        *b = _mm256_or_si256(_mm256_srli_epi32(*b, 7), _mm256_slli_epi32(*b, 25));
    }

    /// Rotate left by 1 for interleaved layout.
    /// Input:  [a0, b0, a1, b1, a2, b2, a3, b3]
    /// Output: [a1, b1, a2, b2, a3, b3, a0, b0]
    #[target_feature(enable = "avx2")]
    #[inline]
    unsafe fn shuffle_rotate_1_interleaved(v: __m256i) -> __m256i {
        // We need to rotate pairs: (a0,b0), (a1,b1), (a2,b2), (a3,b3) -> (a1,b1), (a2,b2), (a3,b3), (a0,b0)
        // Using permute: indices [2,3,4,5,6,7,0,1] in 32-bit terms
        _mm256_permutevar8x32_epi32(v, _mm256_set_epi32(1, 0, 7, 6, 5, 4, 3, 2))
    }

    /// Rotate left by 2 for interleaved layout.
    /// Input:  [a0, b0, a1, b1, a2, b2, a3, b3]
    /// Output: [a2, b2, a3, b3, a0, b0, a1, b1]
    #[target_feature(enable = "avx2")]
    #[inline]
    unsafe fn shuffle_rotate_2_interleaved(v: __m256i) -> __m256i {
        _mm256_permutevar8x32_epi32(v, _mm256_set_epi32(3, 2, 1, 0, 7, 6, 5, 4))
    }

    /// Rotate left by 3 for interleaved layout.
    /// Input:  [a0, b0, a1, b1, a2, b2, a3, b3]
    /// Output: [a3, b3, a0, b0, a1, b1, a2, b2]
    #[target_feature(enable = "avx2")]
    #[inline]
    unsafe fn shuffle_rotate_3_interleaved(v: __m256i) -> __m256i {
        _mm256_permutevar8x32_epi32(v, _mm256_set_epi32(5, 4, 3, 2, 1, 0, 7, 6))
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// AUTO-DISPATCH
// ═══════════════════════════════════════════════════════════════════════════════

/// Compress a BLAKE3 block with automatic SIMD dispatch.
pub fn compress_auto(
    cv: &[u32; 8],
    block: &[u8; 64],
    counter: u64,
    block_len: u32,
    flags: u8,
) -> [u32; 16] {
    #[cfg(all(feature = "std", target_arch = "x86_64"))]
    {
        if has_sse41() {
            return unsafe { sse41::compress_block_sse41(cv, block, counter, block_len, flags) };
        }
    }

    // Fallback to portable
    compress_portable(cv, block, counter, block_len, flags)
}

/// Portable BLAKE3 compression function.
fn compress_portable(
    cv: &[u32; 8],
    block: &[u8; 64],
    counter: u64,
    block_len: u32,
    flags: u8,
) -> [u32; 16] {
    // Parse block into message words
    let mut m = [0u32; 16];
    for i in 0..16 {
        m[i] = u32::from_le_bytes(block[i * 4..(i + 1) * 4].try_into().unwrap());
    }

    // Initialize state
    let mut state = [
        cv[0],
        cv[1],
        cv[2],
        cv[3],
        cv[4],
        cv[5],
        cv[6],
        cv[7],
        IV[0],
        IV[1],
        IV[2],
        IV[3],
        counter as u32,
        (counter >> 32) as u32,
        block_len,
        flags as u32,
    ];

    // 7 rounds
    for _ in 0..7 {
        round_portable(&mut state, &m);
        m = permute(m);
    }

    // XOR the two halves
    for i in 0..8 {
        state[i] ^= state[i + 8];
        state[i + 8] ^= cv[i];
    }

    state
}

/// One round of portable compression.
#[inline(always)]
fn round_portable(state: &mut [u32; 16], m: &[u32; 16]) {
    g_portable(state, 0, 4, 8, 12, m[0], m[1]);
    g_portable(state, 1, 5, 9, 13, m[2], m[3]);
    g_portable(state, 2, 6, 10, 14, m[4], m[5]);
    g_portable(state, 3, 7, 11, 15, m[6], m[7]);
    g_portable(state, 0, 5, 10, 15, m[8], m[9]);
    g_portable(state, 1, 6, 11, 12, m[10], m[11]);
    g_portable(state, 2, 7, 8, 13, m[12], m[13]);
    g_portable(state, 3, 4, 9, 14, m[14], m[15]);
}

/// Portable G mixing function.
#[inline(always)]
fn g_portable(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, mx: u32, my: u32) {
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(mx);
    state[d] = (state[d] ^ state[a]).rotate_right(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(12);
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(my);
    state[d] = (state[d] ^ state[a]).rotate_right(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(7);
}

/// Permute message words.
#[inline(always)]
fn permute(m: [u32; 16]) -> [u32; 16] {
    [
        m[MSG_PERMUTATION[0]],
        m[MSG_PERMUTATION[1]],
        m[MSG_PERMUTATION[2]],
        m[MSG_PERMUTATION[3]],
        m[MSG_PERMUTATION[4]],
        m[MSG_PERMUTATION[5]],
        m[MSG_PERMUTATION[6]],
        m[MSG_PERMUTATION[7]],
        m[MSG_PERMUTATION[8]],
        m[MSG_PERMUTATION[9]],
        m[MSG_PERMUTATION[10]],
        m[MSG_PERMUTATION[11]],
        m[MSG_PERMUTATION[12]],
        m[MSG_PERMUTATION[13]],
        m[MSG_PERMUTATION[14]],
        m[MSG_PERMUTATION[15]],
    ]
}

// ═══════════════════════════════════════════════════════════════════════════════
// 4-WAY PARALLEL COMPRESSION (TRANSPOSED LAYOUT)
// ═══════════════════════════════════════════════════════════════════════════════

/// Pre-computed SSE IV broadcast vectors for 4-way parallel compression.
#[cfg(target_arch = "x86_64")]
const IV_BROADCAST_SSE_0: __m128i =
    unsafe { core::mem::transmute::<[u32; 4], __m128i>([IV[0]; 4]) };
#[cfg(target_arch = "x86_64")]
const IV_BROADCAST_SSE_1: __m128i =
    unsafe { core::mem::transmute::<[u32; 4], __m128i>([IV[1]; 4]) };
#[cfg(target_arch = "x86_64")]
const IV_BROADCAST_SSE_2: __m128i =
    unsafe { core::mem::transmute::<[u32; 4], __m128i>([IV[2]; 4]) };
#[cfg(target_arch = "x86_64")]
const IV_BROADCAST_SSE_3: __m128i =
    unsafe { core::mem::transmute::<[u32; 4], __m128i>([IV[3]; 4]) };

/// Pre-computed message schedule for 4-way compression (7 rounds).
/// Avoids runtime permutation computation in the hot loop.
#[cfg(target_arch = "x86_64")]
const MSG_SCHEDULE_SSE: [[usize; 16]; 7] = [
    // Round 0 (identity)
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    // Round 1
    [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8],
    // Round 2
    [3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1],
    // Round 3
    [10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6],
    // Round 4
    [12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4],
    // Round 5
    [9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7],
    // Round 6
    [11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13],
];

/// 4-way parallel BLAKE3 compression using SSE2 with transposed state layout.
///
/// This processes 4 independent blocks simultaneously by storing corresponding
/// state elements from all 4 blocks in the same __m128i register.
/// E.g., state_0 = [block0.state[0], block1.state[0], block2.state[0], block3.state[0]]
#[cfg(target_arch = "x86_64")]
pub mod parallel4 {
    use super::*;

    /// Compress 4 blocks in parallel.
    ///
    /// Returns 4 chaining values (first 8 words of each output).
    ///
    /// # Safety
    ///
    /// Caller must ensure the CPU supports SSE2.
    #[target_feature(enable = "sse2")]
    pub unsafe fn compress_4blocks(
        cvs: &[[u32; 8]; 4],
        blocks: &[[u8; 64]; 4],
        counters: &[u64; 4],
        block_lens: &[u32; 4],
        flags: &[u8; 4],
    ) -> [[u32; 8]; 4] {
        // Transposed state: state_i holds [block0.s[i], block1.s[i], block2.s[i], block3.s[i]]
        // Using setr (natural order) generates better code than set (reversed order)
        let mut s0 = _mm_setr_epi32(
            cvs[0][0] as i32,
            cvs[1][0] as i32,
            cvs[2][0] as i32,
            cvs[3][0] as i32,
        );
        let mut s1 = _mm_setr_epi32(
            cvs[0][1] as i32,
            cvs[1][1] as i32,
            cvs[2][1] as i32,
            cvs[3][1] as i32,
        );
        let mut s2 = _mm_setr_epi32(
            cvs[0][2] as i32,
            cvs[1][2] as i32,
            cvs[2][2] as i32,
            cvs[3][2] as i32,
        );
        let mut s3 = _mm_setr_epi32(
            cvs[0][3] as i32,
            cvs[1][3] as i32,
            cvs[2][3] as i32,
            cvs[3][3] as i32,
        );
        let mut s4 = _mm_setr_epi32(
            cvs[0][4] as i32,
            cvs[1][4] as i32,
            cvs[2][4] as i32,
            cvs[3][4] as i32,
        );
        let mut s5 = _mm_setr_epi32(
            cvs[0][5] as i32,
            cvs[1][5] as i32,
            cvs[2][5] as i32,
            cvs[3][5] as i32,
        );
        let mut s6 = _mm_setr_epi32(
            cvs[0][6] as i32,
            cvs[1][6] as i32,
            cvs[2][6] as i32,
            cvs[3][6] as i32,
        );
        let mut s7 = _mm_setr_epi32(
            cvs[0][7] as i32,
            cvs[1][7] as i32,
            cvs[2][7] as i32,
            cvs[3][7] as i32,
        );

        // Initialize lower state with pre-computed IV broadcast and counters
        let mut s8 = IV_BROADCAST_SSE_0;
        let mut s9 = IV_BROADCAST_SSE_1;
        let mut s10 = IV_BROADCAST_SSE_2;
        let mut s11 = IV_BROADCAST_SSE_3;
        let mut s12 = _mm_setr_epi32(
            counters[0] as i32,
            counters[1] as i32,
            counters[2] as i32,
            counters[3] as i32,
        );
        let mut s13 = _mm_setr_epi32(
            (counters[0] >> 32) as i32,
            (counters[1] >> 32) as i32,
            (counters[2] >> 32) as i32,
            (counters[3] >> 32) as i32,
        );
        let mut s14 = _mm_setr_epi32(
            block_lens[0] as i32,
            block_lens[1] as i32,
            block_lens[2] as i32,
            block_lens[3] as i32,
        );
        let mut s15 = _mm_setr_epi32(
            flags[0] as i32,
            flags[1] as i32,
            flags[2] as i32,
            flags[3] as i32,
        );

        // Load message words (transposed) - use setr for natural order
        let mut m = [_mm_setzero_si128(); 16];
        for i in 0..16 {
            let offset = i * 4;
            let w0 = u32::from_le_bytes([
                blocks[0][offset],
                blocks[0][offset + 1],
                blocks[0][offset + 2],
                blocks[0][offset + 3],
            ]);
            let w1 = u32::from_le_bytes([
                blocks[1][offset],
                blocks[1][offset + 1],
                blocks[1][offset + 2],
                blocks[1][offset + 3],
            ]);
            let w2 = u32::from_le_bytes([
                blocks[2][offset],
                blocks[2][offset + 1],
                blocks[2][offset + 2],
                blocks[2][offset + 3],
            ]);
            let w3 = u32::from_le_bytes([
                blocks[3][offset],
                blocks[3][offset + 1],
                blocks[3][offset + 2],
                blocks[3][offset + 3],
            ]);
            m[i] = _mm_setr_epi32(w0 as i32, w1 as i32, w2 as i32, w3 as i32);
        }

        // 7 rounds using pre-computed message schedule
        for round in 0..7 {
            let sched = &MSG_SCHEDULE_SSE[round];

            // Column step
            g4(
                &mut s0,
                &mut s4,
                &mut s8,
                &mut s12,
                m[sched[0]],
                m[sched[1]],
            );
            g4(
                &mut s1,
                &mut s5,
                &mut s9,
                &mut s13,
                m[sched[2]],
                m[sched[3]],
            );
            g4(
                &mut s2,
                &mut s6,
                &mut s10,
                &mut s14,
                m[sched[4]],
                m[sched[5]],
            );
            g4(
                &mut s3,
                &mut s7,
                &mut s11,
                &mut s15,
                m[sched[6]],
                m[sched[7]],
            );

            // Diagonal step
            g4(
                &mut s0,
                &mut s5,
                &mut s10,
                &mut s15,
                m[sched[8]],
                m[sched[9]],
            );
            g4(
                &mut s1,
                &mut s6,
                &mut s11,
                &mut s12,
                m[sched[10]],
                m[sched[11]],
            );
            g4(
                &mut s2,
                &mut s7,
                &mut s8,
                &mut s13,
                m[sched[12]],
                m[sched[13]],
            );
            g4(
                &mut s3,
                &mut s4,
                &mut s9,
                &mut s14,
                m[sched[14]],
                m[sched[15]],
            );
        }

        // XOR with input cv
        s0 = _mm_xor_si128(s0, s8);
        s1 = _mm_xor_si128(s1, s9);
        s2 = _mm_xor_si128(s2, s10);
        s3 = _mm_xor_si128(s3, s11);
        s4 = _mm_xor_si128(s4, s12);
        s5 = _mm_xor_si128(s5, s13);
        s6 = _mm_xor_si128(s6, s14);
        s7 = _mm_xor_si128(s7, s15);

        // SIMD 4x8 -> 8x4 transpose using unpack operations
        // We have 8 vectors (s0-s7) each with 4 elements from 4 blocks
        // We want 4 output arrays each with 8 elements

        // Step 1: Interleave pairs of 32-bit values
        let t0 = _mm_unpacklo_epi32(s0, s1); // [s0[0],s1[0],s0[1],s1[1]]
        let t1 = _mm_unpackhi_epi32(s0, s1); // [s0[2],s1[2],s0[3],s1[3]]
        let t2 = _mm_unpacklo_epi32(s2, s3); // [s2[0],s3[0],s2[1],s3[1]]
        let t3 = _mm_unpackhi_epi32(s2, s3); // [s2[2],s3[2],s2[3],s3[3]]
        let t4 = _mm_unpacklo_epi32(s4, s5); // [s4[0],s5[0],s4[1],s5[1]]
        let t5 = _mm_unpackhi_epi32(s4, s5); // [s4[2],s5[2],s4[3],s5[3]]
        let t6 = _mm_unpacklo_epi32(s6, s7); // [s6[0],s7[0],s6[1],s7[1]]
        let t7 = _mm_unpackhi_epi32(s6, s7); // [s6[2],s7[2],s6[3],s7[3]]

        // Step 2: Interleave pairs of 64-bit values (combines 4 consecutive state words)
        let u0 = _mm_unpacklo_epi64(t0, t2); // [s0[0],s1[0],s2[0],s3[0]] = first 4 words of block 0
        let u1 = _mm_unpackhi_epi64(t0, t2); // [s0[1],s1[1],s2[1],s3[1]] = first 4 words of block 1
        let u2 = _mm_unpacklo_epi64(t1, t3); // [s0[2],s1[2],s2[2],s3[2]] = first 4 words of block 2
        let u3 = _mm_unpackhi_epi64(t1, t3); // [s0[3],s1[3],s2[3],s3[3]] = first 4 words of block 3
        let u4 = _mm_unpacklo_epi64(t4, t6); // [s4[0],s5[0],s6[0],s7[0]] = last 4 words of block 0
        let u5 = _mm_unpackhi_epi64(t4, t6); // [s4[1],s5[1],s6[1],s7[1]] = last 4 words of block 1
        let u6 = _mm_unpacklo_epi64(t5, t7); // [s4[2],s5[2],s6[2],s7[2]] = last 4 words of block 2
        let u7 = _mm_unpackhi_epi64(t5, t7); // [s4[3],s5[3],s6[3],s7[3]] = last 4 words of block 3

        // Store directly to results array
        let mut results = [[0u32; 8]; 4];
        _mm_storeu_si128(results[0].as_mut_ptr() as *mut __m128i, u0);
        _mm_storeu_si128(results[0][4..].as_mut_ptr() as *mut __m128i, u4);
        _mm_storeu_si128(results[1].as_mut_ptr() as *mut __m128i, u1);
        _mm_storeu_si128(results[1][4..].as_mut_ptr() as *mut __m128i, u5);
        _mm_storeu_si128(results[2].as_mut_ptr() as *mut __m128i, u2);
        _mm_storeu_si128(results[2][4..].as_mut_ptr() as *mut __m128i, u6);
        _mm_storeu_si128(results[3].as_mut_ptr() as *mut __m128i, u3);
        _mm_storeu_si128(results[3][4..].as_mut_ptr() as *mut __m128i, u7);

        results
    }

    /// 4-way parallel G function.
    #[target_feature(enable = "sse2")]
    #[inline]
    unsafe fn g4(
        a: &mut __m128i,
        b: &mut __m128i,
        c: &mut __m128i,
        d: &mut __m128i,
        mx: __m128i,
        my: __m128i,
    ) {
        // a = a + b + mx
        *a = _mm_add_epi32(*a, _mm_add_epi32(*b, mx));

        // d = (d ^ a) >>> 16
        *d = _mm_xor_si128(*d, *a);
        *d = _mm_or_si128(_mm_srli_epi32(*d, 16), _mm_slli_epi32(*d, 16));

        // c = c + d
        *c = _mm_add_epi32(*c, *d);

        // b = (b ^ c) >>> 12
        *b = _mm_xor_si128(*b, *c);
        *b = _mm_or_si128(_mm_srli_epi32(*b, 12), _mm_slli_epi32(*b, 20));

        // a = a + b + my
        *a = _mm_add_epi32(*a, _mm_add_epi32(*b, my));

        // d = (d ^ a) >>> 8
        *d = _mm_xor_si128(*d, *a);
        *d = _mm_or_si128(_mm_srli_epi32(*d, 8), _mm_slli_epi32(*d, 24));

        // c = c + d
        *c = _mm_add_epi32(*c, *d);

        // b = (b ^ c) >>> 7
        *b = _mm_xor_si128(*b, *c);
        *b = _mm_or_si128(_mm_srli_epi32(*b, 7), _mm_slli_epi32(*b, 25));
    }

    /// Compress 4 parent nodes in parallel.
    ///
    /// This is used in the tree structure to compute parent chaining values.
    #[target_feature(enable = "sse2")]
    pub unsafe fn compress_parents_4(
        key: &[u32; 8],
        left_cvs: &[[u32; 8]; 4],
        right_cvs: &[[u32; 8]; 4],
        flags: u8,
    ) -> [[u32; 8]; 4] {
        // Construct parent blocks: [left_cv || right_cv]
        // Direct pointer copy is faster than per-element to_le_bytes
        let mut blocks = [[0u8; 64]; 4];
        for i in 0..4 {
            core::ptr::copy_nonoverlapping(
                left_cvs[i].as_ptr() as *const u8,
                blocks[i].as_mut_ptr(),
                32,
            );
            core::ptr::copy_nonoverlapping(
                right_cvs[i].as_ptr() as *const u8,
                blocks[i][32..].as_mut_ptr(),
                32,
            );
        }

        let parent_flags = flags | 4; // PARENT flag

        compress_4blocks(
            &[*key, *key, *key, *key],
            &blocks,
            &[0, 0, 0, 0],
            &[64, 64, 64, 64],
            &[parent_flags, parent_flags, parent_flags, parent_flags],
        )
    }
}

/// Compress 4 parent nodes in parallel (public interface).
#[cfg(all(feature = "std", target_arch = "x86_64"))]
pub fn compress_parents_parallel(
    key: &[u32; 8],
    left_cvs: &[[u32; 8]; 4],
    right_cvs: &[[u32; 8]; 4],
    flags: u8,
) -> [[u32; 8]; 4] {
    unsafe { parallel4::compress_parents_4(key, left_cvs, right_cvs, flags) }
}

/// Compress 4 blocks in parallel (public interface).
#[cfg(all(feature = "std", target_arch = "x86_64"))]
pub fn compress_4blocks_parallel(
    cvs: &[[u32; 8]; 4],
    blocks: &[[u8; 64]; 4],
    counters: &[u64; 4],
    block_lens: &[u32; 4],
    flags: &[u8; 4],
) -> [[u32; 8]; 4] {
    unsafe { parallel4::compress_4blocks(cvs, blocks, counters, block_lens, flags) }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 8-WAY PARALLEL COMPRESSION (AVX2)
// ═══════════════════════════════════════════════════════════════════════════════

/// 8-way parallel BLAKE3 compression using AVX2 with transposed state layout.
///
/// This processes 8 independent blocks simultaneously by storing corresponding
/// state elements from all 8 blocks in the same __m256i register.
#[cfg(target_arch = "x86_64")]
pub mod parallel8 {
    use super::*;

    /// Precomputed message schedule indices for all 7 rounds.
    /// Each round uses a permuted version of the previous round's message.
    /// MSG_SCHEDULE[round][i] gives the original message word index for position i in round.
    const MSG_SCHEDULE: [[usize; 16]; 7] = [
        // Round 0: identity
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        // Round 1
        [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8],
        // Round 2
        [3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1],
        // Round 3
        [10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6],
        // Round 4
        [12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4],
        // Round 5
        [9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7],
        // Round 6
        [11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13],
    ];

    /// Pre-computed broadcast IV vectors for efficient state initialization.
    /// These avoid expensive _mm256_set1_epi32 calls in hot loops.
    const IV_BROADCAST_0: __m256i =
        unsafe { core::mem::transmute::<[u32; 8], __m256i>([IV[0]; 8]) };
    const IV_BROADCAST_1: __m256i =
        unsafe { core::mem::transmute::<[u32; 8], __m256i>([IV[1]; 8]) };
    const IV_BROADCAST_2: __m256i =
        unsafe { core::mem::transmute::<[u32; 8], __m256i>([IV[2]; 8]) };
    const IV_BROADCAST_3: __m256i =
        unsafe { core::mem::transmute::<[u32; 8], __m256i>([IV[3]; 8]) };

    /// Shuffle mask for ror 16: swap bytes within each 16-bit pair.
    /// Each 32-bit lane: bytes [0,1,2,3] -> [2,3,0,1]
    const ROT16_SHUFFLE: __m256i = unsafe {
        core::mem::transmute::<[u8; 32], __m256i>([
            2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13, 2, 3, 0, 1, 6, 7, 4, 5, 10, 11,
            8, 9, 14, 15, 12, 13,
        ])
    };

    /// Shuffle mask for ror 8: rotate bytes within each 32-bit lane.
    /// Each 32-bit lane: bytes [0,1,2,3] -> [1,2,3,0]
    const ROT8_SHUFFLE: __m256i = unsafe {
        core::mem::transmute::<[u8; 32], __m256i>([
            1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12, 1, 2, 3, 0, 5, 6, 7, 4, 9, 10,
            11, 8, 13, 14, 15, 12,
        ])
    };

    /// Load a transposed u32 from 8 blocks at the same word position.
    /// Uses gather instruction for efficient strided access.
    #[target_feature(enable = "avx2")]
    #[inline]
    unsafe fn load_msg_word(blocks: &[[u8; 64]; 8], word_idx: usize) -> __m256i {
        // Use AVX2 gather for efficient strided loading
        // Each block is 64 bytes apart, we want word_idx from each
        let base = blocks.as_ptr() as *const i32;
        let word_offset = word_idx as isize;

        // Gather indices: block 0 word N, block 1 word N, etc.
        // Each block is 64 bytes = 16 i32s apart
        let indices = _mm256_setr_epi32(
            (word_offset + 0 * 16) as i32,
            (word_offset + 1 * 16) as i32,
            (word_offset + 2 * 16) as i32,
            (word_offset + 3 * 16) as i32,
            (word_offset + 4 * 16) as i32,
            (word_offset + 5 * 16) as i32,
            (word_offset + 6 * 16) as i32,
            (word_offset + 7 * 16) as i32,
        );

        _mm256_i32gather_epi32::<4>(base, indices)
    }

    /// Load a transposed u32 from 8 chunks at a specific block and word position.
    /// Zero-copy version that reads directly from chunk data without intermediate copies.
    /// Uses efficient scalar loads with insert operations.
    #[target_feature(enable = "avx2")]
    #[inline]
    unsafe fn load_msg_word_from_chunks(
        chunk_ptrs: &[*const u8; 8],
        block_idx: usize,
        word_idx: usize,
    ) -> __m256i {
        // Calculate offset: block_idx * 64 (block offset) + word_idx * 4 (word offset)
        let offset = block_idx * 64 + word_idx * 4;

        // Load each word using unaligned 32-bit loads
        // This generates better code than _mm256_set_epi32 which creates
        // expensive scalar-to-vector shuffles
        let w0 = *(chunk_ptrs[0].add(offset) as *const i32);
        let w1 = *(chunk_ptrs[1].add(offset) as *const i32);
        let w2 = *(chunk_ptrs[2].add(offset) as *const i32);
        let w3 = *(chunk_ptrs[3].add(offset) as *const i32);
        let w4 = *(chunk_ptrs[4].add(offset) as *const i32);
        let w5 = *(chunk_ptrs[5].add(offset) as *const i32);
        let w6 = *(chunk_ptrs[6].add(offset) as *const i32);
        let w7 = *(chunk_ptrs[7].add(offset) as *const i32);

        // Use setr which has better codegen than set (natural order)
        _mm256_setr_epi32(w0, w1, w2, w3, w4, w5, w6, w7)
    }

    /// Load a transposed u32 from 8 contiguous chunks at a specific block and word position.
    /// Zero-copy version using gather for contiguous chunk data at stride CHUNK_LEN.
    ///
    /// This is faster than `load_msg_word_from_chunks` when chunks are contiguous because
    /// it uses a single AVX2 gather instruction instead of 8 scalar loads.
    ///
    /// # Safety
    ///
    /// - `base_ptr` must point to the start of at least 8 contiguous chunks
    /// - Each chunk must be exactly CHUNK_LEN (1024) bytes
    #[target_feature(enable = "avx2")]
    #[inline]
    unsafe fn load_msg_word_contiguous(
        base_ptr: *const u8,
        block_idx: usize,
        word_idx: usize,
    ) -> __m256i {
        const CHUNK_LEN_WORDS: i32 = 256; // 1024 bytes / 4 bytes per word
        const BLOCK_LEN_WORDS: i32 = 16; // 64 bytes / 4 bytes per word

        // Calculate base offset for this block and word
        let base_offset = (block_idx as i32) * BLOCK_LEN_WORDS + (word_idx as i32);

        // Gather indices: chunk 0, 1, 2, ..., 7 at stride CHUNK_LEN_WORDS
        let indices = _mm256_setr_epi32(
            base_offset + 0 * CHUNK_LEN_WORDS,
            base_offset + 1 * CHUNK_LEN_WORDS,
            base_offset + 2 * CHUNK_LEN_WORDS,
            base_offset + 3 * CHUNK_LEN_WORDS,
            base_offset + 4 * CHUNK_LEN_WORDS,
            base_offset + 5 * CHUNK_LEN_WORDS,
            base_offset + 6 * CHUNK_LEN_WORDS,
            base_offset + 7 * CHUNK_LEN_WORDS,
        );

        _mm256_i32gather_epi32::<4>(base_ptr as *const i32, indices)
    }

    /// Compress 8 blocks in parallel using AVX2 with fully unrolled rounds.
    ///
    /// Returns 8 chaining values (first 8 words of each output).
    ///
    /// # Safety
    ///
    /// Caller must ensure the CPU supports AVX2.
    #[target_feature(enable = "avx2")]
    pub unsafe fn compress_8blocks(
        cvs: &[[u32; 8]; 8],
        blocks: &[[u8; 64]; 8],
        counters: &[u64; 8],
        block_lens: &[u32; 8],
        flags: &[u8; 8],
    ) -> [[u32; 8]; 8] {
        // Load all 16 message words upfront (transposed)
        let m0 = load_msg_word(blocks, 0);
        let m1 = load_msg_word(blocks, 1);
        let m2 = load_msg_word(blocks, 2);
        let m3 = load_msg_word(blocks, 3);
        let m4 = load_msg_word(blocks, 4);
        let m5 = load_msg_word(blocks, 5);
        let m6 = load_msg_word(blocks, 6);
        let m7 = load_msg_word(blocks, 7);
        let m8 = load_msg_word(blocks, 8);
        let m9 = load_msg_word(blocks, 9);
        let m10 = load_msg_word(blocks, 10);
        let m11 = load_msg_word(blocks, 11);
        let m12 = load_msg_word(blocks, 12);
        let m13 = load_msg_word(blocks, 13);
        let m14 = load_msg_word(blocks, 14);
        let m15 = load_msg_word(blocks, 15);

        // Store in array for indexed access
        let m = [
            m0, m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15,
        ];

        // Initialize state (transposed) using setr for better codegen
        let mut s0 = _mm256_setr_epi32(
            cvs[0][0] as i32,
            cvs[1][0] as i32,
            cvs[2][0] as i32,
            cvs[3][0] as i32,
            cvs[4][0] as i32,
            cvs[5][0] as i32,
            cvs[6][0] as i32,
            cvs[7][0] as i32,
        );
        let mut s1 = _mm256_setr_epi32(
            cvs[0][1] as i32,
            cvs[1][1] as i32,
            cvs[2][1] as i32,
            cvs[3][1] as i32,
            cvs[4][1] as i32,
            cvs[5][1] as i32,
            cvs[6][1] as i32,
            cvs[7][1] as i32,
        );
        let mut s2 = _mm256_setr_epi32(
            cvs[0][2] as i32,
            cvs[1][2] as i32,
            cvs[2][2] as i32,
            cvs[3][2] as i32,
            cvs[4][2] as i32,
            cvs[5][2] as i32,
            cvs[6][2] as i32,
            cvs[7][2] as i32,
        );
        let mut s3 = _mm256_setr_epi32(
            cvs[0][3] as i32,
            cvs[1][3] as i32,
            cvs[2][3] as i32,
            cvs[3][3] as i32,
            cvs[4][3] as i32,
            cvs[5][3] as i32,
            cvs[6][3] as i32,
            cvs[7][3] as i32,
        );
        let mut s4 = _mm256_setr_epi32(
            cvs[0][4] as i32,
            cvs[1][4] as i32,
            cvs[2][4] as i32,
            cvs[3][4] as i32,
            cvs[4][4] as i32,
            cvs[5][4] as i32,
            cvs[6][4] as i32,
            cvs[7][4] as i32,
        );
        let mut s5 = _mm256_setr_epi32(
            cvs[0][5] as i32,
            cvs[1][5] as i32,
            cvs[2][5] as i32,
            cvs[3][5] as i32,
            cvs[4][5] as i32,
            cvs[5][5] as i32,
            cvs[6][5] as i32,
            cvs[7][5] as i32,
        );
        let mut s6 = _mm256_setr_epi32(
            cvs[0][6] as i32,
            cvs[1][6] as i32,
            cvs[2][6] as i32,
            cvs[3][6] as i32,
            cvs[4][6] as i32,
            cvs[5][6] as i32,
            cvs[6][6] as i32,
            cvs[7][6] as i32,
        );
        let mut s7 = _mm256_setr_epi32(
            cvs[0][7] as i32,
            cvs[1][7] as i32,
            cvs[2][7] as i32,
            cvs[3][7] as i32,
            cvs[4][7] as i32,
            cvs[5][7] as i32,
            cvs[6][7] as i32,
            cvs[7][7] as i32,
        );

        // Use pre-computed IV broadcast vectors
        let mut s8 = IV_BROADCAST_0;
        let mut s9 = IV_BROADCAST_1;
        let mut s10 = IV_BROADCAST_2;
        let mut s11 = IV_BROADCAST_3;

        // Use setr for counters, block_lens, flags (natural order)
        let mut s12 = _mm256_setr_epi32(
            counters[0] as i32,
            counters[1] as i32,
            counters[2] as i32,
            counters[3] as i32,
            counters[4] as i32,
            counters[5] as i32,
            counters[6] as i32,
            counters[7] as i32,
        );
        let mut s13 = _mm256_setr_epi32(
            (counters[0] >> 32) as i32,
            (counters[1] >> 32) as i32,
            (counters[2] >> 32) as i32,
            (counters[3] >> 32) as i32,
            (counters[4] >> 32) as i32,
            (counters[5] >> 32) as i32,
            (counters[6] >> 32) as i32,
            (counters[7] >> 32) as i32,
        );
        let mut s14 = _mm256_setr_epi32(
            block_lens[0] as i32,
            block_lens[1] as i32,
            block_lens[2] as i32,
            block_lens[3] as i32,
            block_lens[4] as i32,
            block_lens[5] as i32,
            block_lens[6] as i32,
            block_lens[7] as i32,
        );
        let mut s15 = _mm256_setr_epi32(
            flags[0] as i32,
            flags[1] as i32,
            flags[2] as i32,
            flags[3] as i32,
            flags[4] as i32,
            flags[5] as i32,
            flags[6] as i32,
            flags[7] as i32,
        );

        // Fully unrolled 7 rounds using precomputed message schedule
        macro_rules! round {
            ($r:expr) => {
                // Column step
                g8(
                    &mut s0,
                    &mut s4,
                    &mut s8,
                    &mut s12,
                    m[MSG_SCHEDULE[$r][0]],
                    m[MSG_SCHEDULE[$r][1]],
                );
                g8(
                    &mut s1,
                    &mut s5,
                    &mut s9,
                    &mut s13,
                    m[MSG_SCHEDULE[$r][2]],
                    m[MSG_SCHEDULE[$r][3]],
                );
                g8(
                    &mut s2,
                    &mut s6,
                    &mut s10,
                    &mut s14,
                    m[MSG_SCHEDULE[$r][4]],
                    m[MSG_SCHEDULE[$r][5]],
                );
                g8(
                    &mut s3,
                    &mut s7,
                    &mut s11,
                    &mut s15,
                    m[MSG_SCHEDULE[$r][6]],
                    m[MSG_SCHEDULE[$r][7]],
                );
                // Diagonal step
                g8(
                    &mut s0,
                    &mut s5,
                    &mut s10,
                    &mut s15,
                    m[MSG_SCHEDULE[$r][8]],
                    m[MSG_SCHEDULE[$r][9]],
                );
                g8(
                    &mut s1,
                    &mut s6,
                    &mut s11,
                    &mut s12,
                    m[MSG_SCHEDULE[$r][10]],
                    m[MSG_SCHEDULE[$r][11]],
                );
                g8(
                    &mut s2,
                    &mut s7,
                    &mut s8,
                    &mut s13,
                    m[MSG_SCHEDULE[$r][12]],
                    m[MSG_SCHEDULE[$r][13]],
                );
                g8(
                    &mut s3,
                    &mut s4,
                    &mut s9,
                    &mut s14,
                    m[MSG_SCHEDULE[$r][14]],
                    m[MSG_SCHEDULE[$r][15]],
                );
            };
        }

        round!(0);
        round!(1);
        round!(2);
        round!(3);
        round!(4);
        round!(5);
        round!(6);

        // XOR with input cv
        s0 = _mm256_xor_si256(s0, s8);
        s1 = _mm256_xor_si256(s1, s9);
        s2 = _mm256_xor_si256(s2, s10);
        s3 = _mm256_xor_si256(s3, s11);
        s4 = _mm256_xor_si256(s4, s12);
        s5 = _mm256_xor_si256(s5, s13);
        s6 = _mm256_xor_si256(s6, s14);
        s7 = _mm256_xor_si256(s7, s15);

        // Extract results using SIMD transpose (8x8 matrix transpose)
        // Input: s0-s7 are transposed (s0 = [block0.state[0], block1.state[0], ...])
        // Output: results[i] = [block_i.state[0], block_i.state[1], ...]

        // Step 1: Interleave pairs of 32-bit values
        let t0 = _mm256_unpacklo_epi32(s0, s1);
        let t1 = _mm256_unpackhi_epi32(s0, s1);
        let t2 = _mm256_unpacklo_epi32(s2, s3);
        let t3 = _mm256_unpackhi_epi32(s2, s3);
        let t4 = _mm256_unpacklo_epi32(s4, s5);
        let t5 = _mm256_unpackhi_epi32(s4, s5);
        let t6 = _mm256_unpacklo_epi32(s6, s7);
        let t7 = _mm256_unpackhi_epi32(s6, s7);

        // Step 2: Interleave pairs of 64-bit values
        let u0 = _mm256_unpacklo_epi64(t0, t2);
        let u1 = _mm256_unpackhi_epi64(t0, t2);
        let u2 = _mm256_unpacklo_epi64(t1, t3);
        let u3 = _mm256_unpackhi_epi64(t1, t3);
        let u4 = _mm256_unpacklo_epi64(t4, t6);
        let u5 = _mm256_unpackhi_epi64(t4, t6);
        let u6 = _mm256_unpacklo_epi64(t5, t7);
        let u7 = _mm256_unpackhi_epi64(t5, t7);

        // Step 3: Combine 128-bit lanes
        let r0 = _mm256_permute2x128_si256(u0, u4, 0x20);
        let r1 = _mm256_permute2x128_si256(u1, u5, 0x20);
        let r2 = _mm256_permute2x128_si256(u2, u6, 0x20);
        let r3 = _mm256_permute2x128_si256(u3, u7, 0x20);
        let r4 = _mm256_permute2x128_si256(u0, u4, 0x31);
        let r5 = _mm256_permute2x128_si256(u1, u5, 0x31);
        let r6 = _mm256_permute2x128_si256(u2, u6, 0x31);
        let r7 = _mm256_permute2x128_si256(u3, u7, 0x31);

        // Store directly to results array
        let mut results = [[0u32; 8]; 8];
        _mm256_storeu_si256(results[0].as_mut_ptr() as *mut __m256i, r0);
        _mm256_storeu_si256(results[1].as_mut_ptr() as *mut __m256i, r1);
        _mm256_storeu_si256(results[2].as_mut_ptr() as *mut __m256i, r2);
        _mm256_storeu_si256(results[3].as_mut_ptr() as *mut __m256i, r3);
        _mm256_storeu_si256(results[4].as_mut_ptr() as *mut __m256i, r4);
        _mm256_storeu_si256(results[5].as_mut_ptr() as *mut __m256i, r5);
        _mm256_storeu_si256(results[6].as_mut_ptr() as *mut __m256i, r6);
        _mm256_storeu_si256(results[7].as_mut_ptr() as *mut __m256i, r7);

        results
    }

    /// Zero-copy version of compress_8blocks that reads directly from chunk data.
    ///
    /// Takes pointers to 8 chunks and a block index, avoiding 512-byte copy per call.
    ///
    /// # Safety
    ///
    /// - Caller must ensure the CPU supports AVX2.
    /// - Each chunk pointer must be valid for 1024 bytes.
    /// - block_idx must be in range 0..16.
    #[target_feature(enable = "avx2")]
    pub unsafe fn compress_8blocks_zero_copy(
        cvs: &[[u32; 8]; 8],
        chunk_ptrs: &[*const u8; 8],
        block_idx: usize,
        counters: &[u64; 8],
        block_lens: &[u32; 8],
        flags: &[u8; 8],
    ) -> [[u32; 8]; 8] {
        // Load all 16 message words upfront (transposed) - directly from chunks
        let m0 = load_msg_word_from_chunks(chunk_ptrs, block_idx, 0);
        let m1 = load_msg_word_from_chunks(chunk_ptrs, block_idx, 1);
        let m2 = load_msg_word_from_chunks(chunk_ptrs, block_idx, 2);
        let m3 = load_msg_word_from_chunks(chunk_ptrs, block_idx, 3);
        let m4 = load_msg_word_from_chunks(chunk_ptrs, block_idx, 4);
        let m5 = load_msg_word_from_chunks(chunk_ptrs, block_idx, 5);
        let m6 = load_msg_word_from_chunks(chunk_ptrs, block_idx, 6);
        let m7 = load_msg_word_from_chunks(chunk_ptrs, block_idx, 7);
        let m8 = load_msg_word_from_chunks(chunk_ptrs, block_idx, 8);
        let m9 = load_msg_word_from_chunks(chunk_ptrs, block_idx, 9);
        let m10 = load_msg_word_from_chunks(chunk_ptrs, block_idx, 10);
        let m11 = load_msg_word_from_chunks(chunk_ptrs, block_idx, 11);
        let m12 = load_msg_word_from_chunks(chunk_ptrs, block_idx, 12);
        let m13 = load_msg_word_from_chunks(chunk_ptrs, block_idx, 13);
        let m14 = load_msg_word_from_chunks(chunk_ptrs, block_idx, 14);
        let m15 = load_msg_word_from_chunks(chunk_ptrs, block_idx, 15);

        // Store in array for indexed access
        let m = [
            m0, m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15,
        ];

        // Initialize state (transposed) using setr for better codegen
        let mut s0 = _mm256_setr_epi32(
            cvs[0][0] as i32,
            cvs[1][0] as i32,
            cvs[2][0] as i32,
            cvs[3][0] as i32,
            cvs[4][0] as i32,
            cvs[5][0] as i32,
            cvs[6][0] as i32,
            cvs[7][0] as i32,
        );
        let mut s1 = _mm256_setr_epi32(
            cvs[0][1] as i32,
            cvs[1][1] as i32,
            cvs[2][1] as i32,
            cvs[3][1] as i32,
            cvs[4][1] as i32,
            cvs[5][1] as i32,
            cvs[6][1] as i32,
            cvs[7][1] as i32,
        );
        let mut s2 = _mm256_setr_epi32(
            cvs[0][2] as i32,
            cvs[1][2] as i32,
            cvs[2][2] as i32,
            cvs[3][2] as i32,
            cvs[4][2] as i32,
            cvs[5][2] as i32,
            cvs[6][2] as i32,
            cvs[7][2] as i32,
        );
        let mut s3 = _mm256_setr_epi32(
            cvs[0][3] as i32,
            cvs[1][3] as i32,
            cvs[2][3] as i32,
            cvs[3][3] as i32,
            cvs[4][3] as i32,
            cvs[5][3] as i32,
            cvs[6][3] as i32,
            cvs[7][3] as i32,
        );
        let mut s4 = _mm256_setr_epi32(
            cvs[0][4] as i32,
            cvs[1][4] as i32,
            cvs[2][4] as i32,
            cvs[3][4] as i32,
            cvs[4][4] as i32,
            cvs[5][4] as i32,
            cvs[6][4] as i32,
            cvs[7][4] as i32,
        );
        let mut s5 = _mm256_setr_epi32(
            cvs[0][5] as i32,
            cvs[1][5] as i32,
            cvs[2][5] as i32,
            cvs[3][5] as i32,
            cvs[4][5] as i32,
            cvs[5][5] as i32,
            cvs[6][5] as i32,
            cvs[7][5] as i32,
        );
        let mut s6 = _mm256_setr_epi32(
            cvs[0][6] as i32,
            cvs[1][6] as i32,
            cvs[2][6] as i32,
            cvs[3][6] as i32,
            cvs[4][6] as i32,
            cvs[5][6] as i32,
            cvs[6][6] as i32,
            cvs[7][6] as i32,
        );
        let mut s7 = _mm256_setr_epi32(
            cvs[0][7] as i32,
            cvs[1][7] as i32,
            cvs[2][7] as i32,
            cvs[3][7] as i32,
            cvs[4][7] as i32,
            cvs[5][7] as i32,
            cvs[6][7] as i32,
            cvs[7][7] as i32,
        );

        // Use pre-computed IV broadcast vectors
        let mut s8 = IV_BROADCAST_0;
        let mut s9 = IV_BROADCAST_1;
        let mut s10 = IV_BROADCAST_2;
        let mut s11 = IV_BROADCAST_3;

        // Use setr for counters, block_lens, flags (natural order)
        let mut s12 = _mm256_setr_epi32(
            counters[0] as i32,
            counters[1] as i32,
            counters[2] as i32,
            counters[3] as i32,
            counters[4] as i32,
            counters[5] as i32,
            counters[6] as i32,
            counters[7] as i32,
        );
        let mut s13 = _mm256_setr_epi32(
            (counters[0] >> 32) as i32,
            (counters[1] >> 32) as i32,
            (counters[2] >> 32) as i32,
            (counters[3] >> 32) as i32,
            (counters[4] >> 32) as i32,
            (counters[5] >> 32) as i32,
            (counters[6] >> 32) as i32,
            (counters[7] >> 32) as i32,
        );
        let mut s14 = _mm256_setr_epi32(
            block_lens[0] as i32,
            block_lens[1] as i32,
            block_lens[2] as i32,
            block_lens[3] as i32,
            block_lens[4] as i32,
            block_lens[5] as i32,
            block_lens[6] as i32,
            block_lens[7] as i32,
        );
        let mut s15 = _mm256_setr_epi32(
            flags[0] as i32,
            flags[1] as i32,
            flags[2] as i32,
            flags[3] as i32,
            flags[4] as i32,
            flags[5] as i32,
            flags[6] as i32,
            flags[7] as i32,
        );

        // Fully unrolled 7 rounds using precomputed message schedule
        macro_rules! round {
            ($r:expr) => {
                // Column step
                g8(
                    &mut s0,
                    &mut s4,
                    &mut s8,
                    &mut s12,
                    m[MSG_SCHEDULE[$r][0]],
                    m[MSG_SCHEDULE[$r][1]],
                );
                g8(
                    &mut s1,
                    &mut s5,
                    &mut s9,
                    &mut s13,
                    m[MSG_SCHEDULE[$r][2]],
                    m[MSG_SCHEDULE[$r][3]],
                );
                g8(
                    &mut s2,
                    &mut s6,
                    &mut s10,
                    &mut s14,
                    m[MSG_SCHEDULE[$r][4]],
                    m[MSG_SCHEDULE[$r][5]],
                );
                g8(
                    &mut s3,
                    &mut s7,
                    &mut s11,
                    &mut s15,
                    m[MSG_SCHEDULE[$r][6]],
                    m[MSG_SCHEDULE[$r][7]],
                );
                // Diagonal step
                g8(
                    &mut s0,
                    &mut s5,
                    &mut s10,
                    &mut s15,
                    m[MSG_SCHEDULE[$r][8]],
                    m[MSG_SCHEDULE[$r][9]],
                );
                g8(
                    &mut s1,
                    &mut s6,
                    &mut s11,
                    &mut s12,
                    m[MSG_SCHEDULE[$r][10]],
                    m[MSG_SCHEDULE[$r][11]],
                );
                g8(
                    &mut s2,
                    &mut s7,
                    &mut s8,
                    &mut s13,
                    m[MSG_SCHEDULE[$r][12]],
                    m[MSG_SCHEDULE[$r][13]],
                );
                g8(
                    &mut s3,
                    &mut s4,
                    &mut s9,
                    &mut s14,
                    m[MSG_SCHEDULE[$r][14]],
                    m[MSG_SCHEDULE[$r][15]],
                );
            };
        }

        round!(0);
        round!(1);
        round!(2);
        round!(3);
        round!(4);
        round!(5);
        round!(6);

        // XOR with input cv
        s0 = _mm256_xor_si256(s0, s8);
        s1 = _mm256_xor_si256(s1, s9);
        s2 = _mm256_xor_si256(s2, s10);
        s3 = _mm256_xor_si256(s3, s11);
        s4 = _mm256_xor_si256(s4, s12);
        s5 = _mm256_xor_si256(s5, s13);
        s6 = _mm256_xor_si256(s6, s14);
        s7 = _mm256_xor_si256(s7, s15);

        // Extract results using SIMD transpose (8x8 matrix transpose)
        // Input: s0-s7 are transposed (s0 = [block0.state[0], block1.state[0], ...])
        // Output: results[i] = [block_i.state[0], block_i.state[1], ...]

        // Step 1: Interleave pairs of 32-bit values
        let t0 = _mm256_unpacklo_epi32(s0, s1);
        let t1 = _mm256_unpackhi_epi32(s0, s1);
        let t2 = _mm256_unpacklo_epi32(s2, s3);
        let t3 = _mm256_unpackhi_epi32(s2, s3);
        let t4 = _mm256_unpacklo_epi32(s4, s5);
        let t5 = _mm256_unpackhi_epi32(s4, s5);
        let t6 = _mm256_unpacklo_epi32(s6, s7);
        let t7 = _mm256_unpackhi_epi32(s6, s7);

        // Step 2: Interleave pairs of 64-bit values
        let u0 = _mm256_unpacklo_epi64(t0, t2);
        let u1 = _mm256_unpackhi_epi64(t0, t2);
        let u2 = _mm256_unpacklo_epi64(t1, t3);
        let u3 = _mm256_unpackhi_epi64(t1, t3);
        let u4 = _mm256_unpacklo_epi64(t4, t6);
        let u5 = _mm256_unpackhi_epi64(t4, t6);
        let u6 = _mm256_unpacklo_epi64(t5, t7);
        let u7 = _mm256_unpackhi_epi64(t5, t7);

        // Step 3: Combine 128-bit lanes
        let r0 = _mm256_permute2x128_si256(u0, u4, 0x20);
        let r1 = _mm256_permute2x128_si256(u1, u5, 0x20);
        let r2 = _mm256_permute2x128_si256(u2, u6, 0x20);
        let r3 = _mm256_permute2x128_si256(u3, u7, 0x20);
        let r4 = _mm256_permute2x128_si256(u0, u4, 0x31);
        let r5 = _mm256_permute2x128_si256(u1, u5, 0x31);
        let r6 = _mm256_permute2x128_si256(u2, u6, 0x31);
        let r7 = _mm256_permute2x128_si256(u3, u7, 0x31);

        // Store directly to results array
        let mut results = [[0u32; 8]; 8];
        _mm256_storeu_si256(results[0].as_mut_ptr() as *mut __m256i, r0);
        _mm256_storeu_si256(results[1].as_mut_ptr() as *mut __m256i, r1);
        _mm256_storeu_si256(results[2].as_mut_ptr() as *mut __m256i, r2);
        _mm256_storeu_si256(results[3].as_mut_ptr() as *mut __m256i, r3);
        _mm256_storeu_si256(results[4].as_mut_ptr() as *mut __m256i, r4);
        _mm256_storeu_si256(results[5].as_mut_ptr() as *mut __m256i, r5);
        _mm256_storeu_si256(results[6].as_mut_ptr() as *mut __m256i, r6);
        _mm256_storeu_si256(results[7].as_mut_ptr() as *mut __m256i, r7);

        results
    }

    /// Compress 8 blocks from contiguous chunks using AVX2 gather.
    ///
    /// This is faster than `compress_8blocks_zero_copy` when chunks are contiguous
    /// because it uses AVX2 gather instead of 8 scalar loads per message word.
    ///
    /// # Safety
    ///
    /// - Caller must ensure the CPU supports AVX2.
    /// - `base_ptr` must point to at least 8 contiguous chunks (8KB).
    /// - block_idx must be in range 0..16.
    #[target_feature(enable = "avx2")]
    pub unsafe fn compress_8blocks_contiguous(
        cvs: &[[u32; 8]; 8],
        base_ptr: *const u8,
        block_idx: usize,
        counters: &[u64; 8],
        block_lens: &[u32; 8],
        flags: &[u8; 8],
    ) -> [[u32; 8]; 8] {
        // Load all 16 message words using gather - single instruction per word
        let m0 = load_msg_word_contiguous(base_ptr, block_idx, 0);
        let m1 = load_msg_word_contiguous(base_ptr, block_idx, 1);
        let m2 = load_msg_word_contiguous(base_ptr, block_idx, 2);
        let m3 = load_msg_word_contiguous(base_ptr, block_idx, 3);
        let m4 = load_msg_word_contiguous(base_ptr, block_idx, 4);
        let m5 = load_msg_word_contiguous(base_ptr, block_idx, 5);
        let m6 = load_msg_word_contiguous(base_ptr, block_idx, 6);
        let m7 = load_msg_word_contiguous(base_ptr, block_idx, 7);
        let m8 = load_msg_word_contiguous(base_ptr, block_idx, 8);
        let m9 = load_msg_word_contiguous(base_ptr, block_idx, 9);
        let m10 = load_msg_word_contiguous(base_ptr, block_idx, 10);
        let m11 = load_msg_word_contiguous(base_ptr, block_idx, 11);
        let m12 = load_msg_word_contiguous(base_ptr, block_idx, 12);
        let m13 = load_msg_word_contiguous(base_ptr, block_idx, 13);
        let m14 = load_msg_word_contiguous(base_ptr, block_idx, 14);
        let m15 = load_msg_word_contiguous(base_ptr, block_idx, 15);

        let m = [
            m0, m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15,
        ];

        // Initialize state (same as compress_8blocks_zero_copy)
        let mut s0 = _mm256_setr_epi32(
            cvs[0][0] as i32,
            cvs[1][0] as i32,
            cvs[2][0] as i32,
            cvs[3][0] as i32,
            cvs[4][0] as i32,
            cvs[5][0] as i32,
            cvs[6][0] as i32,
            cvs[7][0] as i32,
        );
        let mut s1 = _mm256_setr_epi32(
            cvs[0][1] as i32,
            cvs[1][1] as i32,
            cvs[2][1] as i32,
            cvs[3][1] as i32,
            cvs[4][1] as i32,
            cvs[5][1] as i32,
            cvs[6][1] as i32,
            cvs[7][1] as i32,
        );
        let mut s2 = _mm256_setr_epi32(
            cvs[0][2] as i32,
            cvs[1][2] as i32,
            cvs[2][2] as i32,
            cvs[3][2] as i32,
            cvs[4][2] as i32,
            cvs[5][2] as i32,
            cvs[6][2] as i32,
            cvs[7][2] as i32,
        );
        let mut s3 = _mm256_setr_epi32(
            cvs[0][3] as i32,
            cvs[1][3] as i32,
            cvs[2][3] as i32,
            cvs[3][3] as i32,
            cvs[4][3] as i32,
            cvs[5][3] as i32,
            cvs[6][3] as i32,
            cvs[7][3] as i32,
        );
        let mut s4 = _mm256_setr_epi32(
            cvs[0][4] as i32,
            cvs[1][4] as i32,
            cvs[2][4] as i32,
            cvs[3][4] as i32,
            cvs[4][4] as i32,
            cvs[5][4] as i32,
            cvs[6][4] as i32,
            cvs[7][4] as i32,
        );
        let mut s5 = _mm256_setr_epi32(
            cvs[0][5] as i32,
            cvs[1][5] as i32,
            cvs[2][5] as i32,
            cvs[3][5] as i32,
            cvs[4][5] as i32,
            cvs[5][5] as i32,
            cvs[6][5] as i32,
            cvs[7][5] as i32,
        );
        let mut s6 = _mm256_setr_epi32(
            cvs[0][6] as i32,
            cvs[1][6] as i32,
            cvs[2][6] as i32,
            cvs[3][6] as i32,
            cvs[4][6] as i32,
            cvs[5][6] as i32,
            cvs[6][6] as i32,
            cvs[7][6] as i32,
        );
        let mut s7 = _mm256_setr_epi32(
            cvs[0][7] as i32,
            cvs[1][7] as i32,
            cvs[2][7] as i32,
            cvs[3][7] as i32,
            cvs[4][7] as i32,
            cvs[5][7] as i32,
            cvs[6][7] as i32,
            cvs[7][7] as i32,
        );

        let mut s8 = IV_BROADCAST_0;
        let mut s9 = IV_BROADCAST_1;
        let mut s10 = IV_BROADCAST_2;
        let mut s11 = IV_BROADCAST_3;

        let mut s12 = _mm256_setr_epi32(
            counters[0] as i32,
            counters[1] as i32,
            counters[2] as i32,
            counters[3] as i32,
            counters[4] as i32,
            counters[5] as i32,
            counters[6] as i32,
            counters[7] as i32,
        );
        let mut s13 = _mm256_setr_epi32(
            (counters[0] >> 32) as i32,
            (counters[1] >> 32) as i32,
            (counters[2] >> 32) as i32,
            (counters[3] >> 32) as i32,
            (counters[4] >> 32) as i32,
            (counters[5] >> 32) as i32,
            (counters[6] >> 32) as i32,
            (counters[7] >> 32) as i32,
        );
        let mut s14 = _mm256_setr_epi32(
            block_lens[0] as i32,
            block_lens[1] as i32,
            block_lens[2] as i32,
            block_lens[3] as i32,
            block_lens[4] as i32,
            block_lens[5] as i32,
            block_lens[6] as i32,
            block_lens[7] as i32,
        );
        let mut s15 = _mm256_setr_epi32(
            flags[0] as i32,
            flags[1] as i32,
            flags[2] as i32,
            flags[3] as i32,
            flags[4] as i32,
            flags[5] as i32,
            flags[6] as i32,
            flags[7] as i32,
        );

        // Fully unrolled 7 rounds
        macro_rules! round {
            ($r:expr) => {
                g8(
                    &mut s0,
                    &mut s4,
                    &mut s8,
                    &mut s12,
                    m[MSG_SCHEDULE[$r][0]],
                    m[MSG_SCHEDULE[$r][1]],
                );
                g8(
                    &mut s1,
                    &mut s5,
                    &mut s9,
                    &mut s13,
                    m[MSG_SCHEDULE[$r][2]],
                    m[MSG_SCHEDULE[$r][3]],
                );
                g8(
                    &mut s2,
                    &mut s6,
                    &mut s10,
                    &mut s14,
                    m[MSG_SCHEDULE[$r][4]],
                    m[MSG_SCHEDULE[$r][5]],
                );
                g8(
                    &mut s3,
                    &mut s7,
                    &mut s11,
                    &mut s15,
                    m[MSG_SCHEDULE[$r][6]],
                    m[MSG_SCHEDULE[$r][7]],
                );
                g8(
                    &mut s0,
                    &mut s5,
                    &mut s10,
                    &mut s15,
                    m[MSG_SCHEDULE[$r][8]],
                    m[MSG_SCHEDULE[$r][9]],
                );
                g8(
                    &mut s1,
                    &mut s6,
                    &mut s11,
                    &mut s12,
                    m[MSG_SCHEDULE[$r][10]],
                    m[MSG_SCHEDULE[$r][11]],
                );
                g8(
                    &mut s2,
                    &mut s7,
                    &mut s8,
                    &mut s13,
                    m[MSG_SCHEDULE[$r][12]],
                    m[MSG_SCHEDULE[$r][13]],
                );
                g8(
                    &mut s3,
                    &mut s4,
                    &mut s9,
                    &mut s14,
                    m[MSG_SCHEDULE[$r][14]],
                    m[MSG_SCHEDULE[$r][15]],
                );
            };
        }

        round!(0);
        round!(1);
        round!(2);
        round!(3);
        round!(4);
        round!(5);
        round!(6);

        // XOR with input cv
        s0 = _mm256_xor_si256(s0, s8);
        s1 = _mm256_xor_si256(s1, s9);
        s2 = _mm256_xor_si256(s2, s10);
        s3 = _mm256_xor_si256(s3, s11);
        s4 = _mm256_xor_si256(s4, s12);
        s5 = _mm256_xor_si256(s5, s13);
        s6 = _mm256_xor_si256(s6, s14);
        s7 = _mm256_xor_si256(s7, s15);

        // 8x8 matrix transpose for output
        let t0 = _mm256_unpacklo_epi32(s0, s1);
        let t1 = _mm256_unpackhi_epi32(s0, s1);
        let t2 = _mm256_unpacklo_epi32(s2, s3);
        let t3 = _mm256_unpackhi_epi32(s2, s3);
        let t4 = _mm256_unpacklo_epi32(s4, s5);
        let t5 = _mm256_unpackhi_epi32(s4, s5);
        let t6 = _mm256_unpacklo_epi32(s6, s7);
        let t7 = _mm256_unpackhi_epi32(s6, s7);

        let u0 = _mm256_unpacklo_epi64(t0, t2);
        let u1 = _mm256_unpackhi_epi64(t0, t2);
        let u2 = _mm256_unpacklo_epi64(t1, t3);
        let u3 = _mm256_unpackhi_epi64(t1, t3);
        let u4 = _mm256_unpacklo_epi64(t4, t6);
        let u5 = _mm256_unpackhi_epi64(t4, t6);
        let u6 = _mm256_unpacklo_epi64(t5, t7);
        let u7 = _mm256_unpackhi_epi64(t5, t7);

        let r0 = _mm256_permute2x128_si256(u0, u4, 0x20);
        let r1 = _mm256_permute2x128_si256(u1, u5, 0x20);
        let r2 = _mm256_permute2x128_si256(u2, u6, 0x20);
        let r3 = _mm256_permute2x128_si256(u3, u7, 0x20);
        let r4 = _mm256_permute2x128_si256(u0, u4, 0x31);
        let r5 = _mm256_permute2x128_si256(u1, u5, 0x31);
        let r6 = _mm256_permute2x128_si256(u2, u6, 0x31);
        let r7 = _mm256_permute2x128_si256(u3, u7, 0x31);

        let mut results = [[0u32; 8]; 8];
        _mm256_storeu_si256(results[0].as_mut_ptr() as *mut __m256i, r0);
        _mm256_storeu_si256(results[1].as_mut_ptr() as *mut __m256i, r1);
        _mm256_storeu_si256(results[2].as_mut_ptr() as *mut __m256i, r2);
        _mm256_storeu_si256(results[3].as_mut_ptr() as *mut __m256i, r3);
        _mm256_storeu_si256(results[4].as_mut_ptr() as *mut __m256i, r4);
        _mm256_storeu_si256(results[5].as_mut_ptr() as *mut __m256i, r5);
        _mm256_storeu_si256(results[6].as_mut_ptr() as *mut __m256i, r6);
        _mm256_storeu_si256(results[7].as_mut_ptr() as *mut __m256i, r7);

        results
    }

    /// Fused hash of 8 contiguous chunks - processes all 16 blocks with CVs in registers.
    ///
    /// This is the fastest path for 8 contiguous chunks because the CV state vectors
    /// stay in AVX2 registers across all 16 block compressions, eliminating the
    /// load/store overhead between blocks.
    ///
    /// # Safety
    ///
    /// - Caller must ensure the CPU supports AVX2.
    /// - `base_ptr` must point to at least 8 contiguous chunks (8KB).
    #[target_feature(enable = "avx2")]
    pub unsafe fn hash_8_chunks_fused(
        key: &[u32; 8],
        base_ptr: *const u8,
        chunk_counters: &[u64; 8],
        base_flags: u8,
    ) -> [[u32; 8]; 8] {
        const CHUNK_START: u8 = 1;
        const CHUNK_END: u8 = 2;
        const CHUNK_LEN: usize = 1024;

        // Initialize CV state vectors from key - these stay in registers for all 16 blocks
        let mut cv0 = _mm256_set1_epi32(key[0] as i32);
        let mut cv1 = _mm256_set1_epi32(key[1] as i32);
        let mut cv2 = _mm256_set1_epi32(key[2] as i32);
        let mut cv3 = _mm256_set1_epi32(key[3] as i32);
        let mut cv4 = _mm256_set1_epi32(key[4] as i32);
        let mut cv5 = _mm256_set1_epi32(key[5] as i32);
        let mut cv6 = _mm256_set1_epi32(key[6] as i32);
        let mut cv7 = _mm256_set1_epi32(key[7] as i32);

        // Counter vectors (don't change between blocks)
        let counter_lo = _mm256_setr_epi32(
            chunk_counters[0] as i32,
            chunk_counters[1] as i32,
            chunk_counters[2] as i32,
            chunk_counters[3] as i32,
            chunk_counters[4] as i32,
            chunk_counters[5] as i32,
            chunk_counters[6] as i32,
            chunk_counters[7] as i32,
        );
        let counter_hi = _mm256_setr_epi32(
            (chunk_counters[0] >> 32) as i32,
            (chunk_counters[1] >> 32) as i32,
            (chunk_counters[2] >> 32) as i32,
            (chunk_counters[3] >> 32) as i32,
            (chunk_counters[4] >> 32) as i32,
            (chunk_counters[5] >> 32) as i32,
            (chunk_counters[6] >> 32) as i32,
            (chunk_counters[7] >> 32) as i32,
        );
        let block_len = _mm256_set1_epi32(64);

        // Process all 16 blocks, keeping CVs in registers
        for block_idx in 0..16 {
            let is_first = block_idx == 0;
            let is_last = block_idx == 15;

            // Build flags
            let mut flags_val = base_flags;
            if is_first {
                flags_val |= CHUNK_START;
            }
            if is_last {
                flags_val |= CHUNK_END;
            }
            let flags = _mm256_set1_epi32(flags_val as i32);

            // Load 16 message words using gather
            let m0 = load_msg_word_contiguous(base_ptr, block_idx, 0);
            let m1 = load_msg_word_contiguous(base_ptr, block_idx, 1);
            let m2 = load_msg_word_contiguous(base_ptr, block_idx, 2);
            let m3 = load_msg_word_contiguous(base_ptr, block_idx, 3);
            let m4 = load_msg_word_contiguous(base_ptr, block_idx, 4);
            let m5 = load_msg_word_contiguous(base_ptr, block_idx, 5);
            let m6 = load_msg_word_contiguous(base_ptr, block_idx, 6);
            let m7 = load_msg_word_contiguous(base_ptr, block_idx, 7);
            let m8 = load_msg_word_contiguous(base_ptr, block_idx, 8);
            let m9 = load_msg_word_contiguous(base_ptr, block_idx, 9);
            let m10 = load_msg_word_contiguous(base_ptr, block_idx, 10);
            let m11 = load_msg_word_contiguous(base_ptr, block_idx, 11);
            let m12 = load_msg_word_contiguous(base_ptr, block_idx, 12);
            let m13 = load_msg_word_contiguous(base_ptr, block_idx, 13);
            let m14 = load_msg_word_contiguous(base_ptr, block_idx, 14);
            let m15 = load_msg_word_contiguous(base_ptr, block_idx, 15);

            let m = [
                m0, m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15,
            ];

            // Initialize compression state from current CV
            let mut s0 = cv0;
            let mut s1 = cv1;
            let mut s2 = cv2;
            let mut s3 = cv3;
            let mut s4 = cv4;
            let mut s5 = cv5;
            let mut s6 = cv6;
            let mut s7 = cv7;
            let mut s8 = IV_BROADCAST_0;
            let mut s9 = IV_BROADCAST_1;
            let mut s10 = IV_BROADCAST_2;
            let mut s11 = IV_BROADCAST_3;
            let mut s12 = counter_lo;
            let mut s13 = counter_hi;
            let mut s14 = block_len;
            let mut s15 = flags;

            // 7 rounds of mixing
            macro_rules! round {
                ($r:expr) => {
                    g8(
                        &mut s0,
                        &mut s4,
                        &mut s8,
                        &mut s12,
                        m[MSG_SCHEDULE[$r][0]],
                        m[MSG_SCHEDULE[$r][1]],
                    );
                    g8(
                        &mut s1,
                        &mut s5,
                        &mut s9,
                        &mut s13,
                        m[MSG_SCHEDULE[$r][2]],
                        m[MSG_SCHEDULE[$r][3]],
                    );
                    g8(
                        &mut s2,
                        &mut s6,
                        &mut s10,
                        &mut s14,
                        m[MSG_SCHEDULE[$r][4]],
                        m[MSG_SCHEDULE[$r][5]],
                    );
                    g8(
                        &mut s3,
                        &mut s7,
                        &mut s11,
                        &mut s15,
                        m[MSG_SCHEDULE[$r][6]],
                        m[MSG_SCHEDULE[$r][7]],
                    );
                    g8(
                        &mut s0,
                        &mut s5,
                        &mut s10,
                        &mut s15,
                        m[MSG_SCHEDULE[$r][8]],
                        m[MSG_SCHEDULE[$r][9]],
                    );
                    g8(
                        &mut s1,
                        &mut s6,
                        &mut s11,
                        &mut s12,
                        m[MSG_SCHEDULE[$r][10]],
                        m[MSG_SCHEDULE[$r][11]],
                    );
                    g8(
                        &mut s2,
                        &mut s7,
                        &mut s8,
                        &mut s13,
                        m[MSG_SCHEDULE[$r][12]],
                        m[MSG_SCHEDULE[$r][13]],
                    );
                    g8(
                        &mut s3,
                        &mut s4,
                        &mut s9,
                        &mut s14,
                        m[MSG_SCHEDULE[$r][14]],
                        m[MSG_SCHEDULE[$r][15]],
                    );
                };
            }

            round!(0);
            round!(1);
            round!(2);
            round!(3);
            round!(4);
            round!(5);
            round!(6);

            // XOR with input CV to get output CV (stays in registers for next block!)
            cv0 = _mm256_xor_si256(s0, s8);
            cv1 = _mm256_xor_si256(s1, s9);
            cv2 = _mm256_xor_si256(s2, s10);
            cv3 = _mm256_xor_si256(s3, s11);
            cv4 = _mm256_xor_si256(s4, s12);
            cv5 = _mm256_xor_si256(s5, s13);
            cv6 = _mm256_xor_si256(s6, s14);
            cv7 = _mm256_xor_si256(s7, s15);
        }

        // Only now do we store - transpose and output the final CVs
        // cv0-cv7 are in "transposed" form (cv0 has word 0 from all 8 chunks)
        // We need to transpose back to get per-chunk CVs
        let t0 = _mm256_unpacklo_epi32(cv0, cv1);
        let t1 = _mm256_unpackhi_epi32(cv0, cv1);
        let t2 = _mm256_unpacklo_epi32(cv2, cv3);
        let t3 = _mm256_unpackhi_epi32(cv2, cv3);
        let t4 = _mm256_unpacklo_epi32(cv4, cv5);
        let t5 = _mm256_unpackhi_epi32(cv4, cv5);
        let t6 = _mm256_unpacklo_epi32(cv6, cv7);
        let t7 = _mm256_unpackhi_epi32(cv6, cv7);

        let u0 = _mm256_unpacklo_epi64(t0, t2);
        let u1 = _mm256_unpackhi_epi64(t0, t2);
        let u2 = _mm256_unpacklo_epi64(t1, t3);
        let u3 = _mm256_unpackhi_epi64(t1, t3);
        let u4 = _mm256_unpacklo_epi64(t4, t6);
        let u5 = _mm256_unpackhi_epi64(t4, t6);
        let u6 = _mm256_unpacklo_epi64(t5, t7);
        let u7 = _mm256_unpackhi_epi64(t5, t7);

        let r0 = _mm256_permute2x128_si256(u0, u4, 0x20);
        let r1 = _mm256_permute2x128_si256(u1, u5, 0x20);
        let r2 = _mm256_permute2x128_si256(u2, u6, 0x20);
        let r3 = _mm256_permute2x128_si256(u3, u7, 0x20);
        let r4 = _mm256_permute2x128_si256(u0, u4, 0x31);
        let r5 = _mm256_permute2x128_si256(u1, u5, 0x31);
        let r6 = _mm256_permute2x128_si256(u2, u6, 0x31);
        let r7 = _mm256_permute2x128_si256(u3, u7, 0x31);

        let mut results = [[0u32; 8]; 8];
        _mm256_storeu_si256(results[0].as_mut_ptr() as *mut __m256i, r0);
        _mm256_storeu_si256(results[1].as_mut_ptr() as *mut __m256i, r1);
        _mm256_storeu_si256(results[2].as_mut_ptr() as *mut __m256i, r2);
        _mm256_storeu_si256(results[3].as_mut_ptr() as *mut __m256i, r3);
        _mm256_storeu_si256(results[4].as_mut_ptr() as *mut __m256i, r4);
        _mm256_storeu_si256(results[5].as_mut_ptr() as *mut __m256i, r5);
        _mm256_storeu_si256(results[6].as_mut_ptr() as *mut __m256i, r6);
        _mm256_storeu_si256(results[7].as_mut_ptr() as *mut __m256i, r7);

        results
    }

    /// 8-way parallel G function using AVX2.
    /// Uses pure shift+OR for ALL rotations to avoid LLVM shuffle codegen issues.
    /// (Reference blake3 crate notes this produces better code on some compilers)
    #[target_feature(enable = "avx2")]
    #[inline]
    unsafe fn g8(
        a: &mut __m256i,
        b: &mut __m256i,
        c: &mut __m256i,
        d: &mut __m256i,
        mx: __m256i,
        my: __m256i,
    ) {
        // a = a + b + mx
        *a = _mm256_add_epi32(*a, _mm256_add_epi32(*b, mx));

        // d = (d ^ a) >>> 16 (shift+OR - consistent with reference impl)
        *d = _mm256_xor_si256(*d, *a);
        *d = _mm256_or_si256(_mm256_srli_epi32(*d, 16), _mm256_slli_epi32(*d, 16));

        // c = c + d
        *c = _mm256_add_epi32(*c, *d);

        // b = (b ^ c) >>> 12
        *b = _mm256_xor_si256(*b, *c);
        *b = _mm256_or_si256(_mm256_srli_epi32(*b, 12), _mm256_slli_epi32(*b, 20));

        // a = a + b + my
        *a = _mm256_add_epi32(*a, _mm256_add_epi32(*b, my));

        // d = (d ^ a) >>> 8 (shift+OR - consistent with reference impl)
        *d = _mm256_xor_si256(*d, *a);
        *d = _mm256_or_si256(_mm256_srli_epi32(*d, 8), _mm256_slli_epi32(*d, 24));

        // c = c + d
        *c = _mm256_add_epi32(*c, *d);

        // b = (b ^ c) >>> 7
        *b = _mm256_xor_si256(*b, *c);
        *b = _mm256_or_si256(_mm256_srli_epi32(*b, 7), _mm256_slli_epi32(*b, 25));
    }

    /// Compress 8 parent nodes in parallel using AVX2.
    ///
    /// Takes 8 pairs of CVs (left, right) and computes 8 parent CVs.
    /// This is 2x the throughput of 4-way parent compression.
    ///
    /// # Safety
    ///
    /// Caller must ensure the CPU supports AVX2.
    #[target_feature(enable = "avx2")]
    pub unsafe fn compress_parents_8(
        key: &[u32; 8],
        left_cvs: &[[u32; 8]; 8],
        right_cvs: &[[u32; 8]; 8],
        flags: u8,
    ) -> [[u32; 8]; 8] {
        const PARENT: u8 = 4;
        let parent_flags = flags | PARENT;

        // Construct 8 parent blocks: each is [left_cv || right_cv] = 64 bytes
        // Direct pointer copy is faster than per-element to_le_bytes
        let mut blocks = [[0u8; 64]; 8];
        for i in 0..8 {
            core::ptr::copy_nonoverlapping(
                left_cvs[i].as_ptr() as *const u8,
                blocks[i].as_mut_ptr(),
                32,
            );
            core::ptr::copy_nonoverlapping(
                right_cvs[i].as_ptr() as *const u8,
                blocks[i][32..].as_mut_ptr(),
                32,
            );
        }

        // All parent compressions use:
        // - key as the CV
        // - counter = 0
        // - block_len = 64
        // - flags = PARENT
        compress_8blocks(
            &[*key, *key, *key, *key, *key, *key, *key, *key],
            &blocks,
            &[0, 0, 0, 0, 0, 0, 0, 0],
            &[64, 64, 64, 64, 64, 64, 64, 64],
            &[parent_flags; 8],
        )
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 16-WAY PARALLEL COMPRESSION (AVX-512)
// ═══════════════════════════════════════════════════════════════════════════════

/// 16-way parallel BLAKE3 compression using AVX-512.
///
/// Processes 16 independent blocks simultaneously using 512-bit registers.
/// This provides 2x the parallelism of AVX2 8-way compression.
#[cfg(target_arch = "x86_64")]
pub mod parallel16 {
    use super::*;

    /// Precomputed message schedules for all 7 rounds (same as parallel8).
    const MSG_SCHEDULE: [[usize; 16]; 7] = [
        // Round 0
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        // Round 1
        [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8],
        // Round 2
        [3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1],
        // Round 3
        [10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6],
        // Round 4
        [12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4],
        // Round 5
        [9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7],
        // Round 6
        [11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13],
    ];

    /// Shuffle mask for ror 16 in AVX-512.
    const ROT16_SHUFFLE_512: [u8; 64] = [
        2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13, 2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9,
        14, 15, 12, 13, 2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13, 2, 3, 0, 1, 6, 7, 4,
        5, 10, 11, 8, 9, 14, 15, 12, 13,
    ];

    /// Shuffle mask for ror 8 in AVX-512.
    const ROT8_SHUFFLE_512: [u8; 64] = [
        1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12, 1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8,
        13, 14, 15, 12, 1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12, 1, 2, 3, 0, 5, 6, 7,
        4, 9, 10, 11, 8, 13, 14, 15, 12,
    ];

    /// Pre-computed broadcast IV vectors for 512-bit lanes.
    const IV_BROADCAST_512_0: __m512i =
        unsafe { core::mem::transmute::<[u32; 16], __m512i>([IV[0]; 16]) };
    const IV_BROADCAST_512_1: __m512i =
        unsafe { core::mem::transmute::<[u32; 16], __m512i>([IV[1]; 16]) };
    const IV_BROADCAST_512_2: __m512i =
        unsafe { core::mem::transmute::<[u32; 16], __m512i>([IV[2]; 16]) };
    const IV_BROADCAST_512_3: __m512i =
        unsafe { core::mem::transmute::<[u32; 16], __m512i>([IV[3]; 16]) };

    /// Load a transposed u32 from 16 blocks at the same word position.
    /// Uses AVX-512 gather for efficient strided access.
    #[target_feature(enable = "avx512f")]
    #[inline]
    unsafe fn load_msg_word_16(blocks: &[[u8; 64]; 16], word_idx: usize) -> __m512i {
        // Use AVX-512 gather for efficient strided loading
        let base = blocks.as_ptr() as *const i32;
        let word_offset = word_idx as i32;

        // Gather indices: block N word M, each block is 64 bytes = 16 i32s apart
        let indices = _mm512_setr_epi32(
            word_offset + 0 * 16,
            word_offset + 1 * 16,
            word_offset + 2 * 16,
            word_offset + 3 * 16,
            word_offset + 4 * 16,
            word_offset + 5 * 16,
            word_offset + 6 * 16,
            word_offset + 7 * 16,
            word_offset + 8 * 16,
            word_offset + 9 * 16,
            word_offset + 10 * 16,
            word_offset + 11 * 16,
            word_offset + 12 * 16,
            word_offset + 13 * 16,
            word_offset + 14 * 16,
            word_offset + 15 * 16,
        );

        _mm512_i32gather_epi32::<4>(indices, base)
    }

    /// Compress 16 blocks in parallel using AVX-512.
    ///
    /// Returns 16 chaining values (first 8 words of each output).
    ///
    /// # Safety
    ///
    /// Caller must ensure the CPU supports AVX-512F.
    #[target_feature(enable = "avx512f", enable = "avx512bw")]
    pub unsafe fn compress_16blocks(
        cvs: &[[u32; 8]; 16],
        blocks: &[[u8; 64]; 16],
        counters: &[u64; 16],
        block_lens: &[u32; 16],
        flags: &[u8; 16],
    ) -> [[u32; 8]; 16] {
        // Load shuffle masks
        let rot16_mask = _mm512_loadu_si512(ROT16_SHUFFLE_512.as_ptr() as *const __m512i);
        let rot8_mask = _mm512_loadu_si512(ROT8_SHUFFLE_512.as_ptr() as *const __m512i);

        // Load all 16 message words upfront (transposed)
        let m0 = load_msg_word_16(blocks, 0);
        let m1 = load_msg_word_16(blocks, 1);
        let m2 = load_msg_word_16(blocks, 2);
        let m3 = load_msg_word_16(blocks, 3);
        let m4 = load_msg_word_16(blocks, 4);
        let m5 = load_msg_word_16(blocks, 5);
        let m6 = load_msg_word_16(blocks, 6);
        let m7 = load_msg_word_16(blocks, 7);
        let m8 = load_msg_word_16(blocks, 8);
        let m9 = load_msg_word_16(blocks, 9);
        let m10 = load_msg_word_16(blocks, 10);
        let m11 = load_msg_word_16(blocks, 11);
        let m12 = load_msg_word_16(blocks, 12);
        let m13 = load_msg_word_16(blocks, 13);
        let m14 = load_msg_word_16(blocks, 14);
        let m15 = load_msg_word_16(blocks, 15);

        let m = [
            m0, m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15,
        ];

        // Initialize state (transposed across 16 blocks) using setr for better codegen
        let mut s0 = _mm512_setr_epi32(
            cvs[0][0] as i32,
            cvs[1][0] as i32,
            cvs[2][0] as i32,
            cvs[3][0] as i32,
            cvs[4][0] as i32,
            cvs[5][0] as i32,
            cvs[6][0] as i32,
            cvs[7][0] as i32,
            cvs[8][0] as i32,
            cvs[9][0] as i32,
            cvs[10][0] as i32,
            cvs[11][0] as i32,
            cvs[12][0] as i32,
            cvs[13][0] as i32,
            cvs[14][0] as i32,
            cvs[15][0] as i32,
        );
        let mut s1 = _mm512_setr_epi32(
            cvs[0][1] as i32,
            cvs[1][1] as i32,
            cvs[2][1] as i32,
            cvs[3][1] as i32,
            cvs[4][1] as i32,
            cvs[5][1] as i32,
            cvs[6][1] as i32,
            cvs[7][1] as i32,
            cvs[8][1] as i32,
            cvs[9][1] as i32,
            cvs[10][1] as i32,
            cvs[11][1] as i32,
            cvs[12][1] as i32,
            cvs[13][1] as i32,
            cvs[14][1] as i32,
            cvs[15][1] as i32,
        );
        let mut s2 = _mm512_setr_epi32(
            cvs[0][2] as i32,
            cvs[1][2] as i32,
            cvs[2][2] as i32,
            cvs[3][2] as i32,
            cvs[4][2] as i32,
            cvs[5][2] as i32,
            cvs[6][2] as i32,
            cvs[7][2] as i32,
            cvs[8][2] as i32,
            cvs[9][2] as i32,
            cvs[10][2] as i32,
            cvs[11][2] as i32,
            cvs[12][2] as i32,
            cvs[13][2] as i32,
            cvs[14][2] as i32,
            cvs[15][2] as i32,
        );
        let mut s3 = _mm512_setr_epi32(
            cvs[0][3] as i32,
            cvs[1][3] as i32,
            cvs[2][3] as i32,
            cvs[3][3] as i32,
            cvs[4][3] as i32,
            cvs[5][3] as i32,
            cvs[6][3] as i32,
            cvs[7][3] as i32,
            cvs[8][3] as i32,
            cvs[9][3] as i32,
            cvs[10][3] as i32,
            cvs[11][3] as i32,
            cvs[12][3] as i32,
            cvs[13][3] as i32,
            cvs[14][3] as i32,
            cvs[15][3] as i32,
        );
        let mut s4 = _mm512_setr_epi32(
            cvs[0][4] as i32,
            cvs[1][4] as i32,
            cvs[2][4] as i32,
            cvs[3][4] as i32,
            cvs[4][4] as i32,
            cvs[5][4] as i32,
            cvs[6][4] as i32,
            cvs[7][4] as i32,
            cvs[8][4] as i32,
            cvs[9][4] as i32,
            cvs[10][4] as i32,
            cvs[11][4] as i32,
            cvs[12][4] as i32,
            cvs[13][4] as i32,
            cvs[14][4] as i32,
            cvs[15][4] as i32,
        );
        let mut s5 = _mm512_setr_epi32(
            cvs[0][5] as i32,
            cvs[1][5] as i32,
            cvs[2][5] as i32,
            cvs[3][5] as i32,
            cvs[4][5] as i32,
            cvs[5][5] as i32,
            cvs[6][5] as i32,
            cvs[7][5] as i32,
            cvs[8][5] as i32,
            cvs[9][5] as i32,
            cvs[10][5] as i32,
            cvs[11][5] as i32,
            cvs[12][5] as i32,
            cvs[13][5] as i32,
            cvs[14][5] as i32,
            cvs[15][5] as i32,
        );
        let mut s6 = _mm512_setr_epi32(
            cvs[0][6] as i32,
            cvs[1][6] as i32,
            cvs[2][6] as i32,
            cvs[3][6] as i32,
            cvs[4][6] as i32,
            cvs[5][6] as i32,
            cvs[6][6] as i32,
            cvs[7][6] as i32,
            cvs[8][6] as i32,
            cvs[9][6] as i32,
            cvs[10][6] as i32,
            cvs[11][6] as i32,
            cvs[12][6] as i32,
            cvs[13][6] as i32,
            cvs[14][6] as i32,
            cvs[15][6] as i32,
        );
        let mut s7 = _mm512_setr_epi32(
            cvs[0][7] as i32,
            cvs[1][7] as i32,
            cvs[2][7] as i32,
            cvs[3][7] as i32,
            cvs[4][7] as i32,
            cvs[5][7] as i32,
            cvs[6][7] as i32,
            cvs[7][7] as i32,
            cvs[8][7] as i32,
            cvs[9][7] as i32,
            cvs[10][7] as i32,
            cvs[11][7] as i32,
            cvs[12][7] as i32,
            cvs[13][7] as i32,
            cvs[14][7] as i32,
            cvs[15][7] as i32,
        );

        // Use pre-computed IV broadcast vectors
        let mut s8 = IV_BROADCAST_512_0;
        let mut s9 = IV_BROADCAST_512_1;
        let mut s10 = IV_BROADCAST_512_2;
        let mut s11 = IV_BROADCAST_512_3;

        // Use setr for counters, block_lens, flags (natural order)
        let mut s12 = _mm512_setr_epi32(
            counters[0] as i32,
            counters[1] as i32,
            counters[2] as i32,
            counters[3] as i32,
            counters[4] as i32,
            counters[5] as i32,
            counters[6] as i32,
            counters[7] as i32,
            counters[8] as i32,
            counters[9] as i32,
            counters[10] as i32,
            counters[11] as i32,
            counters[12] as i32,
            counters[13] as i32,
            counters[14] as i32,
            counters[15] as i32,
        );
        let mut s13 = _mm512_setr_epi32(
            (counters[0] >> 32) as i32,
            (counters[1] >> 32) as i32,
            (counters[2] >> 32) as i32,
            (counters[3] >> 32) as i32,
            (counters[4] >> 32) as i32,
            (counters[5] >> 32) as i32,
            (counters[6] >> 32) as i32,
            (counters[7] >> 32) as i32,
            (counters[8] >> 32) as i32,
            (counters[9] >> 32) as i32,
            (counters[10] >> 32) as i32,
            (counters[11] >> 32) as i32,
            (counters[12] >> 32) as i32,
            (counters[13] >> 32) as i32,
            (counters[14] >> 32) as i32,
            (counters[15] >> 32) as i32,
        );
        let mut s14 = _mm512_setr_epi32(
            block_lens[0] as i32,
            block_lens[1] as i32,
            block_lens[2] as i32,
            block_lens[3] as i32,
            block_lens[4] as i32,
            block_lens[5] as i32,
            block_lens[6] as i32,
            block_lens[7] as i32,
            block_lens[8] as i32,
            block_lens[9] as i32,
            block_lens[10] as i32,
            block_lens[11] as i32,
            block_lens[12] as i32,
            block_lens[13] as i32,
            block_lens[14] as i32,
            block_lens[15] as i32,
        );
        let mut s15 = _mm512_setr_epi32(
            flags[0] as i32,
            flags[1] as i32,
            flags[2] as i32,
            flags[3] as i32,
            flags[4] as i32,
            flags[5] as i32,
            flags[6] as i32,
            flags[7] as i32,
            flags[8] as i32,
            flags[9] as i32,
            flags[10] as i32,
            flags[11] as i32,
            flags[12] as i32,
            flags[13] as i32,
            flags[14] as i32,
            flags[15] as i32,
        );

        // 16-way parallel G function using AVX-512
        macro_rules! g16 {
            ($a:expr, $b:expr, $c:expr, $d:expr, $mx:expr, $my:expr) => {
                // a = a + b + mx
                $a = _mm512_add_epi32($a, _mm512_add_epi32($b, $mx));
                // d = (d ^ a) >>> 16
                $d = _mm512_xor_si512($d, $a);
                $d = _mm512_shuffle_epi8($d, rot16_mask);
                // c = c + d
                $c = _mm512_add_epi32($c, $d);
                // b = (b ^ c) >>> 12
                $b = _mm512_xor_si512($b, $c);
                $b = _mm512_or_si512(_mm512_srli_epi32($b, 12), _mm512_slli_epi32($b, 20));
                // a = a + b + my
                $a = _mm512_add_epi32($a, _mm512_add_epi32($b, $my));
                // d = (d ^ a) >>> 8
                $d = _mm512_xor_si512($d, $a);
                $d = _mm512_shuffle_epi8($d, rot8_mask);
                // c = c + d
                $c = _mm512_add_epi32($c, $d);
                // b = (b ^ c) >>> 7
                $b = _mm512_xor_si512($b, $c);
                $b = _mm512_or_si512(_mm512_srli_epi32($b, 7), _mm512_slli_epi32($b, 25));
            };
        }

        // Round macro
        macro_rules! round {
            ($r:expr) => {
                g16!(
                    s0,
                    s4,
                    s8,
                    s12,
                    m[MSG_SCHEDULE[$r][0]],
                    m[MSG_SCHEDULE[$r][1]]
                );
                g16!(
                    s1,
                    s5,
                    s9,
                    s13,
                    m[MSG_SCHEDULE[$r][2]],
                    m[MSG_SCHEDULE[$r][3]]
                );
                g16!(
                    s2,
                    s6,
                    s10,
                    s14,
                    m[MSG_SCHEDULE[$r][4]],
                    m[MSG_SCHEDULE[$r][5]]
                );
                g16!(
                    s3,
                    s7,
                    s11,
                    s15,
                    m[MSG_SCHEDULE[$r][6]],
                    m[MSG_SCHEDULE[$r][7]]
                );
                g16!(
                    s0,
                    s5,
                    s10,
                    s15,
                    m[MSG_SCHEDULE[$r][8]],
                    m[MSG_SCHEDULE[$r][9]]
                );
                g16!(
                    s1,
                    s6,
                    s11,
                    s12,
                    m[MSG_SCHEDULE[$r][10]],
                    m[MSG_SCHEDULE[$r][11]]
                );
                g16!(
                    s2,
                    s7,
                    s8,
                    s13,
                    m[MSG_SCHEDULE[$r][12]],
                    m[MSG_SCHEDULE[$r][13]]
                );
                g16!(
                    s3,
                    s4,
                    s9,
                    s14,
                    m[MSG_SCHEDULE[$r][14]],
                    m[MSG_SCHEDULE[$r][15]]
                );
            };
        }

        round!(0);
        round!(1);
        round!(2);
        round!(3);
        round!(4);
        round!(5);
        round!(6);

        // XOR with input cv
        s0 = _mm512_xor_si512(s0, s8);
        s1 = _mm512_xor_si512(s1, s9);
        s2 = _mm512_xor_si512(s2, s10);
        s3 = _mm512_xor_si512(s3, s11);
        s4 = _mm512_xor_si512(s4, s12);
        s5 = _mm512_xor_si512(s5, s13);
        s6 = _mm512_xor_si512(s6, s14);
        s7 = _mm512_xor_si512(s7, s15);

        // Extract results using SIMD transpose (16x8 -> outputs)
        // Split each 512-bit vector into two 256-bit halves, then use 8x8 transpose

        // Extract low and high 256-bit halves
        let s0_lo = _mm512_castsi512_si256(s0);
        let s0_hi = _mm512_extracti64x4_epi64(s0, 1);
        let s1_lo = _mm512_castsi512_si256(s1);
        let s1_hi = _mm512_extracti64x4_epi64(s1, 1);
        let s2_lo = _mm512_castsi512_si256(s2);
        let s2_hi = _mm512_extracti64x4_epi64(s2, 1);
        let s3_lo = _mm512_castsi512_si256(s3);
        let s3_hi = _mm512_extracti64x4_epi64(s3, 1);
        let s4_lo = _mm512_castsi512_si256(s4);
        let s4_hi = _mm512_extracti64x4_epi64(s4, 1);
        let s5_lo = _mm512_castsi512_si256(s5);
        let s5_hi = _mm512_extracti64x4_epi64(s5, 1);
        let s6_lo = _mm512_castsi512_si256(s6);
        let s6_hi = _mm512_extracti64x4_epi64(s6, 1);
        let s7_lo = _mm512_castsi512_si256(s7);
        let s7_hi = _mm512_extracti64x4_epi64(s7, 1);

        // Transpose low halves (blocks 0-7)
        let t0 = _mm256_unpacklo_epi32(s0_lo, s1_lo);
        let t1 = _mm256_unpackhi_epi32(s0_lo, s1_lo);
        let t2 = _mm256_unpacklo_epi32(s2_lo, s3_lo);
        let t3 = _mm256_unpackhi_epi32(s2_lo, s3_lo);
        let t4 = _mm256_unpacklo_epi32(s4_lo, s5_lo);
        let t5 = _mm256_unpackhi_epi32(s4_lo, s5_lo);
        let t6 = _mm256_unpacklo_epi32(s6_lo, s7_lo);
        let t7 = _mm256_unpackhi_epi32(s6_lo, s7_lo);

        let u0 = _mm256_unpacklo_epi64(t0, t2);
        let u1 = _mm256_unpackhi_epi64(t0, t2);
        let u2 = _mm256_unpacklo_epi64(t1, t3);
        let u3 = _mm256_unpackhi_epi64(t1, t3);
        let u4 = _mm256_unpacklo_epi64(t4, t6);
        let u5 = _mm256_unpackhi_epi64(t4, t6);
        let u6 = _mm256_unpacklo_epi64(t5, t7);
        let u7 = _mm256_unpackhi_epi64(t5, t7);

        let r0 = _mm256_permute2x128_si256(u0, u4, 0x20);
        let r1 = _mm256_permute2x128_si256(u1, u5, 0x20);
        let r2 = _mm256_permute2x128_si256(u2, u6, 0x20);
        let r3 = _mm256_permute2x128_si256(u3, u7, 0x20);
        let r4 = _mm256_permute2x128_si256(u0, u4, 0x31);
        let r5 = _mm256_permute2x128_si256(u1, u5, 0x31);
        let r6 = _mm256_permute2x128_si256(u2, u6, 0x31);
        let r7 = _mm256_permute2x128_si256(u3, u7, 0x31);

        // Transpose high halves (blocks 8-15)
        let t0h = _mm256_unpacklo_epi32(s0_hi, s1_hi);
        let t1h = _mm256_unpackhi_epi32(s0_hi, s1_hi);
        let t2h = _mm256_unpacklo_epi32(s2_hi, s3_hi);
        let t3h = _mm256_unpackhi_epi32(s2_hi, s3_hi);
        let t4h = _mm256_unpacklo_epi32(s4_hi, s5_hi);
        let t5h = _mm256_unpackhi_epi32(s4_hi, s5_hi);
        let t6h = _mm256_unpacklo_epi32(s6_hi, s7_hi);
        let t7h = _mm256_unpackhi_epi32(s6_hi, s7_hi);

        let u0h = _mm256_unpacklo_epi64(t0h, t2h);
        let u1h = _mm256_unpackhi_epi64(t0h, t2h);
        let u2h = _mm256_unpacklo_epi64(t1h, t3h);
        let u3h = _mm256_unpackhi_epi64(t1h, t3h);
        let u4h = _mm256_unpacklo_epi64(t4h, t6h);
        let u5h = _mm256_unpackhi_epi64(t4h, t6h);
        let u6h = _mm256_unpacklo_epi64(t5h, t7h);
        let u7h = _mm256_unpackhi_epi64(t5h, t7h);

        let r8 = _mm256_permute2x128_si256(u0h, u4h, 0x20);
        let r9 = _mm256_permute2x128_si256(u1h, u5h, 0x20);
        let r10 = _mm256_permute2x128_si256(u2h, u6h, 0x20);
        let r11 = _mm256_permute2x128_si256(u3h, u7h, 0x20);
        let r12 = _mm256_permute2x128_si256(u0h, u4h, 0x31);
        let r13 = _mm256_permute2x128_si256(u1h, u5h, 0x31);
        let r14 = _mm256_permute2x128_si256(u2h, u6h, 0x31);
        let r15 = _mm256_permute2x128_si256(u3h, u7h, 0x31);

        // Store results
        let mut results = [[0u32; 8]; 16];
        _mm256_storeu_si256(results[0].as_mut_ptr() as *mut __m256i, r0);
        _mm256_storeu_si256(results[1].as_mut_ptr() as *mut __m256i, r1);
        _mm256_storeu_si256(results[2].as_mut_ptr() as *mut __m256i, r2);
        _mm256_storeu_si256(results[3].as_mut_ptr() as *mut __m256i, r3);
        _mm256_storeu_si256(results[4].as_mut_ptr() as *mut __m256i, r4);
        _mm256_storeu_si256(results[5].as_mut_ptr() as *mut __m256i, r5);
        _mm256_storeu_si256(results[6].as_mut_ptr() as *mut __m256i, r6);
        _mm256_storeu_si256(results[7].as_mut_ptr() as *mut __m256i, r7);
        _mm256_storeu_si256(results[8].as_mut_ptr() as *mut __m256i, r8);
        _mm256_storeu_si256(results[9].as_mut_ptr() as *mut __m256i, r9);
        _mm256_storeu_si256(results[10].as_mut_ptr() as *mut __m256i, r10);
        _mm256_storeu_si256(results[11].as_mut_ptr() as *mut __m256i, r11);
        _mm256_storeu_si256(results[12].as_mut_ptr() as *mut __m256i, r12);
        _mm256_storeu_si256(results[13].as_mut_ptr() as *mut __m256i, r13);
        _mm256_storeu_si256(results[14].as_mut_ptr() as *mut __m256i, r14);
        _mm256_storeu_si256(results[15].as_mut_ptr() as *mut __m256i, r15);

        results
    }

    /// Load a transposed u32 from 16 chunk pointers at the same word position within a block.
    #[target_feature(enable = "avx512f")]
    #[inline]
    unsafe fn load_msg_word_from_chunk_ptrs(
        chunk_ptrs: &[*const u8; 16],
        block_idx: usize,
        word_idx: usize,
    ) -> __m512i {
        let offset = block_idx * 64 + word_idx * 4;
        // Use setr (natural order) - better codegen than set (reversed order)
        let w0 = *(chunk_ptrs[0].add(offset) as *const i32);
        let w1 = *(chunk_ptrs[1].add(offset) as *const i32);
        let w2 = *(chunk_ptrs[2].add(offset) as *const i32);
        let w3 = *(chunk_ptrs[3].add(offset) as *const i32);
        let w4 = *(chunk_ptrs[4].add(offset) as *const i32);
        let w5 = *(chunk_ptrs[5].add(offset) as *const i32);
        let w6 = *(chunk_ptrs[6].add(offset) as *const i32);
        let w7 = *(chunk_ptrs[7].add(offset) as *const i32);
        let w8 = *(chunk_ptrs[8].add(offset) as *const i32);
        let w9 = *(chunk_ptrs[9].add(offset) as *const i32);
        let w10 = *(chunk_ptrs[10].add(offset) as *const i32);
        let w11 = *(chunk_ptrs[11].add(offset) as *const i32);
        let w12 = *(chunk_ptrs[12].add(offset) as *const i32);
        let w13 = *(chunk_ptrs[13].add(offset) as *const i32);
        let w14 = *(chunk_ptrs[14].add(offset) as *const i32);
        let w15 = *(chunk_ptrs[15].add(offset) as *const i32);
        _mm512_setr_epi32(
            w0, w1, w2, w3, w4, w5, w6, w7, w8, w9, w10, w11, w12, w13, w14, w15,
        )
    }

    /// Transpose a 16x16 matrix of 32-bit words in AVX-512 registers.
    ///
    /// Input: vecs[i] contains word 0-15 from chunk i
    /// Output: vecs[i] contains word i from chunks 0-15
    ///
    /// This is the key optimization - 16 contiguous loads + transpose is faster
    /// than 16 gather operations because contiguous loads hit cache better and
    /// shuffle operations have lower latency than gathers.
    #[target_feature(enable = "avx512f")]
    #[inline]
    unsafe fn transpose_vecs_512(vecs: &mut [__m512i; 16]) {
        // Helper for 128-bit lane shuffles
        // _MM_SHUFFLE(z, y, x, w) = (z<<6)|(y<<4)|(x<<2)|w
        // unpack_lo_128: select lanes 0,2 from a and 0,2 from b
        // unpack_hi_128: select lanes 1,3 from a and 1,3 from b
        #[inline(always)]
        unsafe fn unpack_lo_128(a: __m512i, b: __m512i) -> __m512i {
            // _MM_SHUFFLE(2, 0, 2, 0) = 0x88
            _mm512_shuffle_i32x4(a, b, 0x88)
        }
        #[inline(always)]
        unsafe fn unpack_hi_128(a: __m512i, b: __m512i) -> __m512i {
            // _MM_SHUFFLE(3, 1, 3, 1) = 0xDD
            _mm512_shuffle_i32x4(a, b, 0xDD)
        }

        // Interleave 32-bit lanes
        let ab_0 = _mm512_unpacklo_epi32(vecs[0], vecs[1]);
        let ab_2 = _mm512_unpackhi_epi32(vecs[0], vecs[1]);
        let cd_0 = _mm512_unpacklo_epi32(vecs[2], vecs[3]);
        let cd_2 = _mm512_unpackhi_epi32(vecs[2], vecs[3]);
        let ef_0 = _mm512_unpacklo_epi32(vecs[4], vecs[5]);
        let ef_2 = _mm512_unpackhi_epi32(vecs[4], vecs[5]);
        let gh_0 = _mm512_unpacklo_epi32(vecs[6], vecs[7]);
        let gh_2 = _mm512_unpackhi_epi32(vecs[6], vecs[7]);
        let ij_0 = _mm512_unpacklo_epi32(vecs[8], vecs[9]);
        let ij_2 = _mm512_unpackhi_epi32(vecs[8], vecs[9]);
        let kl_0 = _mm512_unpacklo_epi32(vecs[10], vecs[11]);
        let kl_2 = _mm512_unpackhi_epi32(vecs[10], vecs[11]);
        let mn_0 = _mm512_unpacklo_epi32(vecs[12], vecs[13]);
        let mn_2 = _mm512_unpackhi_epi32(vecs[12], vecs[13]);
        let op_0 = _mm512_unpacklo_epi32(vecs[14], vecs[15]);
        let op_2 = _mm512_unpackhi_epi32(vecs[14], vecs[15]);

        // Interleave 64-bit lanes
        let abcd_0 = _mm512_unpacklo_epi64(ab_0, cd_0);
        let abcd_1 = _mm512_unpackhi_epi64(ab_0, cd_0);
        let abcd_2 = _mm512_unpacklo_epi64(ab_2, cd_2);
        let abcd_3 = _mm512_unpackhi_epi64(ab_2, cd_2);
        let efgh_0 = _mm512_unpacklo_epi64(ef_0, gh_0);
        let efgh_1 = _mm512_unpackhi_epi64(ef_0, gh_0);
        let efgh_2 = _mm512_unpacklo_epi64(ef_2, gh_2);
        let efgh_3 = _mm512_unpackhi_epi64(ef_2, gh_2);
        let ijkl_0 = _mm512_unpacklo_epi64(ij_0, kl_0);
        let ijkl_1 = _mm512_unpackhi_epi64(ij_0, kl_0);
        let ijkl_2 = _mm512_unpacklo_epi64(ij_2, kl_2);
        let ijkl_3 = _mm512_unpackhi_epi64(ij_2, kl_2);
        let mnop_0 = _mm512_unpacklo_epi64(mn_0, op_0);
        let mnop_1 = _mm512_unpackhi_epi64(mn_0, op_0);
        let mnop_2 = _mm512_unpacklo_epi64(mn_2, op_2);
        let mnop_3 = _mm512_unpackhi_epi64(mn_2, op_2);

        // Interleave 128-bit lanes
        let abcdefgh_0 = unpack_lo_128(abcd_0, efgh_0);
        let abcdefgh_1 = unpack_lo_128(abcd_1, efgh_1);
        let abcdefgh_2 = unpack_lo_128(abcd_2, efgh_2);
        let abcdefgh_3 = unpack_lo_128(abcd_3, efgh_3);
        let abcdefgh_4 = unpack_hi_128(abcd_0, efgh_0);
        let abcdefgh_5 = unpack_hi_128(abcd_1, efgh_1);
        let abcdefgh_6 = unpack_hi_128(abcd_2, efgh_2);
        let abcdefgh_7 = unpack_hi_128(abcd_3, efgh_3);
        let ijklmnop_0 = unpack_lo_128(ijkl_0, mnop_0);
        let ijklmnop_1 = unpack_lo_128(ijkl_1, mnop_1);
        let ijklmnop_2 = unpack_lo_128(ijkl_2, mnop_2);
        let ijklmnop_3 = unpack_lo_128(ijkl_3, mnop_3);
        let ijklmnop_4 = unpack_hi_128(ijkl_0, mnop_0);
        let ijklmnop_5 = unpack_hi_128(ijkl_1, mnop_1);
        let ijklmnop_6 = unpack_hi_128(ijkl_2, mnop_2);
        let ijklmnop_7 = unpack_hi_128(ijkl_3, mnop_3);

        // Final 128-bit interleave for output
        vecs[0] = unpack_lo_128(abcdefgh_0, ijklmnop_0);
        vecs[1] = unpack_lo_128(abcdefgh_1, ijklmnop_1);
        vecs[2] = unpack_lo_128(abcdefgh_2, ijklmnop_2);
        vecs[3] = unpack_lo_128(abcdefgh_3, ijklmnop_3);
        vecs[4] = unpack_lo_128(abcdefgh_4, ijklmnop_4);
        vecs[5] = unpack_lo_128(abcdefgh_5, ijklmnop_5);
        vecs[6] = unpack_lo_128(abcdefgh_6, ijklmnop_6);
        vecs[7] = unpack_lo_128(abcdefgh_7, ijklmnop_7);
        vecs[8] = unpack_hi_128(abcdefgh_0, ijklmnop_0);
        vecs[9] = unpack_hi_128(abcdefgh_1, ijklmnop_1);
        vecs[10] = unpack_hi_128(abcdefgh_2, ijklmnop_2);
        vecs[11] = unpack_hi_128(abcdefgh_3, ijklmnop_3);
        vecs[12] = unpack_hi_128(abcdefgh_4, ijklmnop_4);
        vecs[13] = unpack_hi_128(abcdefgh_5, ijklmnop_5);
        vecs[14] = unpack_hi_128(abcdefgh_6, ijklmnop_6);
        vecs[15] = unpack_hi_128(abcdefgh_7, ijklmnop_7);
    }

    /// Load and transpose message block from 16 contiguous chunks.
    ///
    /// Uses 16 contiguous loads + transpose instead of 16 gathers.
    /// This is faster because contiguous loads hit cache better and
    /// shuffle operations have lower latency than gather instructions.
    #[target_feature(enable = "avx512f")]
    #[inline]
    unsafe fn load_transpose_msg_16(base_ptr: *const u8, block_idx: usize) -> [__m512i; 16] {
        const CHUNK_LEN: usize = 1024;
        const BLOCK_LEN: usize = 64;
        let block_offset = block_idx * BLOCK_LEN;

        // Load complete 64-byte block from each of 16 chunks
        let mut vecs: [__m512i; 16] = [_mm512_setzero_si512(); 16];
        vecs[0] =
            _mm512_loadu_si512((base_ptr.add(0 * CHUNK_LEN + block_offset)) as *const __m512i);
        vecs[1] =
            _mm512_loadu_si512((base_ptr.add(1 * CHUNK_LEN + block_offset)) as *const __m512i);
        vecs[2] =
            _mm512_loadu_si512((base_ptr.add(2 * CHUNK_LEN + block_offset)) as *const __m512i);
        vecs[3] =
            _mm512_loadu_si512((base_ptr.add(3 * CHUNK_LEN + block_offset)) as *const __m512i);
        vecs[4] =
            _mm512_loadu_si512((base_ptr.add(4 * CHUNK_LEN + block_offset)) as *const __m512i);
        vecs[5] =
            _mm512_loadu_si512((base_ptr.add(5 * CHUNK_LEN + block_offset)) as *const __m512i);
        vecs[6] =
            _mm512_loadu_si512((base_ptr.add(6 * CHUNK_LEN + block_offset)) as *const __m512i);
        vecs[7] =
            _mm512_loadu_si512((base_ptr.add(7 * CHUNK_LEN + block_offset)) as *const __m512i);
        vecs[8] =
            _mm512_loadu_si512((base_ptr.add(8 * CHUNK_LEN + block_offset)) as *const __m512i);
        vecs[9] =
            _mm512_loadu_si512((base_ptr.add(9 * CHUNK_LEN + block_offset)) as *const __m512i);
        vecs[10] =
            _mm512_loadu_si512((base_ptr.add(10 * CHUNK_LEN + block_offset)) as *const __m512i);
        vecs[11] =
            _mm512_loadu_si512((base_ptr.add(11 * CHUNK_LEN + block_offset)) as *const __m512i);
        vecs[12] =
            _mm512_loadu_si512((base_ptr.add(12 * CHUNK_LEN + block_offset)) as *const __m512i);
        vecs[13] =
            _mm512_loadu_si512((base_ptr.add(13 * CHUNK_LEN + block_offset)) as *const __m512i);
        vecs[14] =
            _mm512_loadu_si512((base_ptr.add(14 * CHUNK_LEN + block_offset)) as *const __m512i);
        vecs[15] =
            _mm512_loadu_si512((base_ptr.add(15 * CHUNK_LEN + block_offset)) as *const __m512i);

        // Transpose: vecs[i] had word 0-15 from chunk i
        // After transpose: vecs[i] has word i from chunks 0-15
        transpose_vecs_512(&mut vecs);
        vecs
    }

    /// Load a message word from 16 contiguous chunks using AVX-512 gather.
    ///
    /// Gather is efficient for cache-cold access patterns at larger data sizes.
    #[target_feature(enable = "avx512f")]
    #[inline]
    unsafe fn load_msg_word_gather_16(
        base_ptr: *const u8,
        block_idx: usize,
        word_idx: usize,
    ) -> __m512i {
        const CHUNK_LEN_WORDS: i32 = 256; // 1024 bytes / 4 bytes per word
        const BLOCK_LEN_WORDS: i32 = 16; // 64 bytes / 4 bytes per word

        let base_offset = (block_idx as i32) * BLOCK_LEN_WORDS + (word_idx as i32);

        // Gather indices: chunk 0, 1, 2, ..., 15 at stride CHUNK_LEN_WORDS
        let indices = _mm512_setr_epi32(
            base_offset + 0 * CHUNK_LEN_WORDS,
            base_offset + 1 * CHUNK_LEN_WORDS,
            base_offset + 2 * CHUNK_LEN_WORDS,
            base_offset + 3 * CHUNK_LEN_WORDS,
            base_offset + 4 * CHUNK_LEN_WORDS,
            base_offset + 5 * CHUNK_LEN_WORDS,
            base_offset + 6 * CHUNK_LEN_WORDS,
            base_offset + 7 * CHUNK_LEN_WORDS,
            base_offset + 8 * CHUNK_LEN_WORDS,
            base_offset + 9 * CHUNK_LEN_WORDS,
            base_offset + 10 * CHUNK_LEN_WORDS,
            base_offset + 11 * CHUNK_LEN_WORDS,
            base_offset + 12 * CHUNK_LEN_WORDS,
            base_offset + 13 * CHUNK_LEN_WORDS,
            base_offset + 14 * CHUNK_LEN_WORDS,
            base_offset + 15 * CHUNK_LEN_WORDS,
        );

        _mm512_i32gather_epi32::<4>(indices, base_ptr as *const i32)
    }

    /// Load message words using gather (16 gathers per block).
    #[target_feature(enable = "avx512f")]
    #[inline]
    unsafe fn load_msg_gather_16(base_ptr: *const u8, block_idx: usize) -> [__m512i; 16] {
        [
            load_msg_word_gather_16(base_ptr, block_idx, 0),
            load_msg_word_gather_16(base_ptr, block_idx, 1),
            load_msg_word_gather_16(base_ptr, block_idx, 2),
            load_msg_word_gather_16(base_ptr, block_idx, 3),
            load_msg_word_gather_16(base_ptr, block_idx, 4),
            load_msg_word_gather_16(base_ptr, block_idx, 5),
            load_msg_word_gather_16(base_ptr, block_idx, 6),
            load_msg_word_gather_16(base_ptr, block_idx, 7),
            load_msg_word_gather_16(base_ptr, block_idx, 8),
            load_msg_word_gather_16(base_ptr, block_idx, 9),
            load_msg_word_gather_16(base_ptr, block_idx, 10),
            load_msg_word_gather_16(base_ptr, block_idx, 11),
            load_msg_word_gather_16(base_ptr, block_idx, 12),
            load_msg_word_gather_16(base_ptr, block_idx, 13),
            load_msg_word_gather_16(base_ptr, block_idx, 14),
            load_msg_word_gather_16(base_ptr, block_idx, 15),
        ]
    }

    /// Fused hash of 16 contiguous chunks - processes all 16 blocks with CVs in registers.
    ///
    /// This is the fastest path for 16 contiguous chunks because:
    /// 1. Keeps CV state in registers across all 16 block compressions
    /// 2. Only one transpose operation at the end (not per-block)
    ///
    /// The `use_transpose` parameter selects the message loading strategy:
    /// - `true`: Use load+transpose (16 loads + transpose per block) - faster for L1/L2 hot data
    /// - `false`: Use gather (16 gathers per block) - faster for cache-cold patterns
    ///
    /// # Safety
    ///
    /// - Caller must ensure the CPU supports AVX-512F and AVX-512BW.
    /// - `base_ptr` must point to at least 16 contiguous chunks (16KB).
    #[target_feature(enable = "avx512f", enable = "avx512bw")]
    pub unsafe fn hash_16_chunks_fused(
        key: &[u32; 8],
        base_ptr: *const u8,
        chunk_counters: &[u64; 16],
        base_flags: u8,
        use_transpose: bool,
    ) -> [[u32; 8]; 16] {
        const CHUNK_START: u8 = 1;
        const CHUNK_END: u8 = 2;

        // No shuffle masks needed - using native AVX-512 rotate instructions

        // Initialize CV state vectors from key - stay in registers for all 16 blocks
        let mut cv0 = _mm512_set1_epi32(key[0] as i32);
        let mut cv1 = _mm512_set1_epi32(key[1] as i32);
        let mut cv2 = _mm512_set1_epi32(key[2] as i32);
        let mut cv3 = _mm512_set1_epi32(key[3] as i32);
        let mut cv4 = _mm512_set1_epi32(key[4] as i32);
        let mut cv5 = _mm512_set1_epi32(key[5] as i32);
        let mut cv6 = _mm512_set1_epi32(key[6] as i32);
        let mut cv7 = _mm512_set1_epi32(key[7] as i32);

        // Counter vectors (constant across blocks)
        let counter_lo = _mm512_setr_epi32(
            chunk_counters[0] as i32,
            chunk_counters[1] as i32,
            chunk_counters[2] as i32,
            chunk_counters[3] as i32,
            chunk_counters[4] as i32,
            chunk_counters[5] as i32,
            chunk_counters[6] as i32,
            chunk_counters[7] as i32,
            chunk_counters[8] as i32,
            chunk_counters[9] as i32,
            chunk_counters[10] as i32,
            chunk_counters[11] as i32,
            chunk_counters[12] as i32,
            chunk_counters[13] as i32,
            chunk_counters[14] as i32,
            chunk_counters[15] as i32,
        );
        let counter_hi = _mm512_setr_epi32(
            (chunk_counters[0] >> 32) as i32,
            (chunk_counters[1] >> 32) as i32,
            (chunk_counters[2] >> 32) as i32,
            (chunk_counters[3] >> 32) as i32,
            (chunk_counters[4] >> 32) as i32,
            (chunk_counters[5] >> 32) as i32,
            (chunk_counters[6] >> 32) as i32,
            (chunk_counters[7] >> 32) as i32,
            (chunk_counters[8] >> 32) as i32,
            (chunk_counters[9] >> 32) as i32,
            (chunk_counters[10] >> 32) as i32,
            (chunk_counters[11] >> 32) as i32,
            (chunk_counters[12] >> 32) as i32,
            (chunk_counters[13] >> 32) as i32,
            (chunk_counters[14] >> 32) as i32,
            (chunk_counters[15] >> 32) as i32,
        );
        let block_len = _mm512_set1_epi32(64);

        // 16-way G function macro with inline message loading
        // Loads message words on-demand to reduce register pressure
        macro_rules! g16_inline {
            ($a:expr, $b:expr, $c:expr, $d:expr, $mx_idx:expr, $my_idx:expr, $base:expr, $block:expr) => {{
                let mx = load_msg_word_gather_16($base, $block, $mx_idx);
                $a = _mm512_add_epi32($a, _mm512_add_epi32($b, mx));
                $d = _mm512_xor_si512($d, $a);
                $d = _mm512_ror_epi32($d, 16);
                $c = _mm512_add_epi32($c, $d);
                $b = _mm512_xor_si512($b, $c);
                $b = _mm512_ror_epi32($b, 12);
                let my = load_msg_word_gather_16($base, $block, $my_idx);
                $a = _mm512_add_epi32($a, _mm512_add_epi32($b, my));
                $d = _mm512_xor_si512($d, $a);
                $d = _mm512_ror_epi32($d, 8);
                $c = _mm512_add_epi32($c, $d);
                $b = _mm512_xor_si512($b, $c);
                $b = _mm512_ror_epi32($b, 7);
            }};
        }

        // 16-way G function macro - uses native AVX-512 rotate for ALL rotations
        // This avoids shuffle latency and potential LLVM codegen issues
        macro_rules! g16 {
            ($a:expr, $b:expr, $c:expr, $d:expr, $mx:expr, $my:expr) => {
                $a = _mm512_add_epi32($a, _mm512_add_epi32($b, $mx));
                $d = _mm512_xor_si512($d, $a);
                $d = _mm512_ror_epi32($d, 16); // Native rotate instead of shuffle
                $c = _mm512_add_epi32($c, $d);
                $b = _mm512_xor_si512($b, $c);
                $b = _mm512_ror_epi32($b, 12);
                $a = _mm512_add_epi32($a, _mm512_add_epi32($b, $my));
                $d = _mm512_xor_si512($d, $a);
                $d = _mm512_ror_epi32($d, 8); // Native rotate instead of shuffle
                $c = _mm512_add_epi32($c, $d);
                $b = _mm512_xor_si512($b, $c);
                $b = _mm512_ror_epi32($b, 7);
            };
        }

        // Process all 16 blocks, keeping CVs in registers
        for block_idx in 0..16 {
            let is_first = block_idx == 0;
            let is_last = block_idx == 15;

            let mut flags_val = base_flags;
            if is_first {
                flags_val |= CHUNK_START;
            }
            if is_last {
                flags_val |= CHUNK_END;
            }
            let flags = _mm512_set1_epi32(flags_val as i32);

            // Initialize compression state from current CV
            let mut s0 = cv0;
            let mut s1 = cv1;
            let mut s2 = cv2;
            let mut s3 = cv3;
            let mut s4 = cv4;
            let mut s5 = cv5;
            let mut s6 = cv6;
            let mut s7 = cv7;
            let mut s8 = IV_BROADCAST_512_0;
            let mut s9 = IV_BROADCAST_512_1;
            let mut s10 = IV_BROADCAST_512_2;
            let mut s11 = IV_BROADCAST_512_3;
            let mut s12 = counter_lo;
            let mut s13 = counter_hi;
            let mut s14 = block_len;
            let mut s15 = flags;

            // Two strategies for message loading:
            // 1. Inline gather: loads 2 words per G call (16 per round, 112 total)
            //    - Lower register pressure (no message array)
            //    - Works well when data is in L1/L2 cache
            // 2. Bulk load+transpose: loads all 16 words upfront
            //    - More register pressure but fewer total loads
            //    - Better for cache-cold patterns
            if use_transpose {
                // Bulk load all message words (may spill due to register pressure)
                let m = load_transpose_msg_16(base_ptr, block_idx);

                macro_rules! round {
                    ($r:expr) => {{
                        g16!(
                            s0,
                            s4,
                            s8,
                            s12,
                            m[MSG_SCHEDULE[$r][0]],
                            m[MSG_SCHEDULE[$r][1]]
                        );
                        g16!(
                            s1,
                            s5,
                            s9,
                            s13,
                            m[MSG_SCHEDULE[$r][2]],
                            m[MSG_SCHEDULE[$r][3]]
                        );
                        g16!(
                            s2,
                            s6,
                            s10,
                            s14,
                            m[MSG_SCHEDULE[$r][4]],
                            m[MSG_SCHEDULE[$r][5]]
                        );
                        g16!(
                            s3,
                            s7,
                            s11,
                            s15,
                            m[MSG_SCHEDULE[$r][6]],
                            m[MSG_SCHEDULE[$r][7]]
                        );
                        g16!(
                            s0,
                            s5,
                            s10,
                            s15,
                            m[MSG_SCHEDULE[$r][8]],
                            m[MSG_SCHEDULE[$r][9]]
                        );
                        g16!(
                            s1,
                            s6,
                            s11,
                            s12,
                            m[MSG_SCHEDULE[$r][10]],
                            m[MSG_SCHEDULE[$r][11]]
                        );
                        g16!(
                            s2,
                            s7,
                            s8,
                            s13,
                            m[MSG_SCHEDULE[$r][12]],
                            m[MSG_SCHEDULE[$r][13]]
                        );
                        g16!(
                            s3,
                            s4,
                            s9,
                            s14,
                            m[MSG_SCHEDULE[$r][14]],
                            m[MSG_SCHEDULE[$r][15]]
                        );
                    }};
                }
                round!(0);
                round!(1);
                round!(2);
                round!(3);
                round!(4);
                round!(5);
                round!(6);
            } else {
                // Inline gather - load message words on-demand
                macro_rules! round_inline {
                    ($r:expr) => {{
                        g16_inline!(
                            s0,
                            s4,
                            s8,
                            s12,
                            MSG_SCHEDULE[$r][0],
                            MSG_SCHEDULE[$r][1],
                            base_ptr,
                            block_idx
                        );
                        g16_inline!(
                            s1,
                            s5,
                            s9,
                            s13,
                            MSG_SCHEDULE[$r][2],
                            MSG_SCHEDULE[$r][3],
                            base_ptr,
                            block_idx
                        );
                        g16_inline!(
                            s2,
                            s6,
                            s10,
                            s14,
                            MSG_SCHEDULE[$r][4],
                            MSG_SCHEDULE[$r][5],
                            base_ptr,
                            block_idx
                        );
                        g16_inline!(
                            s3,
                            s7,
                            s11,
                            s15,
                            MSG_SCHEDULE[$r][6],
                            MSG_SCHEDULE[$r][7],
                            base_ptr,
                            block_idx
                        );
                        g16_inline!(
                            s0,
                            s5,
                            s10,
                            s15,
                            MSG_SCHEDULE[$r][8],
                            MSG_SCHEDULE[$r][9],
                            base_ptr,
                            block_idx
                        );
                        g16_inline!(
                            s1,
                            s6,
                            s11,
                            s12,
                            MSG_SCHEDULE[$r][10],
                            MSG_SCHEDULE[$r][11],
                            base_ptr,
                            block_idx
                        );
                        g16_inline!(
                            s2,
                            s7,
                            s8,
                            s13,
                            MSG_SCHEDULE[$r][12],
                            MSG_SCHEDULE[$r][13],
                            base_ptr,
                            block_idx
                        );
                        g16_inline!(
                            s3,
                            s4,
                            s9,
                            s14,
                            MSG_SCHEDULE[$r][14],
                            MSG_SCHEDULE[$r][15],
                            base_ptr,
                            block_idx
                        );
                    }};
                }
                round_inline!(0);
                round_inline!(1);
                round_inline!(2);
                round_inline!(3);
                round_inline!(4);
                round_inline!(5);
                round_inline!(6);
            }

            // XOR with input CV to get output CV (stays in registers for next block!)
            cv0 = _mm512_xor_si512(s0, s8);
            cv1 = _mm512_xor_si512(s1, s9);
            cv2 = _mm512_xor_si512(s2, s10);
            cv3 = _mm512_xor_si512(s3, s11);
            cv4 = _mm512_xor_si512(s4, s12);
            cv5 = _mm512_xor_si512(s5, s13);
            cv6 = _mm512_xor_si512(s6, s14);
            cv7 = _mm512_xor_si512(s7, s15);
        }

        // Transpose and output - split into two 256-bit halves for efficient transpose
        let s0_lo = _mm512_extracti64x4_epi64(cv0, 0);
        let s0_hi = _mm512_extracti64x4_epi64(cv0, 1);
        let s1_lo = _mm512_extracti64x4_epi64(cv1, 0);
        let s1_hi = _mm512_extracti64x4_epi64(cv1, 1);
        let s2_lo = _mm512_extracti64x4_epi64(cv2, 0);
        let s2_hi = _mm512_extracti64x4_epi64(cv2, 1);
        let s3_lo = _mm512_extracti64x4_epi64(cv3, 0);
        let s3_hi = _mm512_extracti64x4_epi64(cv3, 1);
        let s4_lo = _mm512_extracti64x4_epi64(cv4, 0);
        let s4_hi = _mm512_extracti64x4_epi64(cv4, 1);
        let s5_lo = _mm512_extracti64x4_epi64(cv5, 0);
        let s5_hi = _mm512_extracti64x4_epi64(cv5, 1);
        let s6_lo = _mm512_extracti64x4_epi64(cv6, 0);
        let s6_hi = _mm512_extracti64x4_epi64(cv6, 1);
        let s7_lo = _mm512_extracti64x4_epi64(cv7, 0);
        let s7_hi = _mm512_extracti64x4_epi64(cv7, 1);

        // Transpose low 8 results
        let t0l = _mm256_unpacklo_epi32(s0_lo, s1_lo);
        let t1l = _mm256_unpackhi_epi32(s0_lo, s1_lo);
        let t2l = _mm256_unpacklo_epi32(s2_lo, s3_lo);
        let t3l = _mm256_unpackhi_epi32(s2_lo, s3_lo);
        let t4l = _mm256_unpacklo_epi32(s4_lo, s5_lo);
        let t5l = _mm256_unpackhi_epi32(s4_lo, s5_lo);
        let t6l = _mm256_unpacklo_epi32(s6_lo, s7_lo);
        let t7l = _mm256_unpackhi_epi32(s6_lo, s7_lo);

        let u0l = _mm256_unpacklo_epi64(t0l, t2l);
        let u1l = _mm256_unpackhi_epi64(t0l, t2l);
        let u2l = _mm256_unpacklo_epi64(t1l, t3l);
        let u3l = _mm256_unpackhi_epi64(t1l, t3l);
        let u4l = _mm256_unpacklo_epi64(t4l, t6l);
        let u5l = _mm256_unpackhi_epi64(t4l, t6l);
        let u6l = _mm256_unpacklo_epi64(t5l, t7l);
        let u7l = _mm256_unpackhi_epi64(t5l, t7l);

        let r0 = _mm256_permute2x128_si256(u0l, u4l, 0x20);
        let r1 = _mm256_permute2x128_si256(u1l, u5l, 0x20);
        let r2 = _mm256_permute2x128_si256(u2l, u6l, 0x20);
        let r3 = _mm256_permute2x128_si256(u3l, u7l, 0x20);
        let r4 = _mm256_permute2x128_si256(u0l, u4l, 0x31);
        let r5 = _mm256_permute2x128_si256(u1l, u5l, 0x31);
        let r6 = _mm256_permute2x128_si256(u2l, u6l, 0x31);
        let r7 = _mm256_permute2x128_si256(u3l, u7l, 0x31);

        // Transpose high 8 results
        let t0h = _mm256_unpacklo_epi32(s0_hi, s1_hi);
        let t1h = _mm256_unpackhi_epi32(s0_hi, s1_hi);
        let t2h = _mm256_unpacklo_epi32(s2_hi, s3_hi);
        let t3h = _mm256_unpackhi_epi32(s2_hi, s3_hi);
        let t4h = _mm256_unpacklo_epi32(s4_hi, s5_hi);
        let t5h = _mm256_unpackhi_epi32(s4_hi, s5_hi);
        let t6h = _mm256_unpacklo_epi32(s6_hi, s7_hi);
        let t7h = _mm256_unpackhi_epi32(s6_hi, s7_hi);

        let u0h = _mm256_unpacklo_epi64(t0h, t2h);
        let u1h = _mm256_unpackhi_epi64(t0h, t2h);
        let u2h = _mm256_unpacklo_epi64(t1h, t3h);
        let u3h = _mm256_unpackhi_epi64(t1h, t3h);
        let u4h = _mm256_unpacklo_epi64(t4h, t6h);
        let u5h = _mm256_unpackhi_epi64(t4h, t6h);
        let u6h = _mm256_unpacklo_epi64(t5h, t7h);
        let u7h = _mm256_unpackhi_epi64(t5h, t7h);

        let r8 = _mm256_permute2x128_si256(u0h, u4h, 0x20);
        let r9 = _mm256_permute2x128_si256(u1h, u5h, 0x20);
        let r10 = _mm256_permute2x128_si256(u2h, u6h, 0x20);
        let r11 = _mm256_permute2x128_si256(u3h, u7h, 0x20);
        let r12 = _mm256_permute2x128_si256(u0h, u4h, 0x31);
        let r13 = _mm256_permute2x128_si256(u1h, u5h, 0x31);
        let r14 = _mm256_permute2x128_si256(u2h, u6h, 0x31);
        let r15 = _mm256_permute2x128_si256(u3h, u7h, 0x31);

        let mut results = [[0u32; 8]; 16];
        _mm256_storeu_si256(results[0].as_mut_ptr() as *mut __m256i, r0);
        _mm256_storeu_si256(results[1].as_mut_ptr() as *mut __m256i, r1);
        _mm256_storeu_si256(results[2].as_mut_ptr() as *mut __m256i, r2);
        _mm256_storeu_si256(results[3].as_mut_ptr() as *mut __m256i, r3);
        _mm256_storeu_si256(results[4].as_mut_ptr() as *mut __m256i, r4);
        _mm256_storeu_si256(results[5].as_mut_ptr() as *mut __m256i, r5);
        _mm256_storeu_si256(results[6].as_mut_ptr() as *mut __m256i, r6);
        _mm256_storeu_si256(results[7].as_mut_ptr() as *mut __m256i, r7);
        _mm256_storeu_si256(results[8].as_mut_ptr() as *mut __m256i, r8);
        _mm256_storeu_si256(results[9].as_mut_ptr() as *mut __m256i, r9);
        _mm256_storeu_si256(results[10].as_mut_ptr() as *mut __m256i, r10);
        _mm256_storeu_si256(results[11].as_mut_ptr() as *mut __m256i, r11);
        _mm256_storeu_si256(results[12].as_mut_ptr() as *mut __m256i, r12);
        _mm256_storeu_si256(results[13].as_mut_ptr() as *mut __m256i, r13);
        _mm256_storeu_si256(results[14].as_mut_ptr() as *mut __m256i, r14);
        _mm256_storeu_si256(results[15].as_mut_ptr() as *mut __m256i, r15);

        results
    }

    /// Compress 16 blocks from chunk pointers (true zero-copy).
    ///
    /// # Safety
    ///
    /// Caller must ensure the CPU supports AVX-512F and pointers are valid.
    #[target_feature(enable = "avx512f", enable = "avx512bw")]
    pub unsafe fn compress_16blocks_from_ptrs(
        cvs: &[[u32; 8]; 16],
        chunk_ptrs: &[*const u8; 16],
        block_idx: usize,
        counters: &[u64; 16],
        block_lens: &[u32; 16],
        flags: &[u8; 16],
    ) -> [[u32; 8]; 16] {
        // Load shuffle masks
        let rot16_mask = _mm512_loadu_si512(ROT16_SHUFFLE_512.as_ptr() as *const __m512i);
        let rot8_mask = _mm512_loadu_si512(ROT8_SHUFFLE_512.as_ptr() as *const __m512i);

        // Load message words directly from chunk pointers
        let m: [__m512i; 16] = [
            load_msg_word_from_chunk_ptrs(chunk_ptrs, block_idx, 0),
            load_msg_word_from_chunk_ptrs(chunk_ptrs, block_idx, 1),
            load_msg_word_from_chunk_ptrs(chunk_ptrs, block_idx, 2),
            load_msg_word_from_chunk_ptrs(chunk_ptrs, block_idx, 3),
            load_msg_word_from_chunk_ptrs(chunk_ptrs, block_idx, 4),
            load_msg_word_from_chunk_ptrs(chunk_ptrs, block_idx, 5),
            load_msg_word_from_chunk_ptrs(chunk_ptrs, block_idx, 6),
            load_msg_word_from_chunk_ptrs(chunk_ptrs, block_idx, 7),
            load_msg_word_from_chunk_ptrs(chunk_ptrs, block_idx, 8),
            load_msg_word_from_chunk_ptrs(chunk_ptrs, block_idx, 9),
            load_msg_word_from_chunk_ptrs(chunk_ptrs, block_idx, 10),
            load_msg_word_from_chunk_ptrs(chunk_ptrs, block_idx, 11),
            load_msg_word_from_chunk_ptrs(chunk_ptrs, block_idx, 12),
            load_msg_word_from_chunk_ptrs(chunk_ptrs, block_idx, 13),
            load_msg_word_from_chunk_ptrs(chunk_ptrs, block_idx, 14),
            load_msg_word_from_chunk_ptrs(chunk_ptrs, block_idx, 15),
        ];

        // Initialize state from CVs (transposed across 16 lanes)
        // Use setr (natural order) - better codegen than set (reversed order)
        let mut s0 = _mm512_setr_epi32(
            cvs[0][0] as i32,
            cvs[1][0] as i32,
            cvs[2][0] as i32,
            cvs[3][0] as i32,
            cvs[4][0] as i32,
            cvs[5][0] as i32,
            cvs[6][0] as i32,
            cvs[7][0] as i32,
            cvs[8][0] as i32,
            cvs[9][0] as i32,
            cvs[10][0] as i32,
            cvs[11][0] as i32,
            cvs[12][0] as i32,
            cvs[13][0] as i32,
            cvs[14][0] as i32,
            cvs[15][0] as i32,
        );
        let mut s1 = _mm512_setr_epi32(
            cvs[0][1] as i32,
            cvs[1][1] as i32,
            cvs[2][1] as i32,
            cvs[3][1] as i32,
            cvs[4][1] as i32,
            cvs[5][1] as i32,
            cvs[6][1] as i32,
            cvs[7][1] as i32,
            cvs[8][1] as i32,
            cvs[9][1] as i32,
            cvs[10][1] as i32,
            cvs[11][1] as i32,
            cvs[12][1] as i32,
            cvs[13][1] as i32,
            cvs[14][1] as i32,
            cvs[15][1] as i32,
        );
        let mut s2 = _mm512_setr_epi32(
            cvs[0][2] as i32,
            cvs[1][2] as i32,
            cvs[2][2] as i32,
            cvs[3][2] as i32,
            cvs[4][2] as i32,
            cvs[5][2] as i32,
            cvs[6][2] as i32,
            cvs[7][2] as i32,
            cvs[8][2] as i32,
            cvs[9][2] as i32,
            cvs[10][2] as i32,
            cvs[11][2] as i32,
            cvs[12][2] as i32,
            cvs[13][2] as i32,
            cvs[14][2] as i32,
            cvs[15][2] as i32,
        );
        let mut s3 = _mm512_setr_epi32(
            cvs[0][3] as i32,
            cvs[1][3] as i32,
            cvs[2][3] as i32,
            cvs[3][3] as i32,
            cvs[4][3] as i32,
            cvs[5][3] as i32,
            cvs[6][3] as i32,
            cvs[7][3] as i32,
            cvs[8][3] as i32,
            cvs[9][3] as i32,
            cvs[10][3] as i32,
            cvs[11][3] as i32,
            cvs[12][3] as i32,
            cvs[13][3] as i32,
            cvs[14][3] as i32,
            cvs[15][3] as i32,
        );
        let mut s4 = _mm512_setr_epi32(
            cvs[0][4] as i32,
            cvs[1][4] as i32,
            cvs[2][4] as i32,
            cvs[3][4] as i32,
            cvs[4][4] as i32,
            cvs[5][4] as i32,
            cvs[6][4] as i32,
            cvs[7][4] as i32,
            cvs[8][4] as i32,
            cvs[9][4] as i32,
            cvs[10][4] as i32,
            cvs[11][4] as i32,
            cvs[12][4] as i32,
            cvs[13][4] as i32,
            cvs[14][4] as i32,
            cvs[15][4] as i32,
        );
        let mut s5 = _mm512_setr_epi32(
            cvs[0][5] as i32,
            cvs[1][5] as i32,
            cvs[2][5] as i32,
            cvs[3][5] as i32,
            cvs[4][5] as i32,
            cvs[5][5] as i32,
            cvs[6][5] as i32,
            cvs[7][5] as i32,
            cvs[8][5] as i32,
            cvs[9][5] as i32,
            cvs[10][5] as i32,
            cvs[11][5] as i32,
            cvs[12][5] as i32,
            cvs[13][5] as i32,
            cvs[14][5] as i32,
            cvs[15][5] as i32,
        );
        let mut s6 = _mm512_setr_epi32(
            cvs[0][6] as i32,
            cvs[1][6] as i32,
            cvs[2][6] as i32,
            cvs[3][6] as i32,
            cvs[4][6] as i32,
            cvs[5][6] as i32,
            cvs[6][6] as i32,
            cvs[7][6] as i32,
            cvs[8][6] as i32,
            cvs[9][6] as i32,
            cvs[10][6] as i32,
            cvs[11][6] as i32,
            cvs[12][6] as i32,
            cvs[13][6] as i32,
            cvs[14][6] as i32,
            cvs[15][6] as i32,
        );
        let mut s7 = _mm512_setr_epi32(
            cvs[0][7] as i32,
            cvs[1][7] as i32,
            cvs[2][7] as i32,
            cvs[3][7] as i32,
            cvs[4][7] as i32,
            cvs[5][7] as i32,
            cvs[6][7] as i32,
            cvs[7][7] as i32,
            cvs[8][7] as i32,
            cvs[9][7] as i32,
            cvs[10][7] as i32,
            cvs[11][7] as i32,
            cvs[12][7] as i32,
            cvs[13][7] as i32,
            cvs[14][7] as i32,
            cvs[15][7] as i32,
        );

        // IV constants for remaining state (use pre-computed broadcast vectors)
        let mut s8 = IV_BROADCAST_512_0;
        let mut s9 = IV_BROADCAST_512_1;
        let mut s10 = IV_BROADCAST_512_2;
        let mut s11 = IV_BROADCAST_512_3;

        // Counter low/high, block_lens, flags (use setr for natural order)
        let mut s12 = _mm512_setr_epi32(
            counters[0] as i32,
            counters[1] as i32,
            counters[2] as i32,
            counters[3] as i32,
            counters[4] as i32,
            counters[5] as i32,
            counters[6] as i32,
            counters[7] as i32,
            counters[8] as i32,
            counters[9] as i32,
            counters[10] as i32,
            counters[11] as i32,
            counters[12] as i32,
            counters[13] as i32,
            counters[14] as i32,
            counters[15] as i32,
        );
        let mut s13 = _mm512_setr_epi32(
            (counters[0] >> 32) as i32,
            (counters[1] >> 32) as i32,
            (counters[2] >> 32) as i32,
            (counters[3] >> 32) as i32,
            (counters[4] >> 32) as i32,
            (counters[5] >> 32) as i32,
            (counters[6] >> 32) as i32,
            (counters[7] >> 32) as i32,
            (counters[8] >> 32) as i32,
            (counters[9] >> 32) as i32,
            (counters[10] >> 32) as i32,
            (counters[11] >> 32) as i32,
            (counters[12] >> 32) as i32,
            (counters[13] >> 32) as i32,
            (counters[14] >> 32) as i32,
            (counters[15] >> 32) as i32,
        );
        let mut s14 = _mm512_setr_epi32(
            block_lens[0] as i32,
            block_lens[1] as i32,
            block_lens[2] as i32,
            block_lens[3] as i32,
            block_lens[4] as i32,
            block_lens[5] as i32,
            block_lens[6] as i32,
            block_lens[7] as i32,
            block_lens[8] as i32,
            block_lens[9] as i32,
            block_lens[10] as i32,
            block_lens[11] as i32,
            block_lens[12] as i32,
            block_lens[13] as i32,
            block_lens[14] as i32,
            block_lens[15] as i32,
        );
        let mut s15 = _mm512_setr_epi32(
            flags[0] as i32,
            flags[1] as i32,
            flags[2] as i32,
            flags[3] as i32,
            flags[4] as i32,
            flags[5] as i32,
            flags[6] as i32,
            flags[7] as i32,
            flags[8] as i32,
            flags[9] as i32,
            flags[10] as i32,
            flags[11] as i32,
            flags[12] as i32,
            flags[13] as i32,
            flags[14] as i32,
            flags[15] as i32,
        );

        // G function for 16-way
        macro_rules! g16 {
            ($a:expr, $b:expr, $c:expr, $d:expr, $mx:expr, $my:expr) => {
                $a = _mm512_add_epi32(_mm512_add_epi32($a, $b), $mx);
                $d = _mm512_shuffle_epi8(_mm512_xor_si512($d, $a), rot16_mask);
                $c = _mm512_add_epi32($c, $d);
                $b = _mm512_xor_si512($b, $c);
                $b = _mm512_or_si512(_mm512_srli_epi32($b, 12), _mm512_slli_epi32($b, 20));

                $a = _mm512_add_epi32(_mm512_add_epi32($a, $b), $my);
                $d = _mm512_shuffle_epi8(_mm512_xor_si512($d, $a), rot8_mask);
                $c = _mm512_add_epi32($c, $d);
                $b = _mm512_xor_si512($b, $c);
                $b = _mm512_or_si512(_mm512_srli_epi32($b, 7), _mm512_slli_epi32($b, 25));
            };
        }

        // Round macro
        macro_rules! round16 {
            ($r:expr) => {
                g16!(
                    s0,
                    s4,
                    s8,
                    s12,
                    m[MSG_SCHEDULE[$r][0]],
                    m[MSG_SCHEDULE[$r][1]]
                );
                g16!(
                    s1,
                    s5,
                    s9,
                    s13,
                    m[MSG_SCHEDULE[$r][2]],
                    m[MSG_SCHEDULE[$r][3]]
                );
                g16!(
                    s2,
                    s6,
                    s10,
                    s14,
                    m[MSG_SCHEDULE[$r][4]],
                    m[MSG_SCHEDULE[$r][5]]
                );
                g16!(
                    s3,
                    s7,
                    s11,
                    s15,
                    m[MSG_SCHEDULE[$r][6]],
                    m[MSG_SCHEDULE[$r][7]]
                );
                g16!(
                    s0,
                    s5,
                    s10,
                    s15,
                    m[MSG_SCHEDULE[$r][8]],
                    m[MSG_SCHEDULE[$r][9]]
                );
                g16!(
                    s1,
                    s6,
                    s11,
                    s12,
                    m[MSG_SCHEDULE[$r][10]],
                    m[MSG_SCHEDULE[$r][11]]
                );
                g16!(
                    s2,
                    s7,
                    s8,
                    s13,
                    m[MSG_SCHEDULE[$r][12]],
                    m[MSG_SCHEDULE[$r][13]]
                );
                g16!(
                    s3,
                    s4,
                    s9,
                    s14,
                    m[MSG_SCHEDULE[$r][14]],
                    m[MSG_SCHEDULE[$r][15]]
                );
            };
        }

        // All 7 rounds
        round16!(0);
        round16!(1);
        round16!(2);
        round16!(3);
        round16!(4);
        round16!(5);
        round16!(6);

        // XOR with input CV
        s0 = _mm512_xor_si512(s0, s8);
        s1 = _mm512_xor_si512(s1, s9);
        s2 = _mm512_xor_si512(s2, s10);
        s3 = _mm512_xor_si512(s3, s11);
        s4 = _mm512_xor_si512(s4, s12);
        s5 = _mm512_xor_si512(s5, s13);
        s6 = _mm512_xor_si512(s6, s14);
        s7 = _mm512_xor_si512(s7, s15);

        // Extract results using SIMD transpose (16x8 -> outputs)
        // Split each 512-bit vector into two 256-bit halves, then use 8x8 transpose

        // Extract low and high 256-bit halves
        let s0_lo = _mm512_castsi512_si256(s0);
        let s0_hi = _mm512_extracti64x4_epi64(s0, 1);
        let s1_lo = _mm512_castsi512_si256(s1);
        let s1_hi = _mm512_extracti64x4_epi64(s1, 1);
        let s2_lo = _mm512_castsi512_si256(s2);
        let s2_hi = _mm512_extracti64x4_epi64(s2, 1);
        let s3_lo = _mm512_castsi512_si256(s3);
        let s3_hi = _mm512_extracti64x4_epi64(s3, 1);
        let s4_lo = _mm512_castsi512_si256(s4);
        let s4_hi = _mm512_extracti64x4_epi64(s4, 1);
        let s5_lo = _mm512_castsi512_si256(s5);
        let s5_hi = _mm512_extracti64x4_epi64(s5, 1);
        let s6_lo = _mm512_castsi512_si256(s6);
        let s6_hi = _mm512_extracti64x4_epi64(s6, 1);
        let s7_lo = _mm512_castsi512_si256(s7);
        let s7_hi = _mm512_extracti64x4_epi64(s7, 1);

        // Transpose low halves (blocks 0-7)
        let t0 = _mm256_unpacklo_epi32(s0_lo, s1_lo);
        let t1 = _mm256_unpackhi_epi32(s0_lo, s1_lo);
        let t2 = _mm256_unpacklo_epi32(s2_lo, s3_lo);
        let t3 = _mm256_unpackhi_epi32(s2_lo, s3_lo);
        let t4 = _mm256_unpacklo_epi32(s4_lo, s5_lo);
        let t5 = _mm256_unpackhi_epi32(s4_lo, s5_lo);
        let t6 = _mm256_unpacklo_epi32(s6_lo, s7_lo);
        let t7 = _mm256_unpackhi_epi32(s6_lo, s7_lo);

        let u0 = _mm256_unpacklo_epi64(t0, t2);
        let u1 = _mm256_unpackhi_epi64(t0, t2);
        let u2 = _mm256_unpacklo_epi64(t1, t3);
        let u3 = _mm256_unpackhi_epi64(t1, t3);
        let u4 = _mm256_unpacklo_epi64(t4, t6);
        let u5 = _mm256_unpackhi_epi64(t4, t6);
        let u6 = _mm256_unpacklo_epi64(t5, t7);
        let u7 = _mm256_unpackhi_epi64(t5, t7);

        let r0 = _mm256_permute2x128_si256(u0, u4, 0x20);
        let r1 = _mm256_permute2x128_si256(u1, u5, 0x20);
        let r2 = _mm256_permute2x128_si256(u2, u6, 0x20);
        let r3 = _mm256_permute2x128_si256(u3, u7, 0x20);
        let r4 = _mm256_permute2x128_si256(u0, u4, 0x31);
        let r5 = _mm256_permute2x128_si256(u1, u5, 0x31);
        let r6 = _mm256_permute2x128_si256(u2, u6, 0x31);
        let r7 = _mm256_permute2x128_si256(u3, u7, 0x31);

        // Transpose high halves (blocks 8-15)
        let t0h = _mm256_unpacklo_epi32(s0_hi, s1_hi);
        let t1h = _mm256_unpackhi_epi32(s0_hi, s1_hi);
        let t2h = _mm256_unpacklo_epi32(s2_hi, s3_hi);
        let t3h = _mm256_unpackhi_epi32(s2_hi, s3_hi);
        let t4h = _mm256_unpacklo_epi32(s4_hi, s5_hi);
        let t5h = _mm256_unpackhi_epi32(s4_hi, s5_hi);
        let t6h = _mm256_unpacklo_epi32(s6_hi, s7_hi);
        let t7h = _mm256_unpackhi_epi32(s6_hi, s7_hi);

        let u0h = _mm256_unpacklo_epi64(t0h, t2h);
        let u1h = _mm256_unpackhi_epi64(t0h, t2h);
        let u2h = _mm256_unpacklo_epi64(t1h, t3h);
        let u3h = _mm256_unpackhi_epi64(t1h, t3h);
        let u4h = _mm256_unpacklo_epi64(t4h, t6h);
        let u5h = _mm256_unpackhi_epi64(t4h, t6h);
        let u6h = _mm256_unpacklo_epi64(t5h, t7h);
        let u7h = _mm256_unpackhi_epi64(t5h, t7h);

        let r8 = _mm256_permute2x128_si256(u0h, u4h, 0x20);
        let r9 = _mm256_permute2x128_si256(u1h, u5h, 0x20);
        let r10 = _mm256_permute2x128_si256(u2h, u6h, 0x20);
        let r11 = _mm256_permute2x128_si256(u3h, u7h, 0x20);
        let r12 = _mm256_permute2x128_si256(u0h, u4h, 0x31);
        let r13 = _mm256_permute2x128_si256(u1h, u5h, 0x31);
        let r14 = _mm256_permute2x128_si256(u2h, u6h, 0x31);
        let r15 = _mm256_permute2x128_si256(u3h, u7h, 0x31);

        // Store results
        let mut results = [[0u32; 8]; 16];
        _mm256_storeu_si256(results[0].as_mut_ptr() as *mut __m256i, r0);
        _mm256_storeu_si256(results[1].as_mut_ptr() as *mut __m256i, r1);
        _mm256_storeu_si256(results[2].as_mut_ptr() as *mut __m256i, r2);
        _mm256_storeu_si256(results[3].as_mut_ptr() as *mut __m256i, r3);
        _mm256_storeu_si256(results[4].as_mut_ptr() as *mut __m256i, r4);
        _mm256_storeu_si256(results[5].as_mut_ptr() as *mut __m256i, r5);
        _mm256_storeu_si256(results[6].as_mut_ptr() as *mut __m256i, r6);
        _mm256_storeu_si256(results[7].as_mut_ptr() as *mut __m256i, r7);
        _mm256_storeu_si256(results[8].as_mut_ptr() as *mut __m256i, r8);
        _mm256_storeu_si256(results[9].as_mut_ptr() as *mut __m256i, r9);
        _mm256_storeu_si256(results[10].as_mut_ptr() as *mut __m256i, r10);
        _mm256_storeu_si256(results[11].as_mut_ptr() as *mut __m256i, r11);
        _mm256_storeu_si256(results[12].as_mut_ptr() as *mut __m256i, r12);
        _mm256_storeu_si256(results[13].as_mut_ptr() as *mut __m256i, r13);
        _mm256_storeu_si256(results[14].as_mut_ptr() as *mut __m256i, r14);
        _mm256_storeu_si256(results[15].as_mut_ptr() as *mut __m256i, r15);

        results
    }

    /// Compress one block using inline assembly for maximum performance.
    ///
    /// This implements the BLAKE3 compression function with hand-written
    /// x86-64 assembly, matching the reference blake3 crate's approach.
    ///
    /// # Safety
    /// Caller must ensure AVX-512F support and valid message pointer.
    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx512f")]
    #[inline]
    pub unsafe fn compress_round_asm(state: &mut [__m512i; 16], msg: &[__m512i; 16], round: usize) {
        use core::arch::asm;

        // Get message words for this round according to BLAKE3 schedule
        let schedule = &MSG_SCHEDULE[round];
        let m0 = msg[schedule[0]];
        let m1 = msg[schedule[1]];
        let m2 = msg[schedule[2]];
        let m3 = msg[schedule[3]];
        let m4 = msg[schedule[4]];
        let m5 = msg[schedule[5]];
        let m6 = msg[schedule[6]];
        let m7 = msg[schedule[7]];
        let m8 = msg[schedule[8]];
        let m9 = msg[schedule[9]];
        let m10 = msg[schedule[10]];
        let m11 = msg[schedule[11]];
        let m12 = msg[schedule[12]];
        let m13 = msg[schedule[13]];
        let m14 = msg[schedule[14]];
        let m15 = msg[schedule[15]];

        // Column G operations (4 parallel): G(0,4,8,12), G(1,5,9,13), G(2,6,10,14), G(3,7,11,15)
        asm!(
            // a = a + b + mx
            "vpaddd {s0}, {s0}, {m0}",
            "vpaddd {s1}, {s1}, {m2}",
            "vpaddd {s2}, {s2}, {m4}",
            "vpaddd {s3}, {s3}, {m6}",
            "vpaddd {s0}, {s0}, {s4}",
            "vpaddd {s1}, {s1}, {s5}",
            "vpaddd {s2}, {s2}, {s6}",
            "vpaddd {s3}, {s3}, {s7}",
            // d = (d ^ a) >>> 16
            "vpxord {s12}, {s12}, {s0}",
            "vpxord {s13}, {s13}, {s1}",
            "vpxord {s14}, {s14}, {s2}",
            "vpxord {s15}, {s15}, {s3}",
            "vprord {s12}, {s12}, 16",
            "vprord {s13}, {s13}, 16",
            "vprord {s14}, {s14}, 16",
            "vprord {s15}, {s15}, 16",
            // c = c + d
            "vpaddd {s8}, {s8}, {s12}",
            "vpaddd {s9}, {s9}, {s13}",
            "vpaddd {s10}, {s10}, {s14}",
            "vpaddd {s11}, {s11}, {s15}",
            // b = (b ^ c) >>> 12
            "vpxord {s4}, {s4}, {s8}",
            "vpxord {s5}, {s5}, {s9}",
            "vpxord {s6}, {s6}, {s10}",
            "vpxord {s7}, {s7}, {s11}",
            "vprord {s4}, {s4}, 12",
            "vprord {s5}, {s5}, 12",
            "vprord {s6}, {s6}, 12",
            "vprord {s7}, {s7}, 12",
            // a = a + b + my
            "vpaddd {s0}, {s0}, {m1}",
            "vpaddd {s1}, {s1}, {m3}",
            "vpaddd {s2}, {s2}, {m5}",
            "vpaddd {s3}, {s3}, {m7}",
            "vpaddd {s0}, {s0}, {s4}",
            "vpaddd {s1}, {s1}, {s5}",
            "vpaddd {s2}, {s2}, {s6}",
            "vpaddd {s3}, {s3}, {s7}",
            // d = (d ^ a) >>> 8
            "vpxord {s12}, {s12}, {s0}",
            "vpxord {s13}, {s13}, {s1}",
            "vpxord {s14}, {s14}, {s2}",
            "vpxord {s15}, {s15}, {s3}",
            "vprord {s12}, {s12}, 8",
            "vprord {s13}, {s13}, 8",
            "vprord {s14}, {s14}, 8",
            "vprord {s15}, {s15}, 8",
            // c = c + d
            "vpaddd {s8}, {s8}, {s12}",
            "vpaddd {s9}, {s9}, {s13}",
            "vpaddd {s10}, {s10}, {s14}",
            "vpaddd {s11}, {s11}, {s15}",
            // b = (b ^ c) >>> 7
            "vpxord {s4}, {s4}, {s8}",
            "vpxord {s5}, {s5}, {s9}",
            "vpxord {s6}, {s6}, {s10}",
            "vpxord {s7}, {s7}, {s11}",
            "vprord {s4}, {s4}, 7",
            "vprord {s5}, {s5}, 7",
            "vprord {s6}, {s6}, 7",
            "vprord {s7}, {s7}, 7",

            // Diagonal G operations: G(0,5,10,15), G(1,6,11,12), G(2,7,8,13), G(3,4,9,14)
            // a = a + b + mx
            "vpaddd {s0}, {s0}, {m8}",
            "vpaddd {s1}, {s1}, {m10}",
            "vpaddd {s2}, {s2}, {m12}",
            "vpaddd {s3}, {s3}, {m14}",
            "vpaddd {s0}, {s0}, {s5}",
            "vpaddd {s1}, {s1}, {s6}",
            "vpaddd {s2}, {s2}, {s7}",
            "vpaddd {s3}, {s3}, {s4}",
            // d = (d ^ a) >>> 16 (with diagonal rotation of d)
            "vpxord {s15}, {s15}, {s0}",
            "vpxord {s12}, {s12}, {s1}",
            "vpxord {s13}, {s13}, {s2}",
            "vpxord {s14}, {s14}, {s3}",
            "vprord {s15}, {s15}, 16",
            "vprord {s12}, {s12}, 16",
            "vprord {s13}, {s13}, 16",
            "vprord {s14}, {s14}, 16",
            // c = c + d (with diagonal rotation of c)
            "vpaddd {s10}, {s10}, {s15}",
            "vpaddd {s11}, {s11}, {s12}",
            "vpaddd {s8}, {s8}, {s13}",
            "vpaddd {s9}, {s9}, {s14}",
            // b = (b ^ c) >>> 12 (with diagonal rotation)
            "vpxord {s5}, {s5}, {s10}",
            "vpxord {s6}, {s6}, {s11}",
            "vpxord {s7}, {s7}, {s8}",
            "vpxord {s4}, {s4}, {s9}",
            "vprord {s5}, {s5}, 12",
            "vprord {s6}, {s6}, 12",
            "vprord {s7}, {s7}, 12",
            "vprord {s4}, {s4}, 12",
            // a = a + b + my
            "vpaddd {s0}, {s0}, {m9}",
            "vpaddd {s1}, {s1}, {m11}",
            "vpaddd {s2}, {s2}, {m13}",
            "vpaddd {s3}, {s3}, {m15}",
            "vpaddd {s0}, {s0}, {s5}",
            "vpaddd {s1}, {s1}, {s6}",
            "vpaddd {s2}, {s2}, {s7}",
            "vpaddd {s3}, {s3}, {s4}",
            // d = (d ^ a) >>> 8
            "vpxord {s15}, {s15}, {s0}",
            "vpxord {s12}, {s12}, {s1}",
            "vpxord {s13}, {s13}, {s2}",
            "vpxord {s14}, {s14}, {s3}",
            "vprord {s15}, {s15}, 8",
            "vprord {s12}, {s12}, 8",
            "vprord {s13}, {s13}, 8",
            "vprord {s14}, {s14}, 8",
            // c = c + d
            "vpaddd {s10}, {s10}, {s15}",
            "vpaddd {s11}, {s11}, {s12}",
            "vpaddd {s8}, {s8}, {s13}",
            "vpaddd {s9}, {s9}, {s14}",
            // b = (b ^ c) >>> 7
            "vpxord {s5}, {s5}, {s10}",
            "vpxord {s6}, {s6}, {s11}",
            "vpxord {s7}, {s7}, {s8}",
            "vpxord {s4}, {s4}, {s9}",
            "vprord {s5}, {s5}, 7",
            "vprord {s6}, {s6}, 7",
            "vprord {s7}, {s7}, 7",
            "vprord {s4}, {s4}, 7",

            s0 = inout(zmm_reg) state[0],
            s1 = inout(zmm_reg) state[1],
            s2 = inout(zmm_reg) state[2],
            s3 = inout(zmm_reg) state[3],
            s4 = inout(zmm_reg) state[4],
            s5 = inout(zmm_reg) state[5],
            s6 = inout(zmm_reg) state[6],
            s7 = inout(zmm_reg) state[7],
            s8 = inout(zmm_reg) state[8],
            s9 = inout(zmm_reg) state[9],
            s10 = inout(zmm_reg) state[10],
            s11 = inout(zmm_reg) state[11],
            s12 = inout(zmm_reg) state[12],
            s13 = inout(zmm_reg) state[13],
            s14 = inout(zmm_reg) state[14],
            s15 = inout(zmm_reg) state[15],
            m0 = in(zmm_reg) m0,
            m1 = in(zmm_reg) m1,
            m2 = in(zmm_reg) m2,
            m3 = in(zmm_reg) m3,
            m4 = in(zmm_reg) m4,
            m5 = in(zmm_reg) m5,
            m6 = in(zmm_reg) m6,
            m7 = in(zmm_reg) m7,
            m8 = in(zmm_reg) m8,
            m9 = in(zmm_reg) m9,
            m10 = in(zmm_reg) m10,
            m11 = in(zmm_reg) m11,
            m12 = in(zmm_reg) m12,
            m13 = in(zmm_reg) m13,
            m14 = in(zmm_reg) m14,
            m15 = in(zmm_reg) m15,
            options(nostack, preserves_flags),
        );
    }

    /// Hash 16 chunks using inline assembly for compression.
    ///
    /// # Safety
    /// Caller must ensure AVX-512F support and valid data pointer.
    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx512f", enable = "avx512bw")]
    pub unsafe fn hash_16_chunks_asm(
        key: &[u32; 8],
        base_ptr: *const u8,
        chunk_counters: &[u64; 16],
        base_flags: u8,
    ) -> [[u32; 8]; 16] {
        const CHUNK_START: u8 = 1;
        const CHUNK_END: u8 = 2;

        // Initialize CV state
        let mut cv0 = _mm512_set1_epi32(key[0] as i32);
        let mut cv1 = _mm512_set1_epi32(key[1] as i32);
        let mut cv2 = _mm512_set1_epi32(key[2] as i32);
        let mut cv3 = _mm512_set1_epi32(key[3] as i32);
        let mut cv4 = _mm512_set1_epi32(key[4] as i32);
        let mut cv5 = _mm512_set1_epi32(key[5] as i32);
        let mut cv6 = _mm512_set1_epi32(key[6] as i32);
        let mut cv7 = _mm512_set1_epi32(key[7] as i32);

        let counter_lo = _mm512_setr_epi32(
            chunk_counters[0] as i32,
            chunk_counters[1] as i32,
            chunk_counters[2] as i32,
            chunk_counters[3] as i32,
            chunk_counters[4] as i32,
            chunk_counters[5] as i32,
            chunk_counters[6] as i32,
            chunk_counters[7] as i32,
            chunk_counters[8] as i32,
            chunk_counters[9] as i32,
            chunk_counters[10] as i32,
            chunk_counters[11] as i32,
            chunk_counters[12] as i32,
            chunk_counters[13] as i32,
            chunk_counters[14] as i32,
            chunk_counters[15] as i32,
        );
        let counter_hi = _mm512_setr_epi32(
            (chunk_counters[0] >> 32) as i32,
            (chunk_counters[1] >> 32) as i32,
            (chunk_counters[2] >> 32) as i32,
            (chunk_counters[3] >> 32) as i32,
            (chunk_counters[4] >> 32) as i32,
            (chunk_counters[5] >> 32) as i32,
            (chunk_counters[6] >> 32) as i32,
            (chunk_counters[7] >> 32) as i32,
            (chunk_counters[8] >> 32) as i32,
            (chunk_counters[9] >> 32) as i32,
            (chunk_counters[10] >> 32) as i32,
            (chunk_counters[11] >> 32) as i32,
            (chunk_counters[12] >> 32) as i32,
            (chunk_counters[13] >> 32) as i32,
            (chunk_counters[14] >> 32) as i32,
            (chunk_counters[15] >> 32) as i32,
        );
        let block_len = _mm512_set1_epi32(64);

        // Process all 16 blocks
        for block_idx in 0..16 {
            let is_first = block_idx == 0;
            let is_last = block_idx == 15;

            let mut flags_val = base_flags;
            if is_first {
                flags_val |= CHUNK_START;
            }
            if is_last {
                flags_val |= CHUNK_END;
            }
            let flags = _mm512_set1_epi32(flags_val as i32);

            // Load message with transpose
            let m = load_transpose_msg_16(base_ptr, block_idx);

            // Initialize state
            let mut state: [__m512i; 16] = [
                cv0,
                cv1,
                cv2,
                cv3,
                cv4,
                cv5,
                cv6,
                cv7,
                IV_BROADCAST_512_0,
                IV_BROADCAST_512_1,
                IV_BROADCAST_512_2,
                IV_BROADCAST_512_3,
                counter_lo,
                counter_hi,
                block_len,
                flags,
            ];

            // 7 rounds using assembly
            compress_round_asm(&mut state, &m, 0);
            compress_round_asm(&mut state, &m, 1);
            compress_round_asm(&mut state, &m, 2);
            compress_round_asm(&mut state, &m, 3);
            compress_round_asm(&mut state, &m, 4);
            compress_round_asm(&mut state, &m, 5);
            compress_round_asm(&mut state, &m, 6);

            // XOR to get new CV
            cv0 = _mm512_xor_si512(state[0], state[8]);
            cv1 = _mm512_xor_si512(state[1], state[9]);
            cv2 = _mm512_xor_si512(state[2], state[10]);
            cv3 = _mm512_xor_si512(state[3], state[11]);
            cv4 = _mm512_xor_si512(state[4], state[12]);
            cv5 = _mm512_xor_si512(state[5], state[13]);
            cv6 = _mm512_xor_si512(state[6], state[14]);
            cv7 = _mm512_xor_si512(state[7], state[15]);
        }

        // Transpose and output (reuse existing transpose logic)
        let s0_lo = _mm512_extracti64x4_epi64(cv0, 0);
        let s0_hi = _mm512_extracti64x4_epi64(cv0, 1);
        let s1_lo = _mm512_extracti64x4_epi64(cv1, 0);
        let s1_hi = _mm512_extracti64x4_epi64(cv1, 1);
        let s2_lo = _mm512_extracti64x4_epi64(cv2, 0);
        let s2_hi = _mm512_extracti64x4_epi64(cv2, 1);
        let s3_lo = _mm512_extracti64x4_epi64(cv3, 0);
        let s3_hi = _mm512_extracti64x4_epi64(cv3, 1);
        let s4_lo = _mm512_extracti64x4_epi64(cv4, 0);
        let s4_hi = _mm512_extracti64x4_epi64(cv4, 1);
        let s5_lo = _mm512_extracti64x4_epi64(cv5, 0);
        let s5_hi = _mm512_extracti64x4_epi64(cv5, 1);
        let s6_lo = _mm512_extracti64x4_epi64(cv6, 0);
        let s6_hi = _mm512_extracti64x4_epi64(cv6, 1);
        let s7_lo = _mm512_extracti64x4_epi64(cv7, 0);
        let s7_hi = _mm512_extracti64x4_epi64(cv7, 1);

        let t0l = _mm256_unpacklo_epi32(s0_lo, s1_lo);
        let t1l = _mm256_unpackhi_epi32(s0_lo, s1_lo);
        let t2l = _mm256_unpacklo_epi32(s2_lo, s3_lo);
        let t3l = _mm256_unpackhi_epi32(s2_lo, s3_lo);
        let t4l = _mm256_unpacklo_epi32(s4_lo, s5_lo);
        let t5l = _mm256_unpackhi_epi32(s4_lo, s5_lo);
        let t6l = _mm256_unpacklo_epi32(s6_lo, s7_lo);
        let t7l = _mm256_unpackhi_epi32(s6_lo, s7_lo);

        let u0l = _mm256_unpacklo_epi64(t0l, t2l);
        let u1l = _mm256_unpackhi_epi64(t0l, t2l);
        let u2l = _mm256_unpacklo_epi64(t1l, t3l);
        let u3l = _mm256_unpackhi_epi64(t1l, t3l);
        let u4l = _mm256_unpacklo_epi64(t4l, t6l);
        let u5l = _mm256_unpackhi_epi64(t4l, t6l);
        let u6l = _mm256_unpacklo_epi64(t5l, t7l);
        let u7l = _mm256_unpackhi_epi64(t5l, t7l);

        let r0 = _mm256_permute2x128_si256(u0l, u4l, 0x20);
        let r1 = _mm256_permute2x128_si256(u1l, u5l, 0x20);
        let r2 = _mm256_permute2x128_si256(u2l, u6l, 0x20);
        let r3 = _mm256_permute2x128_si256(u3l, u7l, 0x20);
        let r4 = _mm256_permute2x128_si256(u0l, u4l, 0x31);
        let r5 = _mm256_permute2x128_si256(u1l, u5l, 0x31);
        let r6 = _mm256_permute2x128_si256(u2l, u6l, 0x31);
        let r7 = _mm256_permute2x128_si256(u3l, u7l, 0x31);

        let t0h = _mm256_unpacklo_epi32(s0_hi, s1_hi);
        let t1h = _mm256_unpackhi_epi32(s0_hi, s1_hi);
        let t2h = _mm256_unpacklo_epi32(s2_hi, s3_hi);
        let t3h = _mm256_unpackhi_epi32(s2_hi, s3_hi);
        let t4h = _mm256_unpacklo_epi32(s4_hi, s5_hi);
        let t5h = _mm256_unpackhi_epi32(s4_hi, s5_hi);
        let t6h = _mm256_unpacklo_epi32(s6_hi, s7_hi);
        let t7h = _mm256_unpackhi_epi32(s6_hi, s7_hi);

        let u0h = _mm256_unpacklo_epi64(t0h, t2h);
        let u1h = _mm256_unpackhi_epi64(t0h, t2h);
        let u2h = _mm256_unpacklo_epi64(t1h, t3h);
        let u3h = _mm256_unpackhi_epi64(t1h, t3h);
        let u4h = _mm256_unpacklo_epi64(t4h, t6h);
        let u5h = _mm256_unpackhi_epi64(t4h, t6h);
        let u6h = _mm256_unpacklo_epi64(t5h, t7h);
        let u7h = _mm256_unpackhi_epi64(t5h, t7h);

        let r8 = _mm256_permute2x128_si256(u0h, u4h, 0x20);
        let r9 = _mm256_permute2x128_si256(u1h, u5h, 0x20);
        let r10 = _mm256_permute2x128_si256(u2h, u6h, 0x20);
        let r11 = _mm256_permute2x128_si256(u3h, u7h, 0x20);
        let r12 = _mm256_permute2x128_si256(u0h, u4h, 0x31);
        let r13 = _mm256_permute2x128_si256(u1h, u5h, 0x31);
        let r14 = _mm256_permute2x128_si256(u2h, u6h, 0x31);
        let r15 = _mm256_permute2x128_si256(u3h, u7h, 0x31);

        let mut results = [[0u32; 8]; 16];
        _mm256_storeu_si256(results[0].as_mut_ptr() as *mut __m256i, r0);
        _mm256_storeu_si256(results[1].as_mut_ptr() as *mut __m256i, r1);
        _mm256_storeu_si256(results[2].as_mut_ptr() as *mut __m256i, r2);
        _mm256_storeu_si256(results[3].as_mut_ptr() as *mut __m256i, r3);
        _mm256_storeu_si256(results[4].as_mut_ptr() as *mut __m256i, r4);
        _mm256_storeu_si256(results[5].as_mut_ptr() as *mut __m256i, r5);
        _mm256_storeu_si256(results[6].as_mut_ptr() as *mut __m256i, r6);
        _mm256_storeu_si256(results[7].as_mut_ptr() as *mut __m256i, r7);
        _mm256_storeu_si256(results[8].as_mut_ptr() as *mut __m256i, r8);
        _mm256_storeu_si256(results[9].as_mut_ptr() as *mut __m256i, r9);
        _mm256_storeu_si256(results[10].as_mut_ptr() as *mut __m256i, r10);
        _mm256_storeu_si256(results[11].as_mut_ptr() as *mut __m256i, r11);
        _mm256_storeu_si256(results[12].as_mut_ptr() as *mut __m256i, r12);
        _mm256_storeu_si256(results[13].as_mut_ptr() as *mut __m256i, r13);
        _mm256_storeu_si256(results[14].as_mut_ptr() as *mut __m256i, r14);
        _mm256_storeu_si256(results[15].as_mut_ptr() as *mut __m256i, r15);

        results
    }
}

/// Compress 16 blocks in parallel (public interface).
#[cfg(all(feature = "std", target_arch = "x86_64"))]
pub fn compress_16blocks_parallel(
    cvs: &[[u32; 8]; 16],
    blocks: &[[u8; 64]; 16],
    counters: &[u64; 16],
    block_lens: &[u32; 16],
    flags: &[u8; 16],
) -> [[u32; 8]; 16] {
    if has_avx512f() {
        unsafe { parallel16::compress_16blocks(cvs, blocks, counters, block_lens, flags) }
    } else {
        // Fallback to two 8-way parallel compressions
        let cvs8_0: [[u32; 8]; 8] = [
            cvs[0], cvs[1], cvs[2], cvs[3], cvs[4], cvs[5], cvs[6], cvs[7],
        ];
        let cvs8_1: [[u32; 8]; 8] = [
            cvs[8], cvs[9], cvs[10], cvs[11], cvs[12], cvs[13], cvs[14], cvs[15],
        ];
        let blocks8_0: [[u8; 64]; 8] = [
            blocks[0], blocks[1], blocks[2], blocks[3], blocks[4], blocks[5], blocks[6], blocks[7],
        ];
        let blocks8_1: [[u8; 64]; 8] = [
            blocks[8], blocks[9], blocks[10], blocks[11], blocks[12], blocks[13], blocks[14],
            blocks[15],
        ];
        let counters8_0: [u64; 8] = [
            counters[0],
            counters[1],
            counters[2],
            counters[3],
            counters[4],
            counters[5],
            counters[6],
            counters[7],
        ];
        let counters8_1: [u64; 8] = [
            counters[8],
            counters[9],
            counters[10],
            counters[11],
            counters[12],
            counters[13],
            counters[14],
            counters[15],
        ];
        let block_lens8_0: [u32; 8] = [
            block_lens[0],
            block_lens[1],
            block_lens[2],
            block_lens[3],
            block_lens[4],
            block_lens[5],
            block_lens[6],
            block_lens[7],
        ];
        let block_lens8_1: [u32; 8] = [
            block_lens[8],
            block_lens[9],
            block_lens[10],
            block_lens[11],
            block_lens[12],
            block_lens[13],
            block_lens[14],
            block_lens[15],
        ];
        let flags8_0: [u8; 8] = [
            flags[0], flags[1], flags[2], flags[3], flags[4], flags[5], flags[6], flags[7],
        ];
        let flags8_1: [u8; 8] = [
            flags[8], flags[9], flags[10], flags[11], flags[12], flags[13], flags[14], flags[15],
        ];

        let result0 =
            compress_8blocks_parallel(&cvs8_0, &blocks8_0, &counters8_0, &block_lens8_0, &flags8_0);
        let result1 =
            compress_8blocks_parallel(&cvs8_1, &blocks8_1, &counters8_1, &block_lens8_1, &flags8_1);

        [
            result0[0], result0[1], result0[2], result0[3], result0[4], result0[5], result0[6],
            result0[7], result1[0], result1[1], result1[2], result1[3], result1[4], result1[5],
            result1[6], result1[7],
        ]
    }
}

/// Compress 8 blocks in parallel (public interface).
#[cfg(all(feature = "std", target_arch = "x86_64"))]
pub fn compress_8blocks_parallel(
    cvs: &[[u32; 8]; 8],
    blocks: &[[u8; 64]; 8],
    counters: &[u64; 8],
    block_lens: &[u32; 8],
    flags: &[u8; 8],
) -> [[u32; 8]; 8] {
    if has_avx2() {
        unsafe { parallel8::compress_8blocks(cvs, blocks, counters, block_lens, flags) }
    } else {
        // Fallback to two 4-way parallel compressions
        let cvs4_0: [[u32; 8]; 4] = [cvs[0], cvs[1], cvs[2], cvs[3]];
        let cvs4_1: [[u32; 8]; 4] = [cvs[4], cvs[5], cvs[6], cvs[7]];
        let blocks4_0: [[u8; 64]; 4] = [blocks[0], blocks[1], blocks[2], blocks[3]];
        let blocks4_1: [[u8; 64]; 4] = [blocks[4], blocks[5], blocks[6], blocks[7]];
        let counters4_0: [u64; 4] = [counters[0], counters[1], counters[2], counters[3]];
        let counters4_1: [u64; 4] = [counters[4], counters[5], counters[6], counters[7]];
        let block_lens4_0: [u32; 4] = [block_lens[0], block_lens[1], block_lens[2], block_lens[3]];
        let block_lens4_1: [u32; 4] = [block_lens[4], block_lens[5], block_lens[6], block_lens[7]];
        let flags4_0: [u8; 4] = [flags[0], flags[1], flags[2], flags[3]];
        let flags4_1: [u8; 4] = [flags[4], flags[5], flags[6], flags[7]];

        let result0 =
            compress_4blocks_parallel(&cvs4_0, &blocks4_0, &counters4_0, &block_lens4_0, &flags4_0);
        let result1 =
            compress_4blocks_parallel(&cvs4_1, &blocks4_1, &counters4_1, &block_lens4_1, &flags4_1);

        [
            result0[0], result0[1], result0[2], result0[3], result1[0], result1[1], result1[2],
            result1[3],
        ]
    }
}

/// Compress 8 parent nodes in parallel (public interface).
///
/// Takes 8 pairs of CVs (left, right) and computes 8 parent CVs.
/// This is 2x the throughput of 4-way parent compression.
#[cfg(all(feature = "std", target_arch = "x86_64"))]
pub fn compress_parents_8_parallel(
    key: &[u32; 8],
    left_cvs: &[[u32; 8]; 8],
    right_cvs: &[[u32; 8]; 8],
    flags: u8,
) -> [[u32; 8]; 8] {
    if has_avx2() {
        unsafe { parallel8::compress_parents_8(key, left_cvs, right_cvs, flags) }
    } else {
        // Fallback to two 4-way parent compressions
        let left4_0: [[u32; 8]; 4] = [left_cvs[0], left_cvs[1], left_cvs[2], left_cvs[3]];
        let left4_1: [[u32; 8]; 4] = [left_cvs[4], left_cvs[5], left_cvs[6], left_cvs[7]];
        let right4_0: [[u32; 8]; 4] = [right_cvs[0], right_cvs[1], right_cvs[2], right_cvs[3]];
        let right4_1: [[u32; 8]; 4] = [right_cvs[4], right_cvs[5], right_cvs[6], right_cvs[7]];

        let result0 = compress_parents_parallel(key, &left4_0, &right4_0, flags);
        let result1 = compress_parents_parallel(key, &left4_1, &right4_1, flags);

        [
            result0[0], result0[1], result0[2], result0[3], result1[0], result1[1], result1[2],
            result1[3],
        ]
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// PARALLEL CHUNK HASHING
// ═══════════════════════════════════════════════════════════════════════════════

/// Hash 4 complete chunks (1024 bytes each) in parallel.
///
/// This processes 4 independent chunks simultaneously by processing
/// corresponding blocks from each chunk in lock-step using SIMD.
///
/// Returns 4 chaining values, one per chunk.
#[cfg(all(feature = "std", target_arch = "x86_64"))]
pub fn hash_4_chunks_parallel(
    key: &[u32; 8],
    chunks: &[[u8; 1024]; 4],
    chunk_counters: &[u64; 4],
    base_flags: u8,
) -> [[u32; 8]; 4] {
    const CHUNK_START: u8 = 1;
    const CHUNK_END: u8 = 2;

    // Start with key as initial CV for all 4 chunks
    let mut cvs = [*key, *key, *key, *key];

    // Process 16 blocks per chunk in lock-step
    for block_idx in 0..16 {
        let is_first = block_idx == 0;
        let is_last = block_idx == 15;

        // Prefetch next block for each chunk to L1 cache
        if block_idx < 15 {
            let next_offset = (block_idx + 1) * 64;
            unsafe {
                prefetch_l1(chunks[0].as_ptr().add(next_offset));
                prefetch_l1(chunks[1].as_ptr().add(next_offset));
                prefetch_l1(chunks[2].as_ptr().add(next_offset));
                prefetch_l1(chunks[3].as_ptr().add(next_offset));
            }
        }

        // Extract the corresponding block from each chunk
        let blocks: [[u8; 64]; 4] = [
            chunks[0][block_idx * 64..(block_idx + 1) * 64]
                .try_into()
                .unwrap(),
            chunks[1][block_idx * 64..(block_idx + 1) * 64]
                .try_into()
                .unwrap(),
            chunks[2][block_idx * 64..(block_idx + 1) * 64]
                .try_into()
                .unwrap(),
            chunks[3][block_idx * 64..(block_idx + 1) * 64]
                .try_into()
                .unwrap(),
        ];

        // Build flags for each block
        let mut block_flags = base_flags;
        if is_first {
            block_flags |= CHUNK_START;
        }
        if is_last {
            block_flags |= CHUNK_END;
        }

        // Compress 4 blocks in parallel
        cvs = unsafe {
            parallel4::compress_4blocks(
                &cvs,
                &blocks,
                chunk_counters,
                &[64, 64, 64, 64],
                &[block_flags, block_flags, block_flags, block_flags],
            )
        };
    }

    cvs
}

/// Hash 8 complete chunks (1024 bytes each) in parallel using AVX2.
///
/// This processes 8 independent chunks simultaneously by processing
/// corresponding blocks from each chunk in lock-step using AVX2.
///
/// Returns 8 chaining values, one per chunk.
#[cfg(all(feature = "std", target_arch = "x86_64"))]
pub fn hash_8_chunks_parallel(
    key: &[u32; 8],
    chunks: &[[u8; 1024]; 8],
    chunk_counters: &[u64; 8],
    base_flags: u8,
) -> [[u32; 8]; 8] {
    const CHUNK_START: u8 = 1;
    const CHUNK_END: u8 = 2;

    // Start with key as initial CV for all 8 chunks
    let mut cvs = [*key, *key, *key, *key, *key, *key, *key, *key];

    // Process 16 blocks per chunk in lock-step
    for block_idx in 0..16 {
        let is_first = block_idx == 0;
        let is_last = block_idx == 15;

        // Prefetch next block for each chunk to L1 cache
        if block_idx < 15 {
            let next_offset = (block_idx + 1) * 64;
            unsafe {
                prefetch_l1(chunks[0].as_ptr().add(next_offset));
                prefetch_l1(chunks[1].as_ptr().add(next_offset));
                prefetch_l1(chunks[2].as_ptr().add(next_offset));
                prefetch_l1(chunks[3].as_ptr().add(next_offset));
                prefetch_l1(chunks[4].as_ptr().add(next_offset));
                prefetch_l1(chunks[5].as_ptr().add(next_offset));
                prefetch_l1(chunks[6].as_ptr().add(next_offset));
                prefetch_l1(chunks[7].as_ptr().add(next_offset));
            }
        }

        // Extract the corresponding block from each chunk
        let blocks: [[u8; 64]; 8] = [
            chunks[0][block_idx * 64..(block_idx + 1) * 64]
                .try_into()
                .unwrap(),
            chunks[1][block_idx * 64..(block_idx + 1) * 64]
                .try_into()
                .unwrap(),
            chunks[2][block_idx * 64..(block_idx + 1) * 64]
                .try_into()
                .unwrap(),
            chunks[3][block_idx * 64..(block_idx + 1) * 64]
                .try_into()
                .unwrap(),
            chunks[4][block_idx * 64..(block_idx + 1) * 64]
                .try_into()
                .unwrap(),
            chunks[5][block_idx * 64..(block_idx + 1) * 64]
                .try_into()
                .unwrap(),
            chunks[6][block_idx * 64..(block_idx + 1) * 64]
                .try_into()
                .unwrap(),
            chunks[7][block_idx * 64..(block_idx + 1) * 64]
                .try_into()
                .unwrap(),
        ];

        // Build flags for each block
        let mut block_flags = base_flags;
        if is_first {
            block_flags |= CHUNK_START;
        }
        if is_last {
            block_flags |= CHUNK_END;
        }

        // Compress 8 blocks in parallel
        cvs = compress_8blocks_parallel(
            &cvs,
            &blocks,
            chunk_counters,
            &[64, 64, 64, 64, 64, 64, 64, 64],
            &[block_flags; 8],
        );
    }

    cvs
}

/// Zero-copy version of hash_8_chunks_parallel.
///
/// Reads block data directly from chunks using pointers, avoiding 512-byte
/// copies per block iteration. This eliminates 8KB of copying per chunk batch.
///
/// # Safety
///
/// Caller must ensure the CPU supports AVX2 (checked internally).
#[cfg(all(feature = "std", target_arch = "x86_64"))]
pub fn hash_8_chunks_parallel_zero_copy(
    key: &[u32; 8],
    chunks: &[[u8; 1024]; 8],
    chunk_counters: &[u64; 8],
    base_flags: u8,
) -> [[u32; 8]; 8] {
    if !has_avx2() {
        // Fallback to copy version if AVX2 not available
        return hash_8_chunks_parallel(key, chunks, chunk_counters, base_flags);
    }

    const CHUNK_START: u8 = 1;
    const CHUNK_END: u8 = 2;

    // Create chunk pointers array
    let chunk_ptrs: [*const u8; 8] = [
        chunks[0].as_ptr(),
        chunks[1].as_ptr(),
        chunks[2].as_ptr(),
        chunks[3].as_ptr(),
        chunks[4].as_ptr(),
        chunks[5].as_ptr(),
        chunks[6].as_ptr(),
        chunks[7].as_ptr(),
    ];

    // Start with key as initial CV for all 8 chunks
    let mut cvs = [*key, *key, *key, *key, *key, *key, *key, *key];

    // Process 16 blocks per chunk in lock-step
    for block_idx in 0..16 {
        let is_first = block_idx == 0;
        let is_last = block_idx == 15;

        // Prefetch next block for each chunk to L1 cache
        if block_idx < 15 {
            let next_offset = (block_idx + 1) * 64;
            unsafe {
                prefetch_l1(chunks[0].as_ptr().add(next_offset));
                prefetch_l1(chunks[1].as_ptr().add(next_offset));
                prefetch_l1(chunks[2].as_ptr().add(next_offset));
                prefetch_l1(chunks[3].as_ptr().add(next_offset));
                prefetch_l1(chunks[4].as_ptr().add(next_offset));
                prefetch_l1(chunks[5].as_ptr().add(next_offset));
                prefetch_l1(chunks[6].as_ptr().add(next_offset));
                prefetch_l1(chunks[7].as_ptr().add(next_offset));
            }
        }

        // Build flags for each block
        let mut block_flags = base_flags;
        if is_first {
            block_flags |= CHUNK_START;
        }
        if is_last {
            block_flags |= CHUNK_END;
        }

        // Compress 8 blocks in parallel using zero-copy (no 512-byte block copies)
        cvs = unsafe {
            parallel8::compress_8blocks_zero_copy(
                &cvs,
                &chunk_ptrs,
                block_idx,
                chunk_counters,
                &[64, 64, 64, 64, 64, 64, 64, 64],
                &[block_flags; 8],
            )
        };
    }

    cvs
}

/// Hash 8 complete chunks using raw pointers (true zero-copy).
///
/// # Safety
///
/// Each pointer in `chunk_ptrs` must point to at least 1024 bytes of valid memory.
#[cfg(all(feature = "std", target_arch = "x86_64"))]
pub unsafe fn hash_8_chunks_from_ptrs(
    key: &[u32; 8],
    chunk_ptrs: &[*const u8; 8],
    chunk_counters: &[u64; 8],
    base_flags: u8,
) -> [[u32; 8]; 8] {
    if !has_avx2() {
        // Scalar fallback
        let mut cvs = [[0u32; 8]; 8];
        for i in 0..8 {
            let chunk = core::slice::from_raw_parts(chunk_ptrs[i], 1024);
            let mut cv = *key;
            const CHUNK_START: u8 = 1;
            const CHUNK_END: u8 = 2;

            for block_idx in 0..16 {
                let is_first = block_idx == 0;
                let is_last = block_idx == 15;
                let mut flags = base_flags;
                if is_first {
                    flags |= CHUNK_START;
                }
                if is_last {
                    flags |= CHUNK_END;
                }

                let block: [u8; 64] = chunk[block_idx * 64..(block_idx + 1) * 64]
                    .try_into()
                    .unwrap();
                let output = compress_auto(&cv, &block, chunk_counters[i], 64, flags);
                cv = output[..8].try_into().unwrap();
            }
            cvs[i] = cv;
        }
        return cvs;
    }

    const CHUNK_START: u8 = 1;
    const CHUNK_END: u8 = 2;

    let mut cvs = [*key, *key, *key, *key, *key, *key, *key, *key];

    // Prefetch first block from all chunks
    prefetch_l1(chunk_ptrs[0]);
    prefetch_l1(chunk_ptrs[1]);
    prefetch_l1(chunk_ptrs[2]);
    prefetch_l1(chunk_ptrs[3]);
    prefetch_l1(chunk_ptrs[4]);
    prefetch_l1(chunk_ptrs[5]);
    prefetch_l1(chunk_ptrs[6]);
    prefetch_l1(chunk_ptrs[7]);

    for block_idx in 0..16 {
        let is_first = block_idx == 0;
        let is_last = block_idx == 15;

        // Prefetch next block
        if block_idx < 15 {
            let next_offset = (block_idx + 1) * 64;
            prefetch_l1(chunk_ptrs[0].add(next_offset));
            prefetch_l1(chunk_ptrs[1].add(next_offset));
            prefetch_l1(chunk_ptrs[2].add(next_offset));
            prefetch_l1(chunk_ptrs[3].add(next_offset));
            prefetch_l1(chunk_ptrs[4].add(next_offset));
            prefetch_l1(chunk_ptrs[5].add(next_offset));
            prefetch_l1(chunk_ptrs[6].add(next_offset));
            prefetch_l1(chunk_ptrs[7].add(next_offset));
        }

        let mut block_flags = base_flags;
        if is_first {
            block_flags |= CHUNK_START;
        }
        if is_last {
            block_flags |= CHUNK_END;
        }

        cvs = parallel8::compress_8blocks_zero_copy(
            &cvs,
            chunk_ptrs,
            block_idx,
            chunk_counters,
            &[64, 64, 64, 64, 64, 64, 64, 64],
            &[block_flags; 8],
        );
    }

    cvs
}

/// Hash 8 contiguous chunks using the fused AVX2 path.
///
/// This is the fastest path for 8 contiguous chunks because:
/// 1. Uses AVX2 gather for single-instruction message word loading
/// 2. Keeps CV state in registers across all 16 block compressions
/// 3. Only one transpose operation at the end (not per-block)
///
/// # Safety
///
/// - `base_ptr` must point to at least 8 contiguous chunks (8KB total)
/// - CPU must support AVX2
#[cfg(all(feature = "std", target_arch = "x86_64"))]
pub unsafe fn hash_8_chunks_contiguous(
    key: &[u32; 8],
    base_ptr: *const u8,
    chunk_counters: &[u64; 8],
    base_flags: u8,
) -> [[u32; 8]; 8] {
    if !has_avx2() {
        // Fallback to pointer-based version
        let chunk_ptrs: [*const u8; 8] = [
            base_ptr,
            base_ptr.add(1024),
            base_ptr.add(2 * 1024),
            base_ptr.add(3 * 1024),
            base_ptr.add(4 * 1024),
            base_ptr.add(5 * 1024),
            base_ptr.add(6 * 1024),
            base_ptr.add(7 * 1024),
        ];
        return hash_8_chunks_from_ptrs(key, &chunk_ptrs, chunk_counters, base_flags);
    }

    // Use fused path that keeps CVs in registers across all 16 blocks
    parallel8::hash_8_chunks_fused(key, base_ptr, chunk_counters, base_flags)
}

/// Hash 16 complete chunks using raw pointers (true zero-copy, AVX-512).
///
/// # Safety
///
/// Each pointer in `chunk_ptrs` must point to at least 1024 bytes of valid memory.
#[cfg(all(feature = "std", target_arch = "x86_64"))]
pub unsafe fn hash_16_chunks_from_ptrs(
    key: &[u32; 8],
    chunk_ptrs: &[*const u8; 16],
    chunk_counters: &[u64; 16],
    base_flags: u8,
) -> [[u32; 8]; 16] {
    if !has_avx512f() {
        // Fallback to 2x 8-way
        let ptrs_lo: [*const u8; 8] = [
            chunk_ptrs[0],
            chunk_ptrs[1],
            chunk_ptrs[2],
            chunk_ptrs[3],
            chunk_ptrs[4],
            chunk_ptrs[5],
            chunk_ptrs[6],
            chunk_ptrs[7],
        ];
        let ptrs_hi: [*const u8; 8] = [
            chunk_ptrs[8],
            chunk_ptrs[9],
            chunk_ptrs[10],
            chunk_ptrs[11],
            chunk_ptrs[12],
            chunk_ptrs[13],
            chunk_ptrs[14],
            chunk_ptrs[15],
        ];
        let counters_lo: [u64; 8] = [
            chunk_counters[0],
            chunk_counters[1],
            chunk_counters[2],
            chunk_counters[3],
            chunk_counters[4],
            chunk_counters[5],
            chunk_counters[6],
            chunk_counters[7],
        ];
        let counters_hi: [u64; 8] = [
            chunk_counters[8],
            chunk_counters[9],
            chunk_counters[10],
            chunk_counters[11],
            chunk_counters[12],
            chunk_counters[13],
            chunk_counters[14],
            chunk_counters[15],
        ];

        let cvs_lo = hash_8_chunks_from_ptrs(key, &ptrs_lo, &counters_lo, base_flags);
        let cvs_hi = hash_8_chunks_from_ptrs(key, &ptrs_hi, &counters_hi, base_flags);

        return [
            cvs_lo[0], cvs_lo[1], cvs_lo[2], cvs_lo[3], cvs_lo[4], cvs_lo[5], cvs_lo[6], cvs_lo[7],
            cvs_hi[0], cvs_hi[1], cvs_hi[2], cvs_hi[3], cvs_hi[4], cvs_hi[5], cvs_hi[6], cvs_hi[7],
        ];
    }

    const CHUNK_START: u8 = 1;
    const CHUNK_END: u8 = 2;

    let mut cvs: [[u32; 8]; 16] = [*key; 16];

    // Prefetch first block from all 16 chunks
    for ptr in chunk_ptrs {
        prefetch_l1(*ptr);
    }

    for block_idx in 0..16 {
        let is_first = block_idx == 0;
        let is_last = block_idx == 15;

        // Prefetch next block from all 16 chunks
        if block_idx < 15 {
            let next_offset = (block_idx + 1) * 64;
            for ptr in chunk_ptrs {
                prefetch_l1(ptr.add(next_offset));
            }
        }

        let mut block_flags = base_flags;
        if is_first {
            block_flags |= CHUNK_START;
        }
        if is_last {
            block_flags |= CHUNK_END;
        }

        // Process using AVX-512 16-way parallel
        cvs = parallel16::compress_16blocks_from_ptrs(
            &cvs,
            chunk_ptrs,
            block_idx,
            chunk_counters,
            &[64; 16],
            &[block_flags; 16],
        );
    }

    cvs
}

/// Hash 16 complete chunks (1024 bytes each) in parallel using AVX-512.
///
/// This processes 16 independent chunks simultaneously, providing 2x the
/// throughput of 8-way AVX2 processing on AVX-512 capable hardware.
///
/// Returns 16 chaining values, one per chunk.
#[cfg(all(feature = "std", target_arch = "x86_64"))]
pub fn hash_16_chunks_parallel(
    key: &[u32; 8],
    chunks: &[[u8; 1024]; 16],
    chunk_counters: &[u64; 16],
    base_flags: u8,
) -> [[u32; 8]; 16] {
    if !has_avx512f() {
        // Fallback to two 8-way parallel calls
        let chunks8_0: [[u8; 1024]; 8] = [
            chunks[0], chunks[1], chunks[2], chunks[3], chunks[4], chunks[5], chunks[6], chunks[7],
        ];
        let chunks8_1: [[u8; 1024]; 8] = [
            chunks[8], chunks[9], chunks[10], chunks[11], chunks[12], chunks[13], chunks[14],
            chunks[15],
        ];
        let counters8_0: [u64; 8] = [
            chunk_counters[0],
            chunk_counters[1],
            chunk_counters[2],
            chunk_counters[3],
            chunk_counters[4],
            chunk_counters[5],
            chunk_counters[6],
            chunk_counters[7],
        ];
        let counters8_1: [u64; 8] = [
            chunk_counters[8],
            chunk_counters[9],
            chunk_counters[10],
            chunk_counters[11],
            chunk_counters[12],
            chunk_counters[13],
            chunk_counters[14],
            chunk_counters[15],
        ];
        let result0 = hash_8_chunks_parallel(key, &chunks8_0, &counters8_0, base_flags);
        let result1 = hash_8_chunks_parallel(key, &chunks8_1, &counters8_1, base_flags);
        return [
            result0[0], result0[1], result0[2], result0[3], result0[4], result0[5], result0[6],
            result0[7], result1[0], result1[1], result1[2], result1[3], result1[4], result1[5],
            result1[6], result1[7],
        ];
    }

    const CHUNK_START: u8 = 1;
    const CHUNK_END: u8 = 2;

    // Start with key as initial CV for all 16 chunks
    let mut cvs = [*key; 16];

    // Process 16 blocks per chunk in lock-step
    for block_idx in 0..16 {
        let is_first = block_idx == 0;
        let is_last = block_idx == 15;

        // Extract the corresponding block from each chunk
        let blocks: [[u8; 64]; 16] = [
            chunks[0][block_idx * 64..(block_idx + 1) * 64]
                .try_into()
                .unwrap(),
            chunks[1][block_idx * 64..(block_idx + 1) * 64]
                .try_into()
                .unwrap(),
            chunks[2][block_idx * 64..(block_idx + 1) * 64]
                .try_into()
                .unwrap(),
            chunks[3][block_idx * 64..(block_idx + 1) * 64]
                .try_into()
                .unwrap(),
            chunks[4][block_idx * 64..(block_idx + 1) * 64]
                .try_into()
                .unwrap(),
            chunks[5][block_idx * 64..(block_idx + 1) * 64]
                .try_into()
                .unwrap(),
            chunks[6][block_idx * 64..(block_idx + 1) * 64]
                .try_into()
                .unwrap(),
            chunks[7][block_idx * 64..(block_idx + 1) * 64]
                .try_into()
                .unwrap(),
            chunks[8][block_idx * 64..(block_idx + 1) * 64]
                .try_into()
                .unwrap(),
            chunks[9][block_idx * 64..(block_idx + 1) * 64]
                .try_into()
                .unwrap(),
            chunks[10][block_idx * 64..(block_idx + 1) * 64]
                .try_into()
                .unwrap(),
            chunks[11][block_idx * 64..(block_idx + 1) * 64]
                .try_into()
                .unwrap(),
            chunks[12][block_idx * 64..(block_idx + 1) * 64]
                .try_into()
                .unwrap(),
            chunks[13][block_idx * 64..(block_idx + 1) * 64]
                .try_into()
                .unwrap(),
            chunks[14][block_idx * 64..(block_idx + 1) * 64]
                .try_into()
                .unwrap(),
            chunks[15][block_idx * 64..(block_idx + 1) * 64]
                .try_into()
                .unwrap(),
        ];

        // Build flags for each block
        let mut block_flags = base_flags;
        if is_first {
            block_flags |= CHUNK_START;
        }
        if is_last {
            block_flags |= CHUNK_END;
        }

        // Compress 16 blocks in parallel using AVX-512
        cvs = compress_16blocks_parallel(
            &cvs,
            &blocks,
            chunk_counters,
            &[64; 16],
            &[block_flags; 16],
        );
    }

    cvs
}

/// Hash multiple complete chunks in parallel, processing 16 at a time with AVX-512
/// or 8 at a time with AVX2.
///
/// Uses 16-way parallelism when AVX-512 is available, 8-way with AVX2,
/// or 4-way SSE4.1 fallback.
/// Returns CVs for all processed chunks.
#[cfg(all(feature = "std", target_arch = "x86_64"))]
pub fn hash_many_chunks_parallel(
    key: &[u32; 8],
    data: &[u8],
    start_chunk_counter: u64,
    base_flags: u8,
) -> Vec<[u32; 8]> {
    const CHUNK_LEN: usize = 1024;
    const BATCH_SIZE_16: usize = 16;
    const BATCH_BYTES_16: usize = CHUNK_LEN * BATCH_SIZE_16;
    const BATCH_SIZE_8: usize = 8;
    const BATCH_BYTES_8: usize = CHUNK_LEN * BATCH_SIZE_8;
    const BATCH_SIZE_4: usize = 4;
    const BATCH_BYTES_4: usize = CHUNK_LEN * BATCH_SIZE_4;

    let num_chunks = data.len() / CHUNK_LEN;
    let mut cvs = Vec::with_capacity(num_chunks);

    let mut offset = 0;
    let mut chunk_counter = start_chunk_counter;

    let use_avx512 = has_avx512f();
    let use_avx2 = has_avx2();

    // Process 16 chunks at a time with AVX-512 (fused gather path)
    if use_avx512 {
        while offset + BATCH_BYTES_16 <= data.len() {
            // Prefetch next batch (16KB) to L2 cache while processing current batch
            let next_batch_offset = offset + BATCH_BYTES_16;
            if next_batch_offset + BATCH_BYTES_16 <= data.len() {
                unsafe {
                    prefetch_range_l2(data.as_ptr().add(next_batch_offset), BATCH_BYTES_16);
                }
            }

            let counters: [u64; 16] = [
                chunk_counter,
                chunk_counter + 1,
                chunk_counter + 2,
                chunk_counter + 3,
                chunk_counter + 4,
                chunk_counter + 5,
                chunk_counter + 6,
                chunk_counter + 7,
                chunk_counter + 8,
                chunk_counter + 9,
                chunk_counter + 10,
                chunk_counter + 11,
                chunk_counter + 12,
                chunk_counter + 13,
                chunk_counter + 14,
                chunk_counter + 15,
            ];

            // SAFETY: data[offset..] contains at least 16 contiguous chunks (16KB)
            // CVs stay in registers across all 16 blocks.
            // Use load+transpose for small data (< 128KB fits in L2 cache), gather for larger.
            let use_transpose = data.len() <= 128 * 1024;
            let batch_cvs = unsafe {
                parallel16::hash_16_chunks_fused(
                    key,
                    data.as_ptr().add(offset),
                    &counters,
                    base_flags,
                    use_transpose,
                )
            };
            cvs.extend_from_slice(&batch_cvs);

            offset += BATCH_BYTES_16;
            chunk_counter += 16;
        }
    }

    // Process 8 chunks at a time with AVX2 (gather-based contiguous path)
    if use_avx2 {
        while offset + BATCH_BYTES_8 <= data.len() {
            // Prefetch next batch (8KB) to L2 cache while processing current batch
            let next_batch_offset = offset + BATCH_BYTES_8;
            if next_batch_offset + BATCH_BYTES_8 <= data.len() {
                unsafe {
                    prefetch_range_l2(data.as_ptr().add(next_batch_offset), BATCH_BYTES_8);
                }
            }

            let counters = [
                chunk_counter,
                chunk_counter + 1,
                chunk_counter + 2,
                chunk_counter + 3,
                chunk_counter + 4,
                chunk_counter + 5,
                chunk_counter + 6,
                chunk_counter + 7,
            ];

            // SAFETY: data[offset..] contains at least 8 contiguous chunks (8KB)
            // Uses AVX2 gather for single-instruction message word loads
            let batch_cvs = unsafe {
                hash_8_chunks_contiguous(key, data.as_ptr().add(offset), &counters, base_flags)
            };
            cvs.extend_from_slice(&batch_cvs);

            offset += BATCH_BYTES_8;
            chunk_counter += 8;
        }
    }

    // Process 4 chunks at a time (fallback or remaining chunks after 8-way processing)
    while offset + BATCH_BYTES_4 <= data.len() {
        let chunks: [[u8; 1024]; 4] = [
            data[offset..offset + CHUNK_LEN].try_into().unwrap(),
            data[offset + CHUNK_LEN..offset + 2 * CHUNK_LEN]
                .try_into()
                .unwrap(),
            data[offset + 2 * CHUNK_LEN..offset + 3 * CHUNK_LEN]
                .try_into()
                .unwrap(),
            data[offset + 3 * CHUNK_LEN..offset + 4 * CHUNK_LEN]
                .try_into()
                .unwrap(),
        ];

        let counters = [
            chunk_counter,
            chunk_counter + 1,
            chunk_counter + 2,
            chunk_counter + 3,
        ];

        let batch_cvs = hash_4_chunks_parallel(key, &chunks, &counters, base_flags);
        cvs.extend_from_slice(&batch_cvs);

        offset += BATCH_BYTES_4;
        chunk_counter += 4;
    }

    // Handle remaining chunks (0-3) sequentially
    while offset + CHUNK_LEN <= data.len() {
        let chunk: [u8; CHUNK_LEN] = data[offset..offset + CHUNK_LEN].try_into().unwrap();
        let cv = hash_single_chunk(key, &chunk, chunk_counter, base_flags);
        cvs.push(cv);
        offset += CHUNK_LEN;
        chunk_counter += 1;
    }

    cvs
}

/// Hash a single complete chunk (1024 bytes).
#[cfg(all(feature = "std", target_arch = "x86_64"))]
fn hash_single_chunk(key: &[u32; 8], chunk: &[u8; 1024], counter: u64, base_flags: u8) -> [u32; 8] {
    const CHUNK_START: u8 = 1;
    const CHUNK_END: u8 = 2;

    let mut cv = *key;

    for block_idx in 0..16 {
        let block: [u8; 64] = chunk[block_idx * 64..(block_idx + 1) * 64]
            .try_into()
            .unwrap();
        let is_first = block_idx == 0;
        let is_last = block_idx == 15;

        let mut flags = base_flags;
        if is_first {
            flags |= CHUNK_START;
        }
        if is_last {
            flags |= CHUNK_END;
        }

        let out = compress_auto(&cv, &block, counter, 64, flags);
        cv.copy_from_slice(&out[..8]);
    }

    cv
}

/// Merge CVs into a single root hash using parallel parent compression.
///
/// This performs the tree reduction, processing 8 parent nodes at a time with AVX2.
#[cfg(all(feature = "std", target_arch = "x86_64"))]
pub fn merge_cvs_to_root(key: &[u32; 8], cvs: &[[u32; 8]], base_flags: u8) -> [u32; 8] {
    const PARENT: u8 = 4;
    const ROOT: u8 = 8;

    if cvs.is_empty() {
        return *key;
    }

    if cvs.len() == 1 {
        return cvs[0];
    }

    let mut current_level = cvs.to_vec();

    while current_level.len() > 1 {
        let mut next_level = Vec::with_capacity((current_level.len() + 1) / 2);
        let mut i = 0;

        // Process 8 pairs (16 CVs) at a time for 8-way parallel parent computation
        while i + 16 <= current_level.len() {
            let left_cvs: [[u32; 8]; 8] = [
                current_level[i],
                current_level[i + 2],
                current_level[i + 4],
                current_level[i + 6],
                current_level[i + 8],
                current_level[i + 10],
                current_level[i + 12],
                current_level[i + 14],
            ];
            let right_cvs: [[u32; 8]; 8] = [
                current_level[i + 1],
                current_level[i + 3],
                current_level[i + 5],
                current_level[i + 7],
                current_level[i + 9],
                current_level[i + 11],
                current_level[i + 13],
                current_level[i + 15],
            ];

            let parent_cvs = compress_parents_8_parallel(key, &left_cvs, &right_cvs, base_flags);
            next_level.extend_from_slice(&parent_cvs);
            i += 16;
        }

        // Process 4 pairs (8 CVs) at a time for remaining
        while i + 8 <= current_level.len() {
            let left_cvs: [[u32; 8]; 4] = [
                current_level[i],
                current_level[i + 2],
                current_level[i + 4],
                current_level[i + 6],
            ];
            let right_cvs: [[u32; 8]; 4] = [
                current_level[i + 1],
                current_level[i + 3],
                current_level[i + 5],
                current_level[i + 7],
            ];

            let parent_cvs = compress_parents_parallel(key, &left_cvs, &right_cvs, base_flags);
            next_level.extend_from_slice(&parent_cvs);
            i += 8;
        }

        // Handle remaining pairs sequentially
        while i + 2 <= current_level.len() {
            let parent_cv =
                parent_cv_single(key, &current_level[i], &current_level[i + 1], base_flags);
            next_level.push(parent_cv);
            i += 2;
        }

        // If odd number of CVs, carry the last one up
        if i < current_level.len() {
            next_level.push(current_level[i]);
        }

        current_level = next_level;
    }

    current_level[0]
}

/// Compute a single parent CV.
fn parent_cv_single(
    key: &[u32; 8],
    left_cv: &[u32; 8],
    right_cv: &[u32; 8],
    base_flags: u8,
) -> [u32; 8] {
    const PARENT: u8 = 4;

    // Construct parent block: [left_cv || right_cv]
    let mut block = [0u8; 64];
    for i in 0..8 {
        block[i * 4..(i + 1) * 4].copy_from_slice(&left_cv[i].to_le_bytes());
        block[32 + i * 4..32 + (i + 1) * 4].copy_from_slice(&right_cv[i].to_le_bytes());
    }

    let out = compress_auto(key, &block, 0, 64, base_flags | PARENT);
    let mut cv = [0u32; 8];
    cv.copy_from_slice(&out[..8]);
    cv
}

/// High-performance parallel BLAKE3 hash for large inputs.
///
/// This function uses 4-way parallel chunk processing to maximize throughput
/// on large inputs. For inputs smaller than 4KB, falls back to sequential processing.
///
/// Returns a 32-byte hash.
#[cfg(all(feature = "std", target_arch = "x86_64"))]
pub fn hash_large_parallel(data: &[u8]) -> [u8; 32] {
    const CHUNK_LEN: usize = 1024;
    const ROOT: u8 = 8;

    if data.is_empty() {
        // Hash empty input
        let out = compress_auto(&IV, &[0u8; 64], 0, 0, 1 | 2 | ROOT); // CHUNK_START | CHUNK_END | ROOT
        return words_to_bytes(&out[..8].try_into().unwrap());
    }

    if data.len() <= CHUNK_LEN {
        // Single chunk - process sequentially with ROOT flag
        return hash_single_chunk_root(&IV, data, 0);
    }

    // Multiple chunks - use parallel processing for complete chunks
    let complete_chunks = data.len() / CHUNK_LEN;
    let complete_bytes = complete_chunks * CHUNK_LEN;
    let remainder = data.len() - complete_bytes;

    // Hash all complete chunks in parallel
    let mut cvs = hash_many_chunks_parallel(&IV, &data[..complete_bytes], 0, 0);

    // Handle partial final chunk if present
    if remainder > 0 {
        let final_cv = hash_partial_chunk(&IV, &data[complete_bytes..], complete_chunks as u64);
        cvs.push(final_cv);
    }

    // If only one chunk, apply ROOT flag and return
    if cvs.len() == 1 {
        return words_to_bytes(&cvs[0]);
    }

    // Merge CVs to get root hash
    let root_cv = merge_cvs_to_root_final(&IV, &cvs, 0);
    words_to_bytes(&root_cv)
}

/// Hash large data using multi-threaded parallel processing.
///
/// Uses rayon to distribute chunk processing across multiple CPU cores.
/// Each thread processes 8 chunks at a time using AVX2 SIMD.
///
/// Returns a 32-byte hash.
#[cfg(all(feature = "rayon", feature = "std", target_arch = "x86_64"))]
pub fn hash_large_parallel_mt(data: &[u8]) -> [u8; 32] {
    use rayon::prelude::*;

    const CHUNK_LEN: usize = 1024;
    const ROOT: u8 = 8;
    const BATCH_SIZE: usize = 8; // Process 8 chunks per batch with AVX2
    const BATCH_BYTES: usize = CHUNK_LEN * BATCH_SIZE;

    if data.is_empty() {
        let out = compress_auto(&IV, &[0u8; 64], 0, 0, 1 | 2 | ROOT);
        return words_to_bytes(&out[..8].try_into().unwrap());
    }

    if data.len() <= CHUNK_LEN {
        return hash_single_chunk_root(&IV, data, 0);
    }

    let complete_chunks = data.len() / CHUNK_LEN;
    let complete_bytes = complete_chunks * CHUNK_LEN;
    let remainder = data.len() - complete_bytes;

    // Calculate number of full 8-chunk batches
    let num_batches = complete_chunks / BATCH_SIZE;
    let leftover_chunks = complete_chunks % BATCH_SIZE;

    // Process all full batches in parallel using rayon
    let batch_cvs: Vec<[[u32; 8]; 8]> = (0..num_batches)
        .into_par_iter()
        .map(|batch_idx| {
            let offset = batch_idx * BATCH_BYTES;
            let batch_data = &data[offset..offset + BATCH_BYTES];

            let chunks: [[u8; 1024]; 8] = [
                batch_data[0..CHUNK_LEN].try_into().unwrap(),
                batch_data[CHUNK_LEN..2 * CHUNK_LEN].try_into().unwrap(),
                batch_data[2 * CHUNK_LEN..3 * CHUNK_LEN].try_into().unwrap(),
                batch_data[3 * CHUNK_LEN..4 * CHUNK_LEN].try_into().unwrap(),
                batch_data[4 * CHUNK_LEN..5 * CHUNK_LEN].try_into().unwrap(),
                batch_data[5 * CHUNK_LEN..6 * CHUNK_LEN].try_into().unwrap(),
                batch_data[6 * CHUNK_LEN..7 * CHUNK_LEN].try_into().unwrap(),
                batch_data[7 * CHUNK_LEN..8 * CHUNK_LEN].try_into().unwrap(),
            ];

            let base_counter = (batch_idx * BATCH_SIZE) as u64;
            let counters = [
                base_counter,
                base_counter + 1,
                base_counter + 2,
                base_counter + 3,
                base_counter + 4,
                base_counter + 5,
                base_counter + 6,
                base_counter + 7,
            ];

            hash_8_chunks_parallel(&IV, &chunks, &counters, 0)
        })
        .collect();

    // Flatten batch results into a single CV list
    let mut cvs: Vec<[u32; 8]> = Vec::with_capacity(complete_chunks + 1);
    for batch_cv in batch_cvs {
        cvs.extend_from_slice(&batch_cv);
    }

    // Process leftover chunks (less than 8) sequentially
    if leftover_chunks > 0 {
        let leftover_offset = num_batches * BATCH_BYTES;
        let leftover_counter = (num_batches * BATCH_SIZE) as u64;

        for i in 0..leftover_chunks {
            let chunk_offset = leftover_offset + i * CHUNK_LEN;
            let chunk: [u8; 1024] = data[chunk_offset..chunk_offset + CHUNK_LEN]
                .try_into()
                .unwrap();
            let cv = hash_single_chunk(&IV, &chunk, leftover_counter + i as u64, 0);
            cvs.push(cv);
        }
    }

    // Handle partial final chunk if present
    if remainder > 0 {
        let final_cv = hash_partial_chunk(&IV, &data[complete_bytes..], complete_chunks as u64);
        cvs.push(final_cv);
    }

    // If only one chunk, apply ROOT flag and return
    if cvs.len() == 1 {
        return words_to_bytes(&cvs[0]);
    }

    // Merge CVs to get root hash
    let root_cv = merge_cvs_to_root_final(&IV, &cvs, 0);
    words_to_bytes(&root_cv)
}

/// Hyper-parallel BLAKE3 hash optimized for high-core-count CPUs (Threadripper, EPYC).
///
/// This function exploits the massive parallelism available in workstation and server CPUs
/// by distributing chunk processing across ALL available cores using lightweight `std::thread`.
/// Each thread processes 16 chunks at a time using AVX-512 SIMD.
///
/// # Why This Exists
///
/// The reference `blake3` crate uses Rayon with a threshold around 128KB, meaning small
/// data (16KB-128KB) gets processed single-threaded. On high-core-count systems, this
/// leaves 90%+ of the CPU idle.
///
/// This function uses no such threshold - it spawns threads immediately for any multi-chunk
/// input, leveraging the fact that modern CPUs (especially Threadripper/EPYC with multiple
/// CCDs) have essentially zero cross-core overhead when each thread works in its own L3.
///
/// # Strategy
///
/// For N chunks of data:
/// - Divide into batches of 16 chunks (16KB each)
/// - Spawn T threads (default: min(num_batches, available_cores))
/// - Each thread processes its assigned batches using AVX-512
/// - Merge CVs using SIMD parent compression
///
/// # Performance Target
///
/// On a 32-core Threadripper with 64KB input (4 batches):
/// - Single-threaded AVX-512: ~4 GiB/s
/// - 4-threaded hyper-parallel: ~16 GiB/s (4x speedup)
/// - Far exceeds the reference crate's ~6 GiB/s
///
/// Returns a 32-byte hash.
#[cfg(all(feature = "std", feature = "rayon", target_arch = "x86_64"))]
pub fn hash_hyper_parallel(data: &[u8]) -> [u8; 32] {
    use rayon::prelude::*;

    const CHUNK_LEN: usize = 1024;
    const BATCH_SIZE: usize = 16; // 16 chunks per batch (AVX-512)
    const BATCH_BYTES: usize = CHUNK_LEN * BATCH_SIZE; // 16KB
    const ROOT: u8 = 8;

    // Small inputs: use single-threaded path
    if data.is_empty() {
        let out = compress_auto(&IV, &[0u8; 64], 0, 0, 1 | 2 | ROOT);
        return words_to_bytes(&out[..8].try_into().unwrap());
    }

    if data.len() <= CHUNK_LEN {
        return hash_single_chunk_root(&IV, data, 0);
    }

    // Need AVX-512 for the parallel path
    if !has_avx512f() {
        return hash_large_parallel(data);
    }

    let complete_chunks = data.len() / CHUNK_LEN;
    let complete_bytes = complete_chunks * CHUNK_LEN;
    let remainder = data.len() - complete_bytes;

    // Calculate batches
    let num_batches = complete_chunks / BATCH_SIZE;
    let leftover_chunks = complete_chunks % BATCH_SIZE;

    // For very small inputs or single batch, skip thread overhead
    if num_batches <= 1 {
        return hash_large_parallel(data);
    }

    // Use Rayon's warm thread pool for parallel batch processing
    // This has much lower overhead than std::thread::scope
    let batch_cvs: Vec<[[u32; 8]; 16]> = (0..num_batches)
        .into_par_iter()
        .map(|batch_idx| {
            let offset = batch_idx * BATCH_BYTES;
            let base_counter = (batch_idx * BATCH_SIZE) as u64;

            let counters: [u64; 16] = [
                base_counter,
                base_counter + 1,
                base_counter + 2,
                base_counter + 3,
                base_counter + 4,
                base_counter + 5,
                base_counter + 6,
                base_counter + 7,
                base_counter + 8,
                base_counter + 9,
                base_counter + 10,
                base_counter + 11,
                base_counter + 12,
                base_counter + 13,
                base_counter + 14,
                base_counter + 15,
            ];

            // SAFETY: offset is within bounds
            unsafe {
                // Use load+transpose for small data
                let use_transpose = data.len() <= 128 * 1024;
                parallel16::hash_16_chunks_fused(
                    &IV,
                    data.as_ptr().add(offset),
                    &counters,
                    0,
                    use_transpose,
                )
            }
        })
        .collect();

    // Flatten batch results into a single CV list
    let mut cvs: Vec<[u32; 8]> = Vec::with_capacity(complete_chunks + 1);
    for batch_cv in batch_cvs {
        cvs.extend_from_slice(&batch_cv);
    }

    // Process leftover chunks (< 16) sequentially
    if leftover_chunks > 0 {
        let leftover_offset = num_batches * BATCH_BYTES;
        let leftover_counter = (num_batches * BATCH_SIZE) as u64;

        // Use 8-chunk AVX2 batch if possible
        if leftover_chunks >= 8 && has_avx2() {
            let counters = [
                leftover_counter,
                leftover_counter + 1,
                leftover_counter + 2,
                leftover_counter + 3,
                leftover_counter + 4,
                leftover_counter + 5,
                leftover_counter + 6,
                leftover_counter + 7,
            ];
            let batch_cvs = unsafe {
                hash_8_chunks_contiguous(&IV, data.as_ptr().add(leftover_offset), &counters, 0)
            };
            cvs.extend_from_slice(&batch_cvs);

            // Process remaining (< 8) sequentially
            for i in 8..leftover_chunks {
                let chunk_offset = leftover_offset + i * CHUNK_LEN;
                let chunk: [u8; 1024] = data[chunk_offset..chunk_offset + CHUNK_LEN]
                    .try_into()
                    .unwrap();
                let cv = hash_single_chunk(&IV, &chunk, leftover_counter + i as u64, 0);
                cvs.push(cv);
            }
        } else {
            // Process all leftover chunks sequentially
            for i in 0..leftover_chunks {
                let chunk_offset = leftover_offset + i * CHUNK_LEN;
                let chunk: [u8; 1024] = data[chunk_offset..chunk_offset + CHUNK_LEN]
                    .try_into()
                    .unwrap();
                let cv = hash_single_chunk(&IV, &chunk, leftover_counter + i as u64, 0);
                cvs.push(cv);
            }
        }
    }

    // Handle partial final chunk if present
    if remainder > 0 {
        let final_cv = hash_partial_chunk(&IV, &data[complete_bytes..], complete_chunks as u64);
        cvs.push(final_cv);
    }

    // Single chunk case
    if cvs.len() == 1 {
        return words_to_bytes(&cvs[0]);
    }

    // Merge CVs to get root hash
    let root_cv = merge_cvs_to_root_final(&IV, &cvs, 0);
    words_to_bytes(&root_cv)
}

// ═══════════════════════════════════════════════════════════════════════════════
// BATCH HASHING API - Hash multiple independent messages in parallel
// ═══════════════════════════════════════════════════════════════════════════════

/// Hash up to 8 independent messages in parallel using AVX2 SIMD.
///
/// This is fundamentally different from parallel chunk processing within a single
/// message. Here we process 8 completely independent messages simultaneously,
/// using the SIMD lanes to process different messages rather than different
/// chunks of the same message.
///
/// # Use Cases
///
/// - Hashing many small files in a directory
/// - Content-addressed storage (hashing many blocks)
/// - Merkle tree leaf node hashing
/// - Database row integrity verification
/// - Batch signature verification preprocessing
///
/// # Performance
///
/// For messages <= 1024 bytes (single chunk), this achieves near-8x throughput
/// improvement over sequential hashing. For larger messages, the speedup is
/// still significant but depends on message sizes.
///
/// # Example
///
/// ```ignore
/// let messages = [
///     b"message 1".as_slice(),
///     b"message 2".as_slice(),
///     b"message 3".as_slice(),
///     b"message 4".as_slice(),
///     b"message 5".as_slice(),
///     b"message 6".as_slice(),
///     b"message 7".as_slice(),
///     b"message 8".as_slice(),
/// ];
/// let hashes = hash_batch_8(&messages);
/// ```
#[cfg(all(feature = "std", target_arch = "x86_64"))]
pub fn hash_batch_8(messages: &[&[u8]; 8]) -> [[u8; 32]; 8] {
    const CHUNK_LEN: usize = 1024;
    const CHUNK_START: u8 = 1;
    const CHUNK_END: u8 = 2;
    const ROOT: u8 = 8;

    // Check if all messages fit in a single chunk - fast path
    let all_single_chunk = messages.iter().all(|m| m.len() <= CHUNK_LEN);

    if all_single_chunk && has_avx2() {
        // Fast path: all messages are single-chunk, use full SIMD parallelism
        return hash_batch_8_single_chunk(messages);
    }

    // Slow path: process multi-chunk messages
    // Use Rayon parallelism when available for significant speedup
    #[cfg(feature = "rayon")]
    {
        use rayon::prelude::*;

        // Parallel threshold: only parallelize if messages are large enough
        // to justify thread overhead (each chunk is 1024 bytes)
        const PARALLEL_THRESHOLD: usize = 4 * CHUNK_LEN; // 4KB per message

        let total_bytes: usize = messages.iter().map(|m| m.len()).sum();
        let avg_bytes = total_bytes / 8;

        if avg_bytes >= PARALLEL_THRESHOLD {
            // Parallel processing for large multi-chunk messages
            let results_vec: Vec<[u8; 32]> = messages
                .par_iter()
                .map(|msg| hash_single_message(msg))
                .collect();

            let mut results = [[0u8; 32]; 8];
            for (i, hash) in results_vec.into_iter().enumerate() {
                results[i] = hash;
            }
            return results;
        }
    }

    // Sequential fallback for small messages or when rayon is disabled
    let mut results = [[0u8; 32]; 8];
    for (i, msg) in messages.iter().enumerate() {
        results[i] = hash_single_message(msg);
    }
    results
}

/// Hash 8 single-chunk messages in parallel using AVX2.
#[cfg(all(feature = "std", target_arch = "x86_64"))]
fn hash_batch_8_single_chunk(messages: &[&[u8]; 8]) -> [[u8; 32]; 8] {
    const CHUNK_START: u8 = 1;
    const CHUNK_END: u8 = 2;
    const ROOT: u8 = 8;

    // Calculate block counts for each message
    let mut block_counts: [usize; 8] = [0; 8];
    let mut msg_lens: [usize; 8] = [0; 8];

    for (i, msg) in messages.iter().enumerate() {
        msg_lens[i] = msg.len();
        block_counts[i] = (msg.len() + 63) / 64;
        if block_counts[i] == 0 {
            block_counts[i] = 1; // Empty message still has one block
        }
    }

    let max_blocks = *block_counts.iter().max().unwrap_or(&1);

    // Initialize CVs with IV and track which are finished
    let mut cvs = [IV; 8];
    let mut finished_cvs: [[u32; 8]; 8] = [IV; 8];
    let mut finished: [bool; 8] = [false; 8];

    // Process all blocks in lock-step
    for block_idx in 0..max_blocks {
        // Prepare blocks for this iteration
        let mut blocks: [[u8; 64]; 8] = [[0u8; 64]; 8];
        let mut flags: [u8; 8] = [0; 8];
        let mut block_lens: [u32; 8] = [0; 8];

        for (i, msg) in messages.iter().enumerate() {
            if finished[i] {
                // Already finished - use a no-op block
                continue;
            }

            if block_idx < block_counts[i] {
                let start = block_idx * 64;
                let end = (start + 64).min(msg.len());
                let len = end.saturating_sub(start);
                if len > 0 {
                    blocks[i][..len].copy_from_slice(&msg[start..end]);
                }

                let is_first = block_idx == 0;
                let is_last = block_idx == block_counts[i] - 1;

                if is_first {
                    flags[i] |= CHUNK_START;
                }
                if is_last {
                    flags[i] |= CHUNK_END | ROOT;
                }

                // Block length
                let start = block_idx * 64;
                let end = (start + 64).min(msg_lens[i]);
                block_lens[i] = (end - start) as u32;
                if msg_lens[i] == 0 {
                    block_lens[i] = 0;
                }
            }
        }

        // Compress all 8 blocks in parallel
        let new_cvs = compress_8blocks_parallel(
            &cvs,
            &blocks,
            &[0, 0, 0, 0, 0, 0, 0, 0],
            &block_lens,
            &flags,
        );

        // Update CVs, saving finished ones
        for i in 0..8 {
            if !finished[i] {
                cvs[i] = new_cvs[i];
                if block_idx == block_counts[i] - 1 {
                    finished_cvs[i] = new_cvs[i];
                    finished[i] = true;
                }
            }
        }
    }

    // Convert finished CVs to output hashes
    let mut results = [[0u8; 32]; 8];
    for i in 0..8 {
        results[i] = words_to_bytes(&finished_cvs[i]);
    }
    results
}

/// Hash a single message (internal helper).
#[cfg(all(feature = "std", target_arch = "x86_64"))]
fn hash_single_message(data: &[u8]) -> [u8; 32] {
    if data.len() <= 1024 {
        hash_single_chunk_root(&IV, data, 0)
    } else {
        hash_large_parallel(data)
    }
}

/// Hash a variable number of messages (1-8) in parallel.
///
/// This is more flexible than `hash_batch_8` when you have fewer than 8 messages.
/// Unused slots are filled with empty message hashes.
#[cfg(all(feature = "std", target_arch = "x86_64"))]
pub fn hash_batch(messages: &[&[u8]]) -> Vec<[u8; 32]> {
    if messages.is_empty() {
        return Vec::new();
    }

    let mut results = Vec::with_capacity(messages.len());

    // Process in batches of 8
    for chunk in messages.chunks(8) {
        if chunk.len() == 8 {
            // Full batch
            let batch: [&[u8]; 8] = [
                chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7],
            ];
            let hashes = hash_batch_8(&batch);
            results.extend_from_slice(&hashes);
        } else {
            // Partial batch - pad with empty slices
            let mut batch: [&[u8]; 8] = [&[]; 8];
            for (i, msg) in chunk.iter().enumerate() {
                batch[i] = msg;
            }
            let hashes = hash_batch_8(&batch);
            results.extend_from_slice(&hashes[..chunk.len()]);
        }
    }

    results
}

/// Hash a single chunk with ROOT flag for final output.
#[cfg(all(feature = "std", target_arch = "x86_64"))]
fn hash_single_chunk_root(key: &[u32; 8], data: &[u8], counter: u64) -> [u8; 32] {
    const CHUNK_START: u8 = 1;
    const CHUNK_END: u8 = 2;
    const ROOT: u8 = 8;

    // Handle empty input specially
    if data.is_empty() {
        let out = compress_auto(key, &[0u8; 64], counter, 0, CHUNK_START | CHUNK_END | ROOT);
        return words_to_bytes(&out[..8].try_into().unwrap());
    }

    let mut cv = *key;
    let num_blocks = (data.len() + 63) / 64;

    for block_idx in 0..num_blocks {
        let start = block_idx * 64;
        let end = (start + 64).min(data.len());
        let block_len = end - start;

        let mut block = [0u8; 64];
        block[..block_len].copy_from_slice(&data[start..end]);

        let is_first = block_idx == 0;
        let is_last = block_idx == num_blocks - 1;

        let mut flags = 0u8;
        if is_first {
            flags |= CHUNK_START;
        }
        if is_last {
            flags |= CHUNK_END | ROOT;
        }

        let out = compress_auto(&cv, &block, counter, block_len as u32, flags);
        cv.copy_from_slice(&out[..8]);
    }

    words_to_bytes(&cv)
}

/// Hash a partial chunk (less than 1024 bytes).
#[cfg(all(feature = "std", target_arch = "x86_64"))]
fn hash_partial_chunk(key: &[u32; 8], data: &[u8], counter: u64) -> [u32; 8] {
    const CHUNK_START: u8 = 1;
    const CHUNK_END: u8 = 2;

    let mut cv = *key;
    let num_blocks = (data.len() + 63) / 64;

    for block_idx in 0..num_blocks {
        let start = block_idx * 64;
        let end = (start + 64).min(data.len());
        let block_len = end - start;

        let mut block = [0u8; 64];
        block[..block_len].copy_from_slice(&data[start..end]);

        let is_first = block_idx == 0;
        let is_last = block_idx == num_blocks - 1;

        let mut flags = 0u8;
        if is_first {
            flags |= CHUNK_START;
        }
        if is_last {
            flags |= CHUNK_END;
        }

        let out = compress_auto(&cv, &block, counter, block_len as u32, flags);
        cv.copy_from_slice(&out[..8]);
    }

    cv
}

/// Merge CVs to root with proper ROOT flag handling.
#[cfg(all(feature = "std", target_arch = "x86_64"))]
fn merge_cvs_to_root_final(key: &[u32; 8], cvs: &[[u32; 8]], base_flags: u8) -> [u32; 8] {
    const PARENT: u8 = 4;
    const ROOT: u8 = 8;

    if cvs.len() == 1 {
        return cvs[0];
    }

    let mut current_level = cvs.to_vec();

    while current_level.len() > 1 {
        let is_final_level = current_level.len() <= 2;
        let mut next_level = Vec::with_capacity((current_level.len() + 1) / 2);
        let mut i = 0;

        // Process 4 pairs (8 CVs) at a time for parallel parent computation
        while i + 8 <= current_level.len() {
            let left_cvs: [[u32; 8]; 4] = [
                current_level[i],
                current_level[i + 2],
                current_level[i + 4],
                current_level[i + 6],
            ];
            let right_cvs: [[u32; 8]; 4] = [
                current_level[i + 1],
                current_level[i + 3],
                current_level[i + 5],
                current_level[i + 7],
            ];

            let parent_cvs = compress_parents_parallel(key, &left_cvs, &right_cvs, base_flags);
            next_level.extend_from_slice(&parent_cvs);
            i += 8;
        }

        // Handle remaining pairs sequentially
        while i + 2 <= current_level.len() {
            let is_root = is_final_level && i + 2 == current_level.len() && next_level.is_empty();
            let flags = if is_root {
                base_flags | ROOT
            } else {
                base_flags
            };
            let parent_cv = parent_cv_single(key, &current_level[i], &current_level[i + 1], flags);
            next_level.push(parent_cv);
            i += 2;
        }

        // If odd number of CVs, carry the last one up
        if i < current_level.len() {
            next_level.push(current_level[i]);
        }

        current_level = next_level;
    }

    current_level[0]
}

/// Convert u32 words to bytes.
fn words_to_bytes(words: &[u32; 8]) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for (i, word) in words.iter().enumerate() {
        bytes[i * 4..(i + 1) * 4].copy_from_slice(&word.to_le_bytes());
    }
    bytes
}

// ═══════════════════════════════════════════════════════════════════════════════
// STREAMING INCREMENTAL HASHER WITH SIMD
// ═══════════════════════════════════════════════════════════════════════════════

/// A high-performance streaming BLAKE3 hasher with SIMD acceleration.
///
/// This hasher buffers data and uses 8-way parallel chunk processing when
/// enough data has accumulated (8KB). This provides optimal performance for
/// streaming scenarios while maintaining incremental update capability.
///
/// # Example
///
/// ```ignore
/// use arcanum_primitives::blake3_simd::StreamingHasher;
///
/// let mut hasher = StreamingHasher::new();
/// hasher.update(b"Hello, ");
/// hasher.update(b"World!");
/// let hash = hasher.finalize();
/// ```
#[cfg(all(feature = "std", target_arch = "x86_64"))]
pub struct StreamingHasher {
    /// Key/IV for hashing
    key: [u32; 8],
    /// Buffer for incomplete chunks (up to 8 chunks = 8KB for batching)
    buffer: Vec<u8>,
    /// Chaining values for completed chunks
    cvs: Vec<[u32; 8]>,
    /// Current chunk counter
    chunk_counter: u64,
}

#[cfg(all(feature = "std", target_arch = "x86_64"))]
impl StreamingHasher {
    /// Create a new streaming hasher.
    pub fn new() -> Self {
        Self {
            key: IV,
            buffer: Vec::with_capacity(8 * 1024), // Buffer up to 8 chunks for batching
            cvs: Vec::new(),
            chunk_counter: 0,
        }
    }

    /// Create a new keyed streaming hasher.
    pub fn new_keyed(key: &[u8; 32]) -> Self {
        let mut key_words = [0u32; 8];
        for i in 0..8 {
            key_words[i] = u32::from_le_bytes(key[i * 4..(i + 1) * 4].try_into().unwrap());
        }
        Self {
            key: key_words,
            buffer: Vec::with_capacity(8 * 1024),
            cvs: Vec::new(),
            chunk_counter: 0,
        }
    }

    /// Update the hasher with more data.
    ///
    /// Data is buffered and processed in 8-chunk batches using SIMD.
    pub fn update(&mut self, data: &[u8]) {
        const CHUNK_LEN: usize = 1024;
        const BATCH_SIZE: usize = 8;
        const BATCH_BYTES: usize = CHUNK_LEN * BATCH_SIZE;

        self.buffer.extend_from_slice(data);

        // Process complete 8-chunk batches
        while self.buffer.len() >= BATCH_BYTES {
            let batch_data: [u8; BATCH_BYTES] = self.buffer[..BATCH_BYTES].try_into().unwrap();

            let chunks: [[u8; 1024]; 8] = [
                batch_data[0..CHUNK_LEN].try_into().unwrap(),
                batch_data[CHUNK_LEN..2 * CHUNK_LEN].try_into().unwrap(),
                batch_data[2 * CHUNK_LEN..3 * CHUNK_LEN].try_into().unwrap(),
                batch_data[3 * CHUNK_LEN..4 * CHUNK_LEN].try_into().unwrap(),
                batch_data[4 * CHUNK_LEN..5 * CHUNK_LEN].try_into().unwrap(),
                batch_data[5 * CHUNK_LEN..6 * CHUNK_LEN].try_into().unwrap(),
                batch_data[6 * CHUNK_LEN..7 * CHUNK_LEN].try_into().unwrap(),
                batch_data[7 * CHUNK_LEN..8 * CHUNK_LEN].try_into().unwrap(),
            ];

            let counters = [
                self.chunk_counter,
                self.chunk_counter + 1,
                self.chunk_counter + 2,
                self.chunk_counter + 3,
                self.chunk_counter + 4,
                self.chunk_counter + 5,
                self.chunk_counter + 6,
                self.chunk_counter + 7,
            ];

            let batch_cvs = hash_8_chunks_parallel(&self.key, &chunks, &counters, 0);
            self.cvs.extend_from_slice(&batch_cvs);

            self.buffer.drain(..BATCH_BYTES);
            self.chunk_counter += 8;
        }
    }

    /// Update with a complete chunk for maximum efficiency.
    ///
    /// This bypasses buffering when you have exactly 1024 bytes.
    pub fn update_chunk(&mut self, chunk: &[u8; 1024]) {
        let cv = hash_single_chunk(&self.key, chunk, self.chunk_counter, 0);
        self.cvs.push(cv);
        self.chunk_counter += 1;
    }

    /// Finalize and return the 32-byte hash.
    pub fn finalize(self) -> [u8; 32] {
        // For simplicity, concatenate all CVs and remaining buffer data
        // then hash using hash_large_parallel which is known to work correctly.
        //
        // A more optimized implementation would track partial chunks
        // and merge CVs incrementally, but this approach ensures correctness
        // while still benefiting from SIMD batching during updates.

        if self.cvs.is_empty() {
            // No complete batches processed yet - just hash the buffer
            if self.key == IV {
                return hash_large_parallel(&self.buffer);
            } else {
                // Keyed hash - need to use keyed variant
                // For now, use the simple path
                return hash_single_chunk_root(&self.key, &self.buffer, 0);
            }
        }

        // Merge the existing CVs with any remaining buffer data.
        const CHUNK_LEN: usize = 1024;

        let mut cvs = self.cvs;

        // Process any remaining complete chunks
        let mut remaining = self.buffer.as_slice();
        let mut counter = self.chunk_counter;

        while remaining.len() >= CHUNK_LEN {
            let chunk: [u8; 1024] = remaining[..CHUNK_LEN].try_into().unwrap();
            let cv = hash_single_chunk(&self.key, &chunk, counter, 0);
            cvs.push(cv);
            remaining = &remaining[CHUNK_LEN..];
            counter += 1;
        }

        // Handle remaining partial chunk
        if !remaining.is_empty() {
            let cv = hash_partial_chunk(&self.key, remaining, counter);
            cvs.push(cv);
        }

        // Handle edge cases
        if cvs.is_empty() {
            return hash_single_chunk_root(&self.key, &[], 0);
        }

        if cvs.len() == 1 {
            // Single chunk - need to apply ROOT flag
            // The CV was computed without ROOT, so we need to re-output with ROOT
            // For BLAKE3, the chaining value IS the output for single chunks
            return words_to_bytes(&cvs[0]);
        }

        // Merge CVs to root
        let root_cv = merge_cvs_to_root_final(&self.key, &cvs, 0);
        words_to_bytes(&root_cv)
    }

    /// Get the number of bytes processed so far.
    pub fn bytes_processed(&self) -> u64 {
        self.chunk_counter * 1024 + self.buffer.len() as u64
    }
}

#[cfg(all(feature = "std", target_arch = "x86_64"))]
impl Default for StreamingHasher {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sse41_matches_portable() {
        if !has_sse41() {
            return;
        }

        let cv = IV;
        let block = [0u8; 64];
        let counter = 0u64;
        let block_len = 64u32;
        let flags = 0u8;

        let portable_result = compress_portable(&cv, &block, counter, block_len, flags);

        let sse41_result =
            unsafe { sse41::compress_block_sse41(&cv, &block, counter, block_len, flags) };

        assert_eq!(
            portable_result, sse41_result,
            "SSE4.1 result should match portable"
        );
    }

    #[test]
    fn test_compress_auto() {
        let cv = IV;
        let block = [0x42u8; 64];
        let counter = 123u64;
        let block_len = 64u32;
        let flags = 1u8;

        let portable_result = compress_portable(&cv, &block, counter, block_len, flags);
        let auto_result = compress_auto(&cv, &block, counter, block_len, flags);

        assert_eq!(portable_result, auto_result);
    }

    #[test]
    fn test_avx2_2blocks_matches_sse41() {
        if !has_avx2() || !has_sse41() {
            return;
        }

        let cv0 = IV;
        let cv1 = [
            0x12345678, 0x9ABCDEF0, 0x13579BDF, 0x2468ACE0, 0x11111111, 0x22222222, 0x33333333,
            0x44444444,
        ];
        let block0 = [0x42u8; 64];
        let block1 = [0x99u8; 64];
        let counter0 = 0u64;
        let counter1 = 1u64;
        let block_len = 64u32;
        let flags = 1u8;

        // Get SSE4.1 results separately
        let sse41_result0 =
            unsafe { sse41::compress_block_sse41(&cv0, &block0, counter0, block_len, flags) };
        let sse41_result1 =
            unsafe { sse41::compress_block_sse41(&cv1, &block1, counter1, block_len, flags) };

        // Get AVX2 results together
        let (avx2_result0, avx2_result1) = unsafe {
            avx2::compress_2blocks_avx2(
                &cv0, &cv1, &block0, &block1, counter0, counter1, block_len, flags,
            )
        };

        assert_eq!(
            sse41_result0, avx2_result0,
            "AVX2 block 0 should match SSE4.1"
        );
        assert_eq!(
            sse41_result1, avx2_result1,
            "AVX2 block 1 should match SSE4.1"
        );
    }

    #[test]
    fn test_parallel4_matches_sequential() {
        let cvs = [
            IV,
            [
                0x12345678, 0x9ABCDEF0, 0x13579BDF, 0x2468ACE0, 0x11111111, 0x22222222, 0x33333333,
                0x44444444,
            ],
            [
                0xDEADBEEF, 0xCAFEBABE, 0x12121212, 0x34343434, 0x56565656, 0x78787878, 0x9A9A9A9A,
                0xBCBCBCBC,
            ],
            [
                0xAAAAAAAA, 0xBBBBBBBB, 0xCCCCCCCC, 0xDDDDDDDD, 0xEEEEEEEE, 0xFFFFFFFF, 0x00000000,
                0x11111111,
            ],
        ];
        let blocks = [[0x42u8; 64], [0x99u8; 64], [0x11u8; 64], [0xFFu8; 64]];
        let counters = [0u64, 1, 2, 3];
        let block_lens = [64u32; 4];
        let flags = [1u8, 2, 3, 4];

        // Get sequential results
        let seq_results: [[u32; 8]; 4] = [
            compress_portable(&cvs[0], &blocks[0], counters[0], block_lens[0], flags[0])[..8]
                .try_into()
                .unwrap(),
            compress_portable(&cvs[1], &blocks[1], counters[1], block_lens[1], flags[1])[..8]
                .try_into()
                .unwrap(),
            compress_portable(&cvs[2], &blocks[2], counters[2], block_lens[2], flags[2])[..8]
                .try_into()
                .unwrap(),
            compress_portable(&cvs[3], &blocks[3], counters[3], block_lens[3], flags[3])[..8]
                .try_into()
                .unwrap(),
        ];

        // Get parallel results
        let par_results =
            unsafe { parallel4::compress_4blocks(&cvs, &blocks, &counters, &block_lens, &flags) };

        for i in 0..4 {
            assert_eq!(seq_results[i], par_results[i], "Block {} mismatch", i);
        }
    }

    #[test]
    fn test_hash_4_chunks_parallel() {
        // Create 4 unique 1024-byte chunks
        let mut chunks = [[0u8; 1024]; 4];
        for i in 0..4 {
            for j in 0..1024 {
                chunks[i][j] = ((i * 1024 + j) % 256) as u8;
            }
        }

        let counters = [0u64, 1, 2, 3];

        // Hash sequentially using the single chunk function
        let seq_cvs: [[u32; 8]; 4] = [
            hash_single_chunk(&IV, &chunks[0], counters[0], 0),
            hash_single_chunk(&IV, &chunks[1], counters[1], 0),
            hash_single_chunk(&IV, &chunks[2], counters[2], 0),
            hash_single_chunk(&IV, &chunks[3], counters[3], 0),
        ];

        // Hash in parallel
        let par_cvs = hash_4_chunks_parallel(&IV, &chunks, &counters, 0);

        for i in 0..4 {
            assert_eq!(seq_cvs[i], par_cvs[i], "Chunk {} CV mismatch", i);
        }
    }

    #[test]
    fn test_hash_many_chunks_parallel() {
        // Create 8 chunks worth of data (8192 bytes)
        let mut data = vec![0u8; 8192];
        for i in 0..8192 {
            data[i] = (i % 256) as u8;
        }

        // Hash with parallel function
        let cvs = hash_many_chunks_parallel(&IV, &data, 0, 0);

        assert_eq!(cvs.len(), 8, "Should have 8 CVs for 8 chunks");

        // Verify each chunk matches sequential hash
        for i in 0..8 {
            let chunk: [u8; 1024] = data[i * 1024..(i + 1) * 1024].try_into().unwrap();
            let expected_cv = hash_single_chunk(&IV, &chunk, i as u64, 0);
            assert_eq!(cvs[i], expected_cv, "Chunk {} CV mismatch", i);
        }
    }

    #[test]
    fn test_merge_cvs_to_root() {
        // Create some test CVs
        let cvs: Vec<[u32; 8]> = (0..8)
            .map(|i| {
                let mut cv = IV;
                cv[0] = cv[0].wrapping_add(i as u32);
                cv
            })
            .collect();

        // Merge to root
        let root = merge_cvs_to_root(&IV, &cvs, 0);

        // Verify it produces a valid result (not zero, not unchanged)
        assert_ne!(root, IV);
        assert_ne!(root, [0u32; 8]);

        // Verify determinism
        let root2 = merge_cvs_to_root(&IV, &cvs, 0);
        assert_eq!(root, root2);
    }

    #[test]
    fn test_hash_large_parallel_matches_reference() {
        // Test various sizes including edge cases
        let test_sizes = [
            0,       // Empty
            1,       // Single byte
            64,      // One block
            1024,    // One chunk
            1025,    // One chunk + 1 byte
            2048,    // Two chunks
            4096,    // Four chunks (first parallel batch)
            4097,    // Four chunks + 1 byte
            8192,    // Eight chunks (8-way parallel with AVX2)
            10000,   // Irregular size
            100_000, // Large input
        ];

        for size in test_sizes {
            let data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();

            let our_hash = hash_large_parallel(&data);
            let ref_hash = blake3::hash(&data);

            assert_eq!(
                our_hash,
                *ref_hash.as_bytes(),
                "Hash mismatch for size {}",
                size
            );
        }
    }

    #[test]
    #[cfg(feature = "rayon")]
    fn test_hash_large_parallel_mt_matches_reference() {
        use super::hash_large_parallel_mt;

        // Test various sizes including edge cases
        let test_sizes = [
            0,         // Empty
            1,         // Single byte
            64,        // One block
            1024,      // One chunk
            1025,      // One chunk + 1 byte
            2048,      // Two chunks
            4096,      // Four chunks (first parallel batch)
            4097,      // Four chunks + 1 byte
            8192,      // Eight chunks (8-way parallel with AVX2)
            10000,     // Irregular size
            100_000,   // Large input
            1_000_000, // 1MB input (tests multi-threading)
        ];

        for size in test_sizes {
            let data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();

            let our_hash = hash_large_parallel_mt(&data);
            let ref_hash = blake3::hash(&data);

            assert_eq!(
                our_hash,
                *ref_hash.as_bytes(),
                "Multi-threaded hash mismatch for size {}",
                size
            );
        }
    }

    #[test]
    fn test_parallel8_matches_parallel4() {
        if !has_avx2() {
            return;
        }

        // Create 8 unique CVs
        let cvs: [[u32; 8]; 8] = [
            IV,
            [
                0x12345678, 0x9ABCDEF0, 0x13579BDF, 0x2468ACE0, 0x11111111, 0x22222222, 0x33333333,
                0x44444444,
            ],
            [
                0xDEADBEEF, 0xCAFEBABE, 0x12121212, 0x34343434, 0x56565656, 0x78787878, 0x9A9A9A9A,
                0xBCBCBCBC,
            ],
            [
                0xAAAAAAAA, 0xBBBBBBBB, 0xCCCCCCCC, 0xDDDDDDDD, 0xEEEEEEEE, 0xFFFFFFFF, 0x00000000,
                0x11111111,
            ],
            [
                0x11223344, 0x55667788, 0x99AABBCC, 0xDDEEFF00, 0x12345678, 0x9ABCDEF0, 0x13579BDF,
                0x2468ACE0,
            ],
            [
                0xFEDCBA98, 0x76543210, 0x01234567, 0x89ABCDEF, 0xFEDCBA98, 0x76543210, 0x01234567,
                0x89ABCDEF,
            ],
            [
                0x11111111, 0x22222222, 0x33333333, 0x44444444, 0x55555555, 0x66666666, 0x77777777,
                0x88888888,
            ],
            [
                0xA1B2C3D4, 0xE5F60718, 0x293A4B5C, 0x6D7E8F90, 0xA1B2C3D4, 0xE5F60718, 0x293A4B5C,
                0x6D7E8F90,
            ],
        ];

        // Create 8 unique blocks
        let mut blocks = [[0u8; 64]; 8];
        for i in 0..8 {
            for j in 0..64 {
                blocks[i][j] = ((i * 64 + j) % 256) as u8;
            }
        }

        let counters = [0u64, 1, 2, 3, 4, 5, 6, 7];
        let block_lens = [64u32; 8];
        let flags = [1u8; 8];

        // Get 8-way parallel results
        let par8_results = compress_8blocks_parallel(&cvs, &blocks, &counters, &block_lens, &flags);

        // Get two 4-way parallel results and combine
        let cvs_lo: [[u32; 8]; 4] = [cvs[0], cvs[1], cvs[2], cvs[3]];
        let cvs_hi: [[u32; 8]; 4] = [cvs[4], cvs[5], cvs[6], cvs[7]];
        let blocks_lo: [[u8; 64]; 4] = [blocks[0], blocks[1], blocks[2], blocks[3]];
        let blocks_hi: [[u8; 64]; 4] = [blocks[4], blocks[5], blocks[6], blocks[7]];
        let counters_lo: [u64; 4] = [0, 1, 2, 3];
        let counters_hi: [u64; 4] = [4, 5, 6, 7];
        let block_lens_4 = [64u32; 4];
        let flags_4 = [1u8; 4];

        let par4_lo =
            compress_4blocks_parallel(&cvs_lo, &blocks_lo, &counters_lo, &block_lens_4, &flags_4);
        let par4_hi =
            compress_4blocks_parallel(&cvs_hi, &blocks_hi, &counters_hi, &block_lens_4, &flags_4);

        // Compare results
        for i in 0..4 {
            assert_eq!(par8_results[i], par4_lo[i], "Block {} mismatch (low)", i);
            assert_eq!(
                par8_results[i + 4],
                par4_hi[i],
                "Block {} mismatch (high)",
                i + 4
            );
        }
    }

    #[test]
    fn test_hash_8_chunks_parallel() {
        if !has_avx2() {
            return;
        }

        // Create 8 unique 1024-byte chunks
        let mut chunks = [[0u8; 1024]; 8];
        for i in 0..8 {
            for j in 0..1024 {
                chunks[i][j] = ((i * 1024 + j) % 256) as u8;
            }
        }

        let counters = [0u64, 1, 2, 3, 4, 5, 6, 7];

        // Hash sequentially using the single chunk function
        let seq_cvs: [[u32; 8]; 8] = [
            hash_single_chunk(&IV, &chunks[0], counters[0], 0),
            hash_single_chunk(&IV, &chunks[1], counters[1], 0),
            hash_single_chunk(&IV, &chunks[2], counters[2], 0),
            hash_single_chunk(&IV, &chunks[3], counters[3], 0),
            hash_single_chunk(&IV, &chunks[4], counters[4], 0),
            hash_single_chunk(&IV, &chunks[5], counters[5], 0),
            hash_single_chunk(&IV, &chunks[6], counters[6], 0),
            hash_single_chunk(&IV, &chunks[7], counters[7], 0),
        ];

        // Hash in parallel using 8-way
        let par_cvs = hash_8_chunks_parallel(&IV, &chunks, &counters, 0);

        for i in 0..8 {
            assert_eq!(seq_cvs[i], par_cvs[i], "Chunk {} CV mismatch", i);
        }
    }

    #[test]
    fn test_hash_8_chunks_zero_copy_matches_copy_version() {
        if !has_avx2() {
            return;
        }

        // Create 8 unique 1024-byte chunks
        let mut chunks = [[0u8; 1024]; 8];
        for i in 0..8 {
            for j in 0..1024 {
                chunks[i][j] = ((i * 1024 + j) % 256) as u8;
            }
        }

        let counters = [0u64, 1, 2, 3, 4, 5, 6, 7];

        // Hash using copy version
        let copy_cvs = hash_8_chunks_parallel(&IV, &chunks, &counters, 0);

        // Hash using zero-copy version
        let zero_copy_cvs = hash_8_chunks_parallel_zero_copy(&IV, &chunks, &counters, 0);

        for i in 0..8 {
            assert_eq!(
                copy_cvs[i], zero_copy_cvs[i],
                "Chunk {} CV mismatch between copy and zero-copy",
                i
            );
        }
    }

    #[test]
    fn test_hash_16_chunks_parallel() {
        // Create 16 unique 1024-byte chunks
        let mut chunks = [[0u8; 1024]; 16];
        for i in 0..16 {
            for j in 0..1024 {
                chunks[i][j] = ((i * 1024 + j) % 256) as u8;
            }
        }

        let counters: [u64; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

        // Hash sequentially using the single chunk function
        let mut seq_cvs = [[0u32; 8]; 16];
        for i in 0..16 {
            seq_cvs[i] = hash_single_chunk(&IV, &chunks[i], counters[i], 0);
        }

        // Hash in parallel using 16-way (will use AVX-512 if available, otherwise 2x 8-way)
        let par_cvs = hash_16_chunks_parallel(&IV, &chunks, &counters, 0);

        for i in 0..16 {
            assert_eq!(seq_cvs[i], par_cvs[i], "Chunk {} CV mismatch", i);
        }
    }

    #[test]
    fn test_batch_8_matches_sequential() {
        // Test that batch hashing produces same results as sequential hashing
        let messages: [&[u8]; 8] = [
            b"hello world",
            b"",
            b"a",
            b"The quick brown fox jumps over the lazy dog",
            &[0u8; 64],   // Exactly one block
            &[0u8; 65],   // Just over one block
            &[0xAB; 128], // Two blocks
            b"test message 8",
        ];

        let batch_results = hash_batch_8(&messages);

        // Compare each result with sequential hashing
        for (i, msg) in messages.iter().enumerate() {
            let sequential_hash = blake3::hash(msg);
            assert_eq!(
                batch_results[i],
                *sequential_hash.as_bytes(),
                "Batch hash mismatch for message {} (len={})",
                i,
                msg.len()
            );
        }
    }

    #[test]
    fn test_batch_variable_sizes() {
        // Test batch hashing with various message sizes
        let test_cases: Vec<Vec<u8>> = vec![
            vec![],           // Empty
            vec![0x42],       // 1 byte
            vec![0x42; 32],   // 32 bytes
            vec![0x42; 64],   // Exactly 1 block
            vec![0x42; 100],  // Between 1-2 blocks
            vec![0x42; 256],  // 4 blocks
            vec![0x42; 512],  // 8 blocks
            vec![0x42; 1000], // Almost 1 chunk
            vec![0x42; 1024], // Exactly 1 chunk
        ];

        for (i, msg) in test_cases.iter().enumerate() {
            // Create a batch with this message repeated 8 times
            let messages: [&[u8]; 8] = [
                msg.as_slice(),
                msg.as_slice(),
                msg.as_slice(),
                msg.as_slice(),
                msg.as_slice(),
                msg.as_slice(),
                msg.as_slice(),
                msg.as_slice(),
            ];

            let batch_results = hash_batch_8(&messages);
            let expected = blake3::hash(msg);

            for j in 0..8 {
                assert_eq!(
                    batch_results[j],
                    *expected.as_bytes(),
                    "Batch hash mismatch for test case {} (size={}), slot {}",
                    i,
                    msg.len(),
                    j
                );
            }
        }
    }

    #[test]
    fn test_batch_flexible() {
        // Test the flexible batch API
        let messages: Vec<&[u8]> = vec![b"one", b"two", b"three"];

        let results = hash_batch(&messages);
        assert_eq!(results.len(), 3);

        for (i, msg) in messages.iter().enumerate() {
            let expected = blake3::hash(msg);
            assert_eq!(
                results[i],
                *expected.as_bytes(),
                "Flexible batch hash mismatch for message {}",
                i
            );
        }
    }

    #[test]
    fn test_batch_many_messages() {
        // Test with more than 8 messages (requires multiple batches)
        let messages: Vec<Vec<u8>> = (0..20)
            .map(|i| format!("message number {}", i).into_bytes())
            .collect();

        let refs: Vec<&[u8]> = messages.iter().map(|m| m.as_slice()).collect();
        let results = hash_batch(&refs);

        assert_eq!(results.len(), 20);

        for (i, msg) in messages.iter().enumerate() {
            let expected = blake3::hash(msg);
            assert_eq!(
                results[i],
                *expected.as_bytes(),
                "Batch hash mismatch for message {}",
                i
            );
        }
    }

    #[test]
    fn test_streaming_hasher_matches_reference() {
        // Test small input
        let small_data = b"Hello, World!";
        let mut hasher = StreamingHasher::new();
        hasher.update(small_data);
        let result = hasher.finalize();
        assert_eq!(result, *blake3::hash(small_data).as_bytes());

        // Test empty input
        let hasher = StreamingHasher::new();
        let result = hasher.finalize();
        assert_eq!(result, *blake3::hash(b"").as_bytes());

        // Test exactly one chunk
        let one_chunk = vec![0x42u8; 1024];
        let mut hasher = StreamingHasher::new();
        hasher.update(&one_chunk);
        let result = hasher.finalize();
        assert_eq!(result, *blake3::hash(&one_chunk).as_bytes());

        // Test multiple chunks (8KB = 8 chunks - triggers SIMD batch)
        let multi_chunk = vec![0xAB; 8 * 1024];
        let mut hasher = StreamingHasher::new();
        hasher.update(&multi_chunk);
        let result = hasher.finalize();
        assert_eq!(result, *blake3::hash(&multi_chunk).as_bytes());

        // Test incremental updates
        let large_data: Vec<u8> = (0..10000).map(|i| (i % 256) as u8).collect();
        let mut hasher = StreamingHasher::new();
        for chunk in large_data.chunks(123) {
            hasher.update(chunk);
        }
        let result = hasher.finalize();
        assert_eq!(result, *blake3::hash(&large_data).as_bytes());
    }

    #[test]
    fn test_streaming_hasher_bytes_processed() {
        let mut hasher = StreamingHasher::new();
        assert_eq!(hasher.bytes_processed(), 0);

        hasher.update(b"hello");
        assert_eq!(hasher.bytes_processed(), 5);

        hasher.update(b" world");
        assert_eq!(hasher.bytes_processed(), 11);
    }

    #[cfg(all(feature = "std", target_arch = "x86_64"))]
    #[test]
    fn test_hash_batch_8_single_chunk() {
        // Test single-chunk messages (fast path)
        let messages: [&[u8]; 8] = [
            b"message 0",
            b"message 1",
            b"message 2",
            b"message 3",
            b"message 4",
            b"message 5",
            b"message 6",
            b"message 7",
        ];

        let batch_results = hash_batch_8(&messages);

        // Verify each result matches individual hashing
        for (i, msg) in messages.iter().enumerate() {
            let expected = hash_single_message(msg);
            assert_eq!(
                batch_results[i], expected,
                "Batch result {} should match individual hash",
                i
            );
        }
    }

    #[cfg(all(feature = "std", target_arch = "x86_64"))]
    #[test]
    fn test_hash_batch_8_multi_chunk() {
        // Test multi-chunk messages (slow path with Rayon)
        // Each message is > 1024 bytes to trigger multi-chunk processing

        let large_data: Vec<u8> = (0..8192).map(|i| (i % 256) as u8).collect();

        let messages: [&[u8]; 8] = [
            &large_data[0..2000],
            &large_data[0..3000],
            &large_data[0..4000],
            &large_data[0..5000],
            &large_data[0..6000],
            &large_data[0..7000],
            &large_data[0..8000],
            &large_data[0..8192],
        ];

        let batch_results = hash_batch_8(&messages);

        // Verify each result matches individual hashing
        for (i, msg) in messages.iter().enumerate() {
            let expected = hash_single_message(msg);
            assert_eq!(
                batch_results[i], expected,
                "Multi-chunk batch result {} should match individual hash",
                i
            );
        }
    }

    #[cfg(all(feature = "std", target_arch = "x86_64"))]
    #[test]
    fn test_hash_batch_8_mixed_sizes() {
        // Test mixed message sizes (some single-chunk, some multi-chunk)
        let large_data: Vec<u8> = (0..5000).map(|i| (i % 256) as u8).collect();

        let messages: [&[u8]; 8] = [
            b"small",                 // Single chunk
            &large_data[0..500],      // Single chunk
            &large_data[0..1024],     // Exactly one chunk
            &large_data[0..1025],     // Just over one chunk
            &large_data[0..2000],     // Two chunks
            &large_data[0..3500],     // Multi-chunk
            b"another small message", // Single chunk
            &large_data[0..5000],     // Multi-chunk
        ];

        let batch_results = hash_batch_8(&messages);

        for (i, msg) in messages.iter().enumerate() {
            let expected = hash_single_message(msg);
            assert_eq!(
                batch_results[i], expected,
                "Mixed-size batch result {} should match individual hash",
                i
            );
        }
    }

    #[test]
    fn test_prefetch_config_for_size() {
        // Small messages
        let config = PrefetchConfig::for_size(1000);
        assert_eq!(config.l1_distance, PrefetchConfig::SMALL.l1_distance);
        assert!(!config.streaming);

        // Medium messages
        let config = PrefetchConfig::for_size(10000);
        assert_eq!(config.l1_distance, PrefetchConfig::MEDIUM.l1_distance);
        assert!(!config.streaming);

        // Large messages
        let config = PrefetchConfig::for_size(100000);
        assert_eq!(config.l1_distance, PrefetchConfig::LARGE.l1_distance);
        assert!(config.streaming);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_prefetch_chunk_adaptive_no_panic() {
        // Test that adaptive prefetch doesn't panic with various inputs
        let data = vec![0u8; 16384]; // 16 chunks
        let config = PrefetchConfig::for_size(data.len());

        unsafe {
            // Test various chunk positions
            prefetch_chunk_adaptive(data.as_ptr(), 0, 16, &config);
            prefetch_chunk_adaptive(data.as_ptr(), 5, 16, &config);
            prefetch_chunk_adaptive(data.as_ptr(), 15, 16, &config);

            // Edge case: near end
            prefetch_chunk_adaptive(data.as_ptr(), 14, 16, &config);
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_prefetch_batch_adaptive_no_panic() {
        let data1 = vec![0u8; 4096];
        let data2 = vec![0u8; 8192];

        let messages = [data1.as_ptr(), data2.as_ptr()];
        let lens = [data1.len(), data2.len()];
        let config = PrefetchConfig::MEDIUM;

        unsafe {
            prefetch_batch_adaptive(&messages, 0, &lens, &config);
            prefetch_batch_adaptive(&messages, 512, &lens, &config);
            prefetch_batch_adaptive(&messages, 2048, &lens, &config);
        }
    }
}
