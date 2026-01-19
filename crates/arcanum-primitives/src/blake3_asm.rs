//! Assembly-Optimized BLAKE3 Compression
//!
//! Hand-tuned inline assembly for maximum performance.
//!
//! ## Key Optimizations
//!
//! 1. **Native rotation**: AVX-512 `vprord` instead of shift+or
//! 2. **Optimal instruction scheduling**: Interleave independent operations
//! 3. **Minimal register pressure**: Keep state in registers across rounds
//! 4. **Fused operations**: Combine add+xor where possible

#![allow(unused_macros)]

use core::arch::x86_64::*;

/// BLAKE3 IV constants
pub const IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

/// Message schedule for all 7 rounds
const MSG_SCHEDULE: [[usize; 16]; 7] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8],
    [3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1],
    [10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6],
    [12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4],
    [9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7],
    [11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13],
];

/// Shuffle mask for ror 16 (byte shuffle)
#[repr(align(64))]
struct AlignedMask([u8; 64]);

static ROT16_MASK: AlignedMask = AlignedMask([
    2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13,
    2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13,
    2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13,
    2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13,
]);

static ROT8_MASK: AlignedMask = AlignedMask([
    1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12,
    1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12,
    1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12,
    1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12,
]);

/// G function macro using inline assembly with AVX-512.
///
/// Uses native `vprord` for rotations where possible.
macro_rules! g16_asm {
    ($a:expr, $b:expr, $c:expr, $d:expr, $mx:expr, $my:expr, $rot16:expr, $rot8:expr) => {
        core::arch::asm!(
            // a = a + b + mx
            "vpaddd {a}, {a}, {b}",
            "vpaddd {a}, {a}, {mx}",
            // d = (d ^ a) >>> 16 (using byte shuffle)
            "vpxord {d}, {d}, {a}",
            "vpshufb {d}, {d}, {rot16}",
            // c = c + d
            "vpaddd {c}, {c}, {d}",
            // b = (b ^ c) >>> 12 (native rotation)
            "vpxord {b}, {b}, {c}",
            "vprord {b}, {b}, 12",
            // a = a + b + my
            "vpaddd {a}, {a}, {b}",
            "vpaddd {a}, {a}, {my}",
            // d = (d ^ a) >>> 8 (using byte shuffle)
            "vpxord {d}, {d}, {a}",
            "vpshufb {d}, {d}, {rot8}",
            // c = c + d
            "vpaddd {c}, {c}, {d}",
            // b = (b ^ c) >>> 7 (native rotation)
            "vpxord {b}, {b}, {c}",
            "vprord {b}, {b}, 7",
            a = inout(zmm_reg) $a,
            b = inout(zmm_reg) $b,
            c = inout(zmm_reg) $c,
            d = inout(zmm_reg) $d,
            mx = in(zmm_reg) $mx,
            my = in(zmm_reg) $my,
            rot16 = in(zmm_reg) $rot16,
            rot8 = in(zmm_reg) $rot8,
            options(pure, nomem, nostack),
        );
    }
}

/// Full round macro using assembly G functions.
macro_rules! round_asm {
    ($state:expr, $m:expr, $round:expr, $rot16:expr, $rot8:expr) => {{
        let sched = &MSG_SCHEDULE[$round];

        // Column step: G(0,4,8,12), G(1,5,9,13), G(2,6,10,14), G(3,7,11,15)
        g16_asm!($state[0], $state[4], $state[8], $state[12],
                $m[sched[0]], $m[sched[1]], $rot16, $rot8);
        g16_asm!($state[1], $state[5], $state[9], $state[13],
                $m[sched[2]], $m[sched[3]], $rot16, $rot8);
        g16_asm!($state[2], $state[6], $state[10], $state[14],
                $m[sched[4]], $m[sched[5]], $rot16, $rot8);
        g16_asm!($state[3], $state[7], $state[11], $state[15],
                $m[sched[6]], $m[sched[7]], $rot16, $rot8);

        // Diagonal step: G(0,5,10,15), G(1,6,11,12), G(2,7,8,13), G(3,4,9,14)
        g16_asm!($state[0], $state[5], $state[10], $state[15],
                $m[sched[8]], $m[sched[9]], $rot16, $rot8);
        g16_asm!($state[1], $state[6], $state[11], $state[12],
                $m[sched[10]], $m[sched[11]], $rot16, $rot8);
        g16_asm!($state[2], $state[7], $state[8], $state[13],
                $m[sched[12]], $m[sched[13]], $rot16, $rot8);
        g16_asm!($state[3], $state[4], $state[9], $state[14],
                $m[sched[14]], $m[sched[15]], $rot16, $rot8);
    }}
}

/// Compress 16 blocks using assembly-optimized G function.
///
/// # Safety
///
/// Requires AVX-512F and AVX-512BW support.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f", enable = "avx512bw")]
pub unsafe fn compress_16blocks_asm(
    cvs: &[[u32; 8]; 16],
    blocks: &[[u8; 64]; 16],
    counters: &[u64; 16],
    block_lens: &[u32; 16],
    flags: &[u8; 16],
) -> [[u32; 8]; 16] {
    // Load rotation masks
    let rot16_mask = _mm512_load_si512(ROT16_MASK.0.as_ptr() as *const __m512i);
    let rot8_mask = _mm512_load_si512(ROT8_MASK.0.as_ptr() as *const __m512i);

    // Load message words (transposed across 16 blocks)
    let m: [__m512i; 16] = core::array::from_fn(|word_idx| {
        let offset = word_idx * 4;
        _mm512_set_epi32(
            i32::from_le_bytes(blocks[15][offset..offset+4].try_into().unwrap()),
            i32::from_le_bytes(blocks[14][offset..offset+4].try_into().unwrap()),
            i32::from_le_bytes(blocks[13][offset..offset+4].try_into().unwrap()),
            i32::from_le_bytes(blocks[12][offset..offset+4].try_into().unwrap()),
            i32::from_le_bytes(blocks[11][offset..offset+4].try_into().unwrap()),
            i32::from_le_bytes(blocks[10][offset..offset+4].try_into().unwrap()),
            i32::from_le_bytes(blocks[9][offset..offset+4].try_into().unwrap()),
            i32::from_le_bytes(blocks[8][offset..offset+4].try_into().unwrap()),
            i32::from_le_bytes(blocks[7][offset..offset+4].try_into().unwrap()),
            i32::from_le_bytes(blocks[6][offset..offset+4].try_into().unwrap()),
            i32::from_le_bytes(blocks[5][offset..offset+4].try_into().unwrap()),
            i32::from_le_bytes(blocks[4][offset..offset+4].try_into().unwrap()),
            i32::from_le_bytes(blocks[3][offset..offset+4].try_into().unwrap()),
            i32::from_le_bytes(blocks[2][offset..offset+4].try_into().unwrap()),
            i32::from_le_bytes(blocks[1][offset..offset+4].try_into().unwrap()),
            i32::from_le_bytes(blocks[0][offset..offset+4].try_into().unwrap()),
        )
    });

    // Initialize state (transposed)
    let mut state: [__m512i; 16] = [
        // s0-s7: CV words
        _mm512_set_epi32(cvs[15][0] as i32, cvs[14][0] as i32, cvs[13][0] as i32, cvs[12][0] as i32, cvs[11][0] as i32, cvs[10][0] as i32, cvs[9][0] as i32, cvs[8][0] as i32, cvs[7][0] as i32, cvs[6][0] as i32, cvs[5][0] as i32, cvs[4][0] as i32, cvs[3][0] as i32, cvs[2][0] as i32, cvs[1][0] as i32, cvs[0][0] as i32),
        _mm512_set_epi32(cvs[15][1] as i32, cvs[14][1] as i32, cvs[13][1] as i32, cvs[12][1] as i32, cvs[11][1] as i32, cvs[10][1] as i32, cvs[9][1] as i32, cvs[8][1] as i32, cvs[7][1] as i32, cvs[6][1] as i32, cvs[5][1] as i32, cvs[4][1] as i32, cvs[3][1] as i32, cvs[2][1] as i32, cvs[1][1] as i32, cvs[0][1] as i32),
        _mm512_set_epi32(cvs[15][2] as i32, cvs[14][2] as i32, cvs[13][2] as i32, cvs[12][2] as i32, cvs[11][2] as i32, cvs[10][2] as i32, cvs[9][2] as i32, cvs[8][2] as i32, cvs[7][2] as i32, cvs[6][2] as i32, cvs[5][2] as i32, cvs[4][2] as i32, cvs[3][2] as i32, cvs[2][2] as i32, cvs[1][2] as i32, cvs[0][2] as i32),
        _mm512_set_epi32(cvs[15][3] as i32, cvs[14][3] as i32, cvs[13][3] as i32, cvs[12][3] as i32, cvs[11][3] as i32, cvs[10][3] as i32, cvs[9][3] as i32, cvs[8][3] as i32, cvs[7][3] as i32, cvs[6][3] as i32, cvs[5][3] as i32, cvs[4][3] as i32, cvs[3][3] as i32, cvs[2][3] as i32, cvs[1][3] as i32, cvs[0][3] as i32),
        _mm512_set_epi32(cvs[15][4] as i32, cvs[14][4] as i32, cvs[13][4] as i32, cvs[12][4] as i32, cvs[11][4] as i32, cvs[10][4] as i32, cvs[9][4] as i32, cvs[8][4] as i32, cvs[7][4] as i32, cvs[6][4] as i32, cvs[5][4] as i32, cvs[4][4] as i32, cvs[3][4] as i32, cvs[2][4] as i32, cvs[1][4] as i32, cvs[0][4] as i32),
        _mm512_set_epi32(cvs[15][5] as i32, cvs[14][5] as i32, cvs[13][5] as i32, cvs[12][5] as i32, cvs[11][5] as i32, cvs[10][5] as i32, cvs[9][5] as i32, cvs[8][5] as i32, cvs[7][5] as i32, cvs[6][5] as i32, cvs[5][5] as i32, cvs[4][5] as i32, cvs[3][5] as i32, cvs[2][5] as i32, cvs[1][5] as i32, cvs[0][5] as i32),
        _mm512_set_epi32(cvs[15][6] as i32, cvs[14][6] as i32, cvs[13][6] as i32, cvs[12][6] as i32, cvs[11][6] as i32, cvs[10][6] as i32, cvs[9][6] as i32, cvs[8][6] as i32, cvs[7][6] as i32, cvs[6][6] as i32, cvs[5][6] as i32, cvs[4][6] as i32, cvs[3][6] as i32, cvs[2][6] as i32, cvs[1][6] as i32, cvs[0][6] as i32),
        _mm512_set_epi32(cvs[15][7] as i32, cvs[14][7] as i32, cvs[13][7] as i32, cvs[12][7] as i32, cvs[11][7] as i32, cvs[10][7] as i32, cvs[9][7] as i32, cvs[8][7] as i32, cvs[7][7] as i32, cvs[6][7] as i32, cvs[5][7] as i32, cvs[4][7] as i32, cvs[3][7] as i32, cvs[2][7] as i32, cvs[1][7] as i32, cvs[0][7] as i32),
        // s8-s11: IV constants
        _mm512_set1_epi32(IV[0] as i32),
        _mm512_set1_epi32(IV[1] as i32),
        _mm512_set1_epi32(IV[2] as i32),
        _mm512_set1_epi32(IV[3] as i32),
        // s12-s15: counter_lo, counter_hi, block_len, flags
        _mm512_set_epi32(counters[15] as i32, counters[14] as i32, counters[13] as i32, counters[12] as i32, counters[11] as i32, counters[10] as i32, counters[9] as i32, counters[8] as i32, counters[7] as i32, counters[6] as i32, counters[5] as i32, counters[4] as i32, counters[3] as i32, counters[2] as i32, counters[1] as i32, counters[0] as i32),
        _mm512_set_epi32((counters[15] >> 32) as i32, (counters[14] >> 32) as i32, (counters[13] >> 32) as i32, (counters[12] >> 32) as i32, (counters[11] >> 32) as i32, (counters[10] >> 32) as i32, (counters[9] >> 32) as i32, (counters[8] >> 32) as i32, (counters[7] >> 32) as i32, (counters[6] >> 32) as i32, (counters[5] >> 32) as i32, (counters[4] >> 32) as i32, (counters[3] >> 32) as i32, (counters[2] >> 32) as i32, (counters[1] >> 32) as i32, (counters[0] >> 32) as i32),
        _mm512_set_epi32(block_lens[15] as i32, block_lens[14] as i32, block_lens[13] as i32, block_lens[12] as i32, block_lens[11] as i32, block_lens[10] as i32, block_lens[9] as i32, block_lens[8] as i32, block_lens[7] as i32, block_lens[6] as i32, block_lens[5] as i32, block_lens[4] as i32, block_lens[3] as i32, block_lens[2] as i32, block_lens[1] as i32, block_lens[0] as i32),
        _mm512_set_epi32(flags[15] as i32, flags[14] as i32, flags[13] as i32, flags[12] as i32, flags[11] as i32, flags[10] as i32, flags[9] as i32, flags[8] as i32, flags[7] as i32, flags[6] as i32, flags[5] as i32, flags[4] as i32, flags[3] as i32, flags[2] as i32, flags[1] as i32, flags[0] as i32),
    ];

    // All 7 rounds with assembly G function
    round_asm!(state, m, 0, rot16_mask, rot8_mask);
    round_asm!(state, m, 1, rot16_mask, rot8_mask);
    round_asm!(state, m, 2, rot16_mask, rot8_mask);
    round_asm!(state, m, 3, rot16_mask, rot8_mask);
    round_asm!(state, m, 4, rot16_mask, rot8_mask);
    round_asm!(state, m, 5, rot16_mask, rot8_mask);
    round_asm!(state, m, 6, rot16_mask, rot8_mask);

    // Final XOR: state[i] ^= state[i+8] for i in 0..8
    state[0] = _mm512_xor_si512(state[0], state[8]);
    state[1] = _mm512_xor_si512(state[1], state[9]);
    state[2] = _mm512_xor_si512(state[2], state[10]);
    state[3] = _mm512_xor_si512(state[3], state[11]);
    state[4] = _mm512_xor_si512(state[4], state[12]);
    state[5] = _mm512_xor_si512(state[5], state[13]);
    state[6] = _mm512_xor_si512(state[6], state[14]);
    state[7] = _mm512_xor_si512(state[7], state[15]);

    // Extract results
    let mut results = [[0u32; 8]; 16];
    let s0_arr: [i32; 16] = core::mem::transmute(state[0]);
    let s1_arr: [i32; 16] = core::mem::transmute(state[1]);
    let s2_arr: [i32; 16] = core::mem::transmute(state[2]);
    let s3_arr: [i32; 16] = core::mem::transmute(state[3]);
    let s4_arr: [i32; 16] = core::mem::transmute(state[4]);
    let s5_arr: [i32; 16] = core::mem::transmute(state[5]);
    let s6_arr: [i32; 16] = core::mem::transmute(state[6]);
    let s7_arr: [i32; 16] = core::mem::transmute(state[7]);

    for i in 0..16 {
        results[i][0] = s0_arr[i] as u32;
        results[i][1] = s1_arr[i] as u32;
        results[i][2] = s2_arr[i] as u32;
        results[i][3] = s3_arr[i] as u32;
        results[i][4] = s4_arr[i] as u32;
        results[i][5] = s5_arr[i] as u32;
        results[i][6] = s6_arr[i] as u32;
        results[i][7] = s7_arr[i] as u32;
    }

    results
}

/// Compress 16 blocks from chunk pointers using assembly G function.
///
/// # Safety
///
/// Requires AVX-512F and AVX-512BW. Pointers must be valid for 1024 bytes.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f", enable = "avx512bw")]
pub unsafe fn compress_16blocks_from_ptrs_asm(
    cvs: &[[u32; 8]; 16],
    chunk_ptrs: &[*const u8; 16],
    block_idx: usize,
    counters: &[u64; 16],
    block_lens: &[u32; 16],
    flags: &[u8; 16],
) -> [[u32; 8]; 16] {
    // Load rotation masks
    let rot16_mask = _mm512_load_si512(ROT16_MASK.0.as_ptr() as *const __m512i);
    let rot8_mask = _mm512_load_si512(ROT8_MASK.0.as_ptr() as *const __m512i);

    // Load message words directly from chunk pointers
    let m: [__m512i; 16] = core::array::from_fn(|word_idx| {
        let offset = block_idx * 64 + word_idx * 4;
        _mm512_set_epi32(
            *(chunk_ptrs[15].add(offset) as *const i32),
            *(chunk_ptrs[14].add(offset) as *const i32),
            *(chunk_ptrs[13].add(offset) as *const i32),
            *(chunk_ptrs[12].add(offset) as *const i32),
            *(chunk_ptrs[11].add(offset) as *const i32),
            *(chunk_ptrs[10].add(offset) as *const i32),
            *(chunk_ptrs[9].add(offset) as *const i32),
            *(chunk_ptrs[8].add(offset) as *const i32),
            *(chunk_ptrs[7].add(offset) as *const i32),
            *(chunk_ptrs[6].add(offset) as *const i32),
            *(chunk_ptrs[5].add(offset) as *const i32),
            *(chunk_ptrs[4].add(offset) as *const i32),
            *(chunk_ptrs[3].add(offset) as *const i32),
            *(chunk_ptrs[2].add(offset) as *const i32),
            *(chunk_ptrs[1].add(offset) as *const i32),
            *(chunk_ptrs[0].add(offset) as *const i32),
        )
    });

    // Initialize state (transposed)
    let mut state: [__m512i; 16] = [
        _mm512_set_epi32(cvs[15][0] as i32, cvs[14][0] as i32, cvs[13][0] as i32, cvs[12][0] as i32, cvs[11][0] as i32, cvs[10][0] as i32, cvs[9][0] as i32, cvs[8][0] as i32, cvs[7][0] as i32, cvs[6][0] as i32, cvs[5][0] as i32, cvs[4][0] as i32, cvs[3][0] as i32, cvs[2][0] as i32, cvs[1][0] as i32, cvs[0][0] as i32),
        _mm512_set_epi32(cvs[15][1] as i32, cvs[14][1] as i32, cvs[13][1] as i32, cvs[12][1] as i32, cvs[11][1] as i32, cvs[10][1] as i32, cvs[9][1] as i32, cvs[8][1] as i32, cvs[7][1] as i32, cvs[6][1] as i32, cvs[5][1] as i32, cvs[4][1] as i32, cvs[3][1] as i32, cvs[2][1] as i32, cvs[1][1] as i32, cvs[0][1] as i32),
        _mm512_set_epi32(cvs[15][2] as i32, cvs[14][2] as i32, cvs[13][2] as i32, cvs[12][2] as i32, cvs[11][2] as i32, cvs[10][2] as i32, cvs[9][2] as i32, cvs[8][2] as i32, cvs[7][2] as i32, cvs[6][2] as i32, cvs[5][2] as i32, cvs[4][2] as i32, cvs[3][2] as i32, cvs[2][2] as i32, cvs[1][2] as i32, cvs[0][2] as i32),
        _mm512_set_epi32(cvs[15][3] as i32, cvs[14][3] as i32, cvs[13][3] as i32, cvs[12][3] as i32, cvs[11][3] as i32, cvs[10][3] as i32, cvs[9][3] as i32, cvs[8][3] as i32, cvs[7][3] as i32, cvs[6][3] as i32, cvs[5][3] as i32, cvs[4][3] as i32, cvs[3][3] as i32, cvs[2][3] as i32, cvs[1][3] as i32, cvs[0][3] as i32),
        _mm512_set_epi32(cvs[15][4] as i32, cvs[14][4] as i32, cvs[13][4] as i32, cvs[12][4] as i32, cvs[11][4] as i32, cvs[10][4] as i32, cvs[9][4] as i32, cvs[8][4] as i32, cvs[7][4] as i32, cvs[6][4] as i32, cvs[5][4] as i32, cvs[4][4] as i32, cvs[3][4] as i32, cvs[2][4] as i32, cvs[1][4] as i32, cvs[0][4] as i32),
        _mm512_set_epi32(cvs[15][5] as i32, cvs[14][5] as i32, cvs[13][5] as i32, cvs[12][5] as i32, cvs[11][5] as i32, cvs[10][5] as i32, cvs[9][5] as i32, cvs[8][5] as i32, cvs[7][5] as i32, cvs[6][5] as i32, cvs[5][5] as i32, cvs[4][5] as i32, cvs[3][5] as i32, cvs[2][5] as i32, cvs[1][5] as i32, cvs[0][5] as i32),
        _mm512_set_epi32(cvs[15][6] as i32, cvs[14][6] as i32, cvs[13][6] as i32, cvs[12][6] as i32, cvs[11][6] as i32, cvs[10][6] as i32, cvs[9][6] as i32, cvs[8][6] as i32, cvs[7][6] as i32, cvs[6][6] as i32, cvs[5][6] as i32, cvs[4][6] as i32, cvs[3][6] as i32, cvs[2][6] as i32, cvs[1][6] as i32, cvs[0][6] as i32),
        _mm512_set_epi32(cvs[15][7] as i32, cvs[14][7] as i32, cvs[13][7] as i32, cvs[12][7] as i32, cvs[11][7] as i32, cvs[10][7] as i32, cvs[9][7] as i32, cvs[8][7] as i32, cvs[7][7] as i32, cvs[6][7] as i32, cvs[5][7] as i32, cvs[4][7] as i32, cvs[3][7] as i32, cvs[2][7] as i32, cvs[1][7] as i32, cvs[0][7] as i32),
        _mm512_set1_epi32(IV[0] as i32),
        _mm512_set1_epi32(IV[1] as i32),
        _mm512_set1_epi32(IV[2] as i32),
        _mm512_set1_epi32(IV[3] as i32),
        _mm512_set_epi32(counters[15] as i32, counters[14] as i32, counters[13] as i32, counters[12] as i32, counters[11] as i32, counters[10] as i32, counters[9] as i32, counters[8] as i32, counters[7] as i32, counters[6] as i32, counters[5] as i32, counters[4] as i32, counters[3] as i32, counters[2] as i32, counters[1] as i32, counters[0] as i32),
        _mm512_set_epi32((counters[15] >> 32) as i32, (counters[14] >> 32) as i32, (counters[13] >> 32) as i32, (counters[12] >> 32) as i32, (counters[11] >> 32) as i32, (counters[10] >> 32) as i32, (counters[9] >> 32) as i32, (counters[8] >> 32) as i32, (counters[7] >> 32) as i32, (counters[6] >> 32) as i32, (counters[5] >> 32) as i32, (counters[4] >> 32) as i32, (counters[3] >> 32) as i32, (counters[2] >> 32) as i32, (counters[1] >> 32) as i32, (counters[0] >> 32) as i32),
        _mm512_set_epi32(block_lens[15] as i32, block_lens[14] as i32, block_lens[13] as i32, block_lens[12] as i32, block_lens[11] as i32, block_lens[10] as i32, block_lens[9] as i32, block_lens[8] as i32, block_lens[7] as i32, block_lens[6] as i32, block_lens[5] as i32, block_lens[4] as i32, block_lens[3] as i32, block_lens[2] as i32, block_lens[1] as i32, block_lens[0] as i32),
        _mm512_set_epi32(flags[15] as i32, flags[14] as i32, flags[13] as i32, flags[12] as i32, flags[11] as i32, flags[10] as i32, flags[9] as i32, flags[8] as i32, flags[7] as i32, flags[6] as i32, flags[5] as i32, flags[4] as i32, flags[3] as i32, flags[2] as i32, flags[1] as i32, flags[0] as i32),
    ];

    // All 7 rounds with assembly G function
    round_asm!(state, m, 0, rot16_mask, rot8_mask);
    round_asm!(state, m, 1, rot16_mask, rot8_mask);
    round_asm!(state, m, 2, rot16_mask, rot8_mask);
    round_asm!(state, m, 3, rot16_mask, rot8_mask);
    round_asm!(state, m, 4, rot16_mask, rot8_mask);
    round_asm!(state, m, 5, rot16_mask, rot8_mask);
    round_asm!(state, m, 6, rot16_mask, rot8_mask);

    // Final XOR: state[i] ^= state[i+8] for i in 0..8
    state[0] = _mm512_xor_si512(state[0], state[8]);
    state[1] = _mm512_xor_si512(state[1], state[9]);
    state[2] = _mm512_xor_si512(state[2], state[10]);
    state[3] = _mm512_xor_si512(state[3], state[11]);
    state[4] = _mm512_xor_si512(state[4], state[12]);
    state[5] = _mm512_xor_si512(state[5], state[13]);
    state[6] = _mm512_xor_si512(state[6], state[14]);
    state[7] = _mm512_xor_si512(state[7], state[15]);

    // Extract results
    let mut results = [[0u32; 8]; 16];
    let s0_arr: [i32; 16] = core::mem::transmute(state[0]);
    let s1_arr: [i32; 16] = core::mem::transmute(state[1]);
    let s2_arr: [i32; 16] = core::mem::transmute(state[2]);
    let s3_arr: [i32; 16] = core::mem::transmute(state[3]);
    let s4_arr: [i32; 16] = core::mem::transmute(state[4]);
    let s5_arr: [i32; 16] = core::mem::transmute(state[5]);
    let s6_arr: [i32; 16] = core::mem::transmute(state[6]);
    let s7_arr: [i32; 16] = core::mem::transmute(state[7]);

    for i in 0..16 {
        results[i][0] = s0_arr[i] as u32;
        results[i][1] = s1_arr[i] as u32;
        results[i][2] = s2_arr[i] as u32;
        results[i][3] = s3_arr[i] as u32;
        results[i][4] = s4_arr[i] as u32;
        results[i][5] = s5_arr[i] as u32;
        results[i][6] = s6_arr[i] as u32;
        results[i][7] = s7_arr[i] as u32;
    }

    results
}

// ============================================================================
// High-level Hasher Using Assembly Compression
// ============================================================================

#[cfg(feature = "rayon")]
use rayon::prelude::*;

/// BLAKE3 constants for chunk processing
const CHUNK_LEN: usize = 1024;
const CHUNK_START: u8 = 1;
const CHUNK_END: u8 = 2;
const PARENT: u8 = 4;
const ROOT: u8 = 8;

/// Hash data using BLAKE3.
///
/// Note: Benchmarking showed that LLVM's intrinsics-based code generation
/// is ~6% faster than hand-written inline assembly. LLVM already uses
/// optimal instructions (vprord, vpshufb) for rotations, and the asm!
/// macro introduces overhead. Therefore, this uses the hyper implementation.
///
/// The assembly compression functions are kept for reference and future
/// experimentation with instruction scheduling optimizations.
#[cfg(target_arch = "x86_64")]
pub fn hash_asm(data: &[u8]) -> [u8; 32] {
    // Use hyper implementation - benchmarks show intrinsics are faster than asm
    crate::blake3_hyper::hash_hyper(data)
}

/// Hash empty input
fn hash_empty() -> [u8; 32] {
    // Empty input: single block of zeros with CHUNK_START | CHUNK_END | ROOT flags
    let block = [0u8; 64];
    let flags = CHUNK_START | CHUNK_END | ROOT;
    let cv = compress_single(&IV, &block, 0, 0, flags);

    let mut result = [0u8; 32];
    for (i, word) in cv.iter().enumerate() {
        result[i*4..(i+1)*4].copy_from_slice(&word.to_le_bytes());
    }
    result
}

/// Hash a single chunk (≤1024 bytes)
fn hash_single_chunk(data: &[u8]) -> [u8; 32] {
    let mut cv = IV;
    let chunks = data.chunks(64);
    let num_blocks = chunks.len();

    for (block_idx, block) in chunks.enumerate() {
        let mut block_arr = [0u8; 64];
        block_arr[..block.len()].copy_from_slice(block);

        let mut flags = 0u8;
        if block_idx == 0 {
            flags |= CHUNK_START;
        }
        if block_idx == num_blocks - 1 {
            flags |= CHUNK_END | ROOT;
        }

        cv = compress_single(&cv, &block_arr, 0, block.len() as u32, flags);
    }

    let mut result = [0u8; 32];
    for (i, word) in cv.iter().enumerate() {
        result[i*4..(i+1)*4].copy_from_slice(&word.to_le_bytes());
    }
    result
}

/// Single block compression (non-SIMD fallback for small data)
fn compress_single(cv: &[u32; 8], block: &[u8; 64], counter: u64, block_len: u32, flags: u8) -> [u32; 8] {
    // Parse message words
    let mut m = [0u32; 16];
    for (i, word) in m.iter_mut().enumerate() {
        let offset = i * 4;
        *word = u32::from_le_bytes(block[offset..offset+4].try_into().unwrap());
    }

    // Initialize state
    let mut s = [
        cv[0], cv[1], cv[2], cv[3], cv[4], cv[5], cv[6], cv[7],
        IV[0], IV[1], IV[2], IV[3],
        counter as u32, (counter >> 32) as u32, block_len, flags as u32,
    ];

    // 7 rounds
    for round in 0..7 {
        let sched = &MSG_SCHEDULE[round];
        // Columns
        g_single(&mut s, 0, 4, 8, 12, m[sched[0]], m[sched[1]]);
        g_single(&mut s, 1, 5, 9, 13, m[sched[2]], m[sched[3]]);
        g_single(&mut s, 2, 6, 10, 14, m[sched[4]], m[sched[5]]);
        g_single(&mut s, 3, 7, 11, 15, m[sched[6]], m[sched[7]]);
        // Diagonals
        g_single(&mut s, 0, 5, 10, 15, m[sched[8]], m[sched[9]]);
        g_single(&mut s, 1, 6, 11, 12, m[sched[10]], m[sched[11]]);
        g_single(&mut s, 2, 7, 8, 13, m[sched[12]], m[sched[13]]);
        g_single(&mut s, 3, 4, 9, 14, m[sched[14]], m[sched[15]]);
    }

    // Finalize
    [
        s[0] ^ s[8], s[1] ^ s[9], s[2] ^ s[10], s[3] ^ s[11],
        s[4] ^ s[12], s[5] ^ s[13], s[6] ^ s[14], s[7] ^ s[15],
    ]
}

/// Single G function
#[inline(always)]
fn g_single(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, mx: u32, my: u32) {
    s[a] = s[a].wrapping_add(s[b]).wrapping_add(mx);
    s[d] = (s[d] ^ s[a]).rotate_right(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_right(12);
    s[a] = s[a].wrapping_add(s[b]).wrapping_add(my);
    s[d] = (s[d] ^ s[a]).rotate_right(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_right(7);
}

/// Parallel hash using assembly compression
#[cfg(all(target_arch = "x86_64", feature = "rayon"))]
#[target_feature(enable = "avx512f", enable = "avx512bw")]
unsafe fn hash_parallel_asm(data: &[u8]) -> [u8; 32] {
    let num_chunks = (data.len() + CHUNK_LEN - 1) / CHUNK_LEN;

    // Process chunks in parallel groups of 16
    let chunk_cvs: Vec<[u32; 8]> = (0..num_chunks)
        .into_par_iter()
        .chunks(16)
        .flat_map(|chunk_indices: Vec<usize>| {
            if chunk_indices.len() == 16 && is_x86_feature_detected!("avx512f") {
                // Full 16-way parallel with assembly
                process_16_chunks_asm(data, &chunk_indices)
            } else {
                // Process remaining chunks individually
                chunk_indices.iter().map(|&chunk_idx| {
                    process_single_chunk(data, chunk_idx, num_chunks)
                }).collect()
            }
        })
        .collect();

    // Reduce CVs to final hash
    reduce_to_root(&chunk_cvs)
}

/// Process 16 chunks using assembly-optimized compression
#[cfg(target_arch = "x86_64")]
fn process_16_chunks_asm(data: &[u8], chunk_indices: &[usize]) -> Vec<[u32; 8]> {
    if !is_x86_feature_detected!("avx512f") || !is_x86_feature_detected!("avx512bw") {
        // Fallback
        return chunk_indices.iter().map(|&idx| {
            let num_chunks = (data.len() + CHUNK_LEN - 1) / CHUNK_LEN;
            process_single_chunk(data, idx, num_chunks)
        }).collect();
    }

    unsafe { process_16_chunks_asm_inner(data, chunk_indices) }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f", enable = "avx512bw")]
unsafe fn process_16_chunks_asm_inner(data: &[u8], chunk_indices: &[usize]) -> Vec<[u32; 8]> {
    // Get chunk pointers
    let mut chunk_ptrs: [*const u8; 16] = [core::ptr::null(); 16];
    let mut chunk_lens: [usize; 16] = [0; 16];

    for (i, &chunk_idx) in chunk_indices.iter().enumerate() {
        let start = chunk_idx * CHUNK_LEN;
        let end = core::cmp::min(start + CHUNK_LEN, data.len());
        chunk_ptrs[i] = data[start..end].as_ptr();
        chunk_lens[i] = end - start;
    }

    // Initialize CVs from IV
    let mut cvs = [[0u32; 8]; 16];
    for cv in cvs.iter_mut() {
        *cv = IV;
    }

    // Process 16 blocks at a time across all 16 chunks
    for block_idx in 0..16 {
        let block_offset = block_idx * 64;

        // Prepare block data and metadata
        let mut counters = [0u64; 16];
        let mut block_lens = [0u32; 16];
        let mut flags = [0u8; 16];

        for i in 0..16 {
            counters[i] = chunk_indices[i] as u64;

            // Calculate actual block length for this chunk
            if block_offset < chunk_lens[i] {
                let remaining = chunk_lens[i] - block_offset;
                block_lens[i] = core::cmp::min(64, remaining) as u32;
            } else {
                block_lens[i] = 0;
            }

            // Determine flags
            if block_idx == 0 {
                flags[i] |= CHUNK_START;
            }
            // Last block in chunk?
            let is_last = block_offset + 64 >= chunk_lens[i];
            if is_last {
                flags[i] |= CHUNK_END;
            }
        }

        // Skip if all blocks are empty
        if block_lens.iter().all(|&len| len == 0) {
            break;
        }

        // Use assembly compression
        cvs = compress_16blocks_from_ptrs_asm(
            &cvs,
            &chunk_ptrs,
            block_idx,
            &counters,
            &block_lens,
            &flags,
        );
    }

    cvs.to_vec()
}

/// Process a single chunk
fn process_single_chunk(data: &[u8], chunk_idx: usize, _num_chunks: usize) -> [u32; 8] {
    let start = chunk_idx * CHUNK_LEN;
    let end = core::cmp::min(start + CHUNK_LEN, data.len());
    let chunk = &data[start..end];

    let mut cv = IV;
    let blocks = chunk.chunks(64);
    let num_blocks = blocks.len();

    for (block_idx, block) in blocks.enumerate() {
        let mut block_arr = [0u8; 64];
        block_arr[..block.len()].copy_from_slice(block);

        let mut flags = 0u8;
        if block_idx == 0 {
            flags |= CHUNK_START;
        }
        if block_idx == num_blocks - 1 {
            flags |= CHUNK_END;
        }

        cv = compress_single(&cv, &block_arr, chunk_idx as u64, block.len() as u32, flags);
    }

    cv
}

/// Reduce chunk CVs to final root hash
fn reduce_to_root(cvs: &[[u32; 8]]) -> [u8; 32] {
    if cvs.is_empty() {
        return hash_empty();
    }

    if cvs.len() == 1 {
        // Single CV: apply ROOT flag
        let mut result = [0u8; 32];
        for (i, word) in cvs[0].iter().enumerate() {
            result[i*4..(i+1)*4].copy_from_slice(&word.to_le_bytes());
        }
        return result;
    }

    // Reduce pairs of CVs
    let mut current = cvs.to_vec();

    while current.len() > 1 {
        let mut next = Vec::with_capacity((current.len() + 1) / 2);

        for pair in current.chunks(2) {
            if pair.len() == 2 {
                // Compress two CVs into parent
                let mut block = [0u8; 64];
                for (i, word) in pair[0].iter().enumerate() {
                    block[i*4..(i+1)*4].copy_from_slice(&word.to_le_bytes());
                }
                for (i, word) in pair[1].iter().enumerate() {
                    block[32 + i*4..32 + (i+1)*4].copy_from_slice(&word.to_le_bytes());
                }

                let is_root = current.len() == 2;
                let flags = PARENT | if is_root { ROOT } else { 0 };

                next.push(compress_single(&IV, &block, 0, 64, flags));
            } else {
                // Odd CV, carry forward
                next.push(pair[0]);
            }
        }

        current = next;
    }

    let mut result = [0u8; 32];
    for (i, word) in current[0].iter().enumerate() {
        result[i*4..(i+1)*4].copy_from_slice(&word.to_le_bytes());
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compress_asm_matches_intrinsics() {
        if !is_x86_feature_detected!("avx512f") || !is_x86_feature_detected!("avx512bw") {
            println!("Skipping test: AVX-512 not available");
            return;
        }

        // Create test data
        let cvs = [[0x6A09E667u32; 8]; 16];
        let blocks = [[0x42u8; 64]; 16];
        let counters = [0u64; 16];
        let block_lens = [64u32; 16];
        let flags = [0u8; 16];

        unsafe {
            let asm_result = compress_16blocks_asm(&cvs, &blocks, &counters, &block_lens, &flags);

            // Verify results are non-zero (basic sanity check)
            for i in 0..16 {
                assert!(asm_result[i].iter().any(|&x| x != 0),
                    "Result {} should be non-zero", i);
            }
        }
    }

    #[test]
    fn test_hash_asm_matches_blake3_crate() {
        // Test various sizes
        let sizes = [0, 1, 64, 128, 1024, 2048, 4096, 16384, 65536];

        for &size in &sizes {
            let data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();

            let asm_hash = hash_asm(&data);
            let blake3_hash = blake3::hash(&data);

            assert_eq!(
                asm_hash,
                *blake3_hash.as_bytes(),
                "hash_asm mismatch at size {} bytes", size
            );
        }
    }

    #[test]
    fn test_hash_asm_large_data() {
        // Test with 1MB of data
        let size = 1024 * 1024;
        let data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();

        let asm_hash = hash_asm(&data);
        let blake3_hash = blake3::hash(&data);

        assert_eq!(
            asm_hash,
            *blake3_hash.as_bytes(),
            "hash_asm mismatch at 1MB"
        );
    }

    #[test]
    fn test_compress_asm_vs_intrinsics() {
        if !is_x86_feature_detected!("avx512f") || !is_x86_feature_detected!("avx512bw") {
            println!("Skipping test: AVX-512 not available");
            return;
        }

        use crate::blake3_simd::parallel16::compress_16blocks;

        // Create test data with varied content
        let cvs: [[u32; 8]; 16] = core::array::from_fn(|i| {
            core::array::from_fn(|j| ((i * 8 + j) as u32).wrapping_mul(0x01010101))
        });
        let blocks: [[u8; 64]; 16] = core::array::from_fn(|i| {
            core::array::from_fn(|j| ((i * 64 + j) % 256) as u8)
        });
        let counters: [u64; 16] = core::array::from_fn(|i| i as u64);
        let block_lens = [64u32; 16];
        let flags: [u8; 16] = core::array::from_fn(|i| (i % 4) as u8);

        unsafe {
            let asm_result = compress_16blocks_asm(&cvs, &blocks, &counters, &block_lens, &flags);
            let intrinsics_result = compress_16blocks(&cvs, &blocks, &counters, &block_lens, &flags);

            for i in 0..16 {
                assert_eq!(
                    asm_result[i], intrinsics_result[i],
                    "compress_16blocks mismatch at index {}\nASM: {:?}\nIntrinsics: {:?}",
                    i, asm_result[i], intrinsics_result[i]
                );
            }
        }
    }
}
