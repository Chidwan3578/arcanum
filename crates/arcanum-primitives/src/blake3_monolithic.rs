//! Monolithic AVX-512 BLAKE3 implementation
//!
//! This module contains a fully unrolled, monolithic assembly implementation
//! of BLAKE3 compression. All 7 rounds are in a single asm! block with no
//! function calls, maximizing register utilization and eliminating call overhead.

#![allow(unused)]

#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

/// BLAKE3 IV constants
const IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

/// Message schedule for all 7 rounds
/// MSG_SCHEDULE[round][i] gives the original message word index for position i
const MSG_SCHEDULE: [[usize; 16]; 7] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8],
    [3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1],
    [10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6],
    [12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4],
    [9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7],
    [11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13],
];

/// Compress 16 blocks in parallel using monolithic inline assembly.
///
/// This function processes 16 BLAKE3 blocks simultaneously using AVX-512.
/// All 7 compression rounds are in a single asm! block - no function calls.
///
/// # Safety
/// - Requires AVX-512F and AVX-512VL support
/// - `state` must contain valid __m512i values
/// - `msg` must contain 16 pre-loaded message vectors
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f")]
#[inline(never)] // Prevent inlining to keep the hot loop tight
pub unsafe fn compress_16blocks_monolithic(
    state: &mut [__m512i; 16],
    msg: &[__m512i; 16],
) {
    use core::arch::asm;

    // Load all message words - they'll be permuted per-round inside asm
    let m0 = msg[0];
    let m1 = msg[1];
    let m2 = msg[2];
    let m3 = msg[3];
    let m4 = msg[4];
    let m5 = msg[5];
    let m6 = msg[6];
    let m7 = msg[7];
    let m8 = msg[8];
    let m9 = msg[9];
    let m10 = msg[10];
    let m11 = msg[11];
    let m12 = msg[12];
    let m13 = msg[13];
    let m14 = msg[14];
    let m15 = msg[15];

    // All 7 rounds in one monolithic asm! block
    // Round 0: schedule = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15]
    // Round 1: schedule = [2,6,3,10,7,0,4,13,1,11,12,5,9,14,15,8]
    // ... etc
    asm!(
        // ═══════════════════════════════════════════════════════════════════
        // ROUND 0 - Message schedule: identity
        // Column: G(0,4,8,12) m0,m1; G(1,5,9,13) m2,m3; G(2,6,10,14) m4,m5; G(3,7,11,15) m6,m7
        // Diagonal: G(0,5,10,15) m8,m9; G(1,6,11,12) m10,m11; G(2,7,8,13) m12,m13; G(3,4,9,14) m14,m15
        // ═══════════════════════════════════════════════════════════════════

        // Column step - a = a + b + mx
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

        // Diagonal step - a = a + b + mx (with diagonal indices)
        "vpaddd {s0}, {s0}, {m8}",
        "vpaddd {s1}, {s1}, {m10}",
        "vpaddd {s2}, {s2}, {m12}",
        "vpaddd {s3}, {s3}, {m14}",
        "vpaddd {s0}, {s0}, {s5}",
        "vpaddd {s1}, {s1}, {s6}",
        "vpaddd {s2}, {s2}, {s7}",
        "vpaddd {s3}, {s3}, {s4}",
        // d = (d ^ a) >>> 16 (diagonal d)
        "vpxord {s15}, {s15}, {s0}",
        "vpxord {s12}, {s12}, {s1}",
        "vpxord {s13}, {s13}, {s2}",
        "vpxord {s14}, {s14}, {s3}",
        "vprord {s15}, {s15}, 16",
        "vprord {s12}, {s12}, 16",
        "vprord {s13}, {s13}, 16",
        "vprord {s14}, {s14}, 16",
        // c = c + d (diagonal c)
        "vpaddd {s10}, {s10}, {s15}",
        "vpaddd {s11}, {s11}, {s12}",
        "vpaddd {s8}, {s8}, {s13}",
        "vpaddd {s9}, {s9}, {s14}",
        // b = (b ^ c) >>> 12 (diagonal b)
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

        // ═══════════════════════════════════════════════════════════════════
        // ROUND 1 - Message schedule: [2,6,3,10,7,0,4,13,1,11,12,5,9,14,15,8]
        // Column: G(0,4,8,12) m2,m6; G(1,5,9,13) m3,m10; G(2,6,10,14) m7,m0; G(3,7,11,15) m4,m13
        // Diagonal: G(0,5,10,15) m1,m11; G(1,6,11,12) m12,m5; G(2,7,8,13) m9,m14; G(3,4,9,14) m15,m8
        // ═══════════════════════════════════════════════════════════════════

        // Column step
        "vpaddd {s0}, {s0}, {m2}",
        "vpaddd {s1}, {s1}, {m3}",
        "vpaddd {s2}, {s2}, {m7}",
        "vpaddd {s3}, {s3}, {m4}",
        "vpaddd {s0}, {s0}, {s4}",
        "vpaddd {s1}, {s1}, {s5}",
        "vpaddd {s2}, {s2}, {s6}",
        "vpaddd {s3}, {s3}, {s7}",
        "vpxord {s12}, {s12}, {s0}",
        "vpxord {s13}, {s13}, {s1}",
        "vpxord {s14}, {s14}, {s2}",
        "vpxord {s15}, {s15}, {s3}",
        "vprord {s12}, {s12}, 16",
        "vprord {s13}, {s13}, 16",
        "vprord {s14}, {s14}, 16",
        "vprord {s15}, {s15}, 16",
        "vpaddd {s8}, {s8}, {s12}",
        "vpaddd {s9}, {s9}, {s13}",
        "vpaddd {s10}, {s10}, {s14}",
        "vpaddd {s11}, {s11}, {s15}",
        "vpxord {s4}, {s4}, {s8}",
        "vpxord {s5}, {s5}, {s9}",
        "vpxord {s6}, {s6}, {s10}",
        "vpxord {s7}, {s7}, {s11}",
        "vprord {s4}, {s4}, 12",
        "vprord {s5}, {s5}, 12",
        "vprord {s6}, {s6}, 12",
        "vprord {s7}, {s7}, 12",
        "vpaddd {s0}, {s0}, {m6}",
        "vpaddd {s1}, {s1}, {m10}",
        "vpaddd {s2}, {s2}, {m0}",
        "vpaddd {s3}, {s3}, {m13}",
        "vpaddd {s0}, {s0}, {s4}",
        "vpaddd {s1}, {s1}, {s5}",
        "vpaddd {s2}, {s2}, {s6}",
        "vpaddd {s3}, {s3}, {s7}",
        "vpxord {s12}, {s12}, {s0}",
        "vpxord {s13}, {s13}, {s1}",
        "vpxord {s14}, {s14}, {s2}",
        "vpxord {s15}, {s15}, {s3}",
        "vprord {s12}, {s12}, 8",
        "vprord {s13}, {s13}, 8",
        "vprord {s14}, {s14}, 8",
        "vprord {s15}, {s15}, 8",
        "vpaddd {s8}, {s8}, {s12}",
        "vpaddd {s9}, {s9}, {s13}",
        "vpaddd {s10}, {s10}, {s14}",
        "vpaddd {s11}, {s11}, {s15}",
        "vpxord {s4}, {s4}, {s8}",
        "vpxord {s5}, {s5}, {s9}",
        "vpxord {s6}, {s6}, {s10}",
        "vpxord {s7}, {s7}, {s11}",
        "vprord {s4}, {s4}, 7",
        "vprord {s5}, {s5}, 7",
        "vprord {s6}, {s6}, 7",
        "vprord {s7}, {s7}, 7",

        // Diagonal step
        "vpaddd {s0}, {s0}, {m1}",
        "vpaddd {s1}, {s1}, {m12}",
        "vpaddd {s2}, {s2}, {m9}",
        "vpaddd {s3}, {s3}, {m15}",
        "vpaddd {s0}, {s0}, {s5}",
        "vpaddd {s1}, {s1}, {s6}",
        "vpaddd {s2}, {s2}, {s7}",
        "vpaddd {s3}, {s3}, {s4}",
        "vpxord {s15}, {s15}, {s0}",
        "vpxord {s12}, {s12}, {s1}",
        "vpxord {s13}, {s13}, {s2}",
        "vpxord {s14}, {s14}, {s3}",
        "vprord {s15}, {s15}, 16",
        "vprord {s12}, {s12}, 16",
        "vprord {s13}, {s13}, 16",
        "vprord {s14}, {s14}, 16",
        "vpaddd {s10}, {s10}, {s15}",
        "vpaddd {s11}, {s11}, {s12}",
        "vpaddd {s8}, {s8}, {s13}",
        "vpaddd {s9}, {s9}, {s14}",
        "vpxord {s5}, {s5}, {s10}",
        "vpxord {s6}, {s6}, {s11}",
        "vpxord {s7}, {s7}, {s8}",
        "vpxord {s4}, {s4}, {s9}",
        "vprord {s5}, {s5}, 12",
        "vprord {s6}, {s6}, 12",
        "vprord {s7}, {s7}, 12",
        "vprord {s4}, {s4}, 12",
        "vpaddd {s0}, {s0}, {m11}",
        "vpaddd {s1}, {s1}, {m5}",
        "vpaddd {s2}, {s2}, {m14}",
        "vpaddd {s3}, {s3}, {m8}",
        "vpaddd {s0}, {s0}, {s5}",
        "vpaddd {s1}, {s1}, {s6}",
        "vpaddd {s2}, {s2}, {s7}",
        "vpaddd {s3}, {s3}, {s4}",
        "vpxord {s15}, {s15}, {s0}",
        "vpxord {s12}, {s12}, {s1}",
        "vpxord {s13}, {s13}, {s2}",
        "vpxord {s14}, {s14}, {s3}",
        "vprord {s15}, {s15}, 8",
        "vprord {s12}, {s12}, 8",
        "vprord {s13}, {s13}, 8",
        "vprord {s14}, {s14}, 8",
        "vpaddd {s10}, {s10}, {s15}",
        "vpaddd {s11}, {s11}, {s12}",
        "vpaddd {s8}, {s8}, {s13}",
        "vpaddd {s9}, {s9}, {s14}",
        "vpxord {s5}, {s5}, {s10}",
        "vpxord {s6}, {s6}, {s11}",
        "vpxord {s7}, {s7}, {s8}",
        "vpxord {s4}, {s4}, {s9}",
        "vprord {s5}, {s5}, 7",
        "vprord {s6}, {s6}, 7",
        "vprord {s7}, {s7}, 7",
        "vprord {s4}, {s4}, 7",

        // ═══════════════════════════════════════════════════════════════════
        // ROUND 2 - Message schedule: [3,4,10,12,13,2,7,14,6,5,9,0,11,15,8,1]
        // ═══════════════════════════════════════════════════════════════════

        // Column step
        "vpaddd {s0}, {s0}, {m3}",
        "vpaddd {s1}, {s1}, {m10}",
        "vpaddd {s2}, {s2}, {m13}",
        "vpaddd {s3}, {s3}, {m7}",
        "vpaddd {s0}, {s0}, {s4}",
        "vpaddd {s1}, {s1}, {s5}",
        "vpaddd {s2}, {s2}, {s6}",
        "vpaddd {s3}, {s3}, {s7}",
        "vpxord {s12}, {s12}, {s0}",
        "vpxord {s13}, {s13}, {s1}",
        "vpxord {s14}, {s14}, {s2}",
        "vpxord {s15}, {s15}, {s3}",
        "vprord {s12}, {s12}, 16",
        "vprord {s13}, {s13}, 16",
        "vprord {s14}, {s14}, 16",
        "vprord {s15}, {s15}, 16",
        "vpaddd {s8}, {s8}, {s12}",
        "vpaddd {s9}, {s9}, {s13}",
        "vpaddd {s10}, {s10}, {s14}",
        "vpaddd {s11}, {s11}, {s15}",
        "vpxord {s4}, {s4}, {s8}",
        "vpxord {s5}, {s5}, {s9}",
        "vpxord {s6}, {s6}, {s10}",
        "vpxord {s7}, {s7}, {s11}",
        "vprord {s4}, {s4}, 12",
        "vprord {s5}, {s5}, 12",
        "vprord {s6}, {s6}, 12",
        "vprord {s7}, {s7}, 12",
        "vpaddd {s0}, {s0}, {m4}",
        "vpaddd {s1}, {s1}, {m12}",
        "vpaddd {s2}, {s2}, {m2}",
        "vpaddd {s3}, {s3}, {m14}",
        "vpaddd {s0}, {s0}, {s4}",
        "vpaddd {s1}, {s1}, {s5}",
        "vpaddd {s2}, {s2}, {s6}",
        "vpaddd {s3}, {s3}, {s7}",
        "vpxord {s12}, {s12}, {s0}",
        "vpxord {s13}, {s13}, {s1}",
        "vpxord {s14}, {s14}, {s2}",
        "vpxord {s15}, {s15}, {s3}",
        "vprord {s12}, {s12}, 8",
        "vprord {s13}, {s13}, 8",
        "vprord {s14}, {s14}, 8",
        "vprord {s15}, {s15}, 8",
        "vpaddd {s8}, {s8}, {s12}",
        "vpaddd {s9}, {s9}, {s13}",
        "vpaddd {s10}, {s10}, {s14}",
        "vpaddd {s11}, {s11}, {s15}",
        "vpxord {s4}, {s4}, {s8}",
        "vpxord {s5}, {s5}, {s9}",
        "vpxord {s6}, {s6}, {s10}",
        "vpxord {s7}, {s7}, {s11}",
        "vprord {s4}, {s4}, 7",
        "vprord {s5}, {s5}, 7",
        "vprord {s6}, {s6}, 7",
        "vprord {s7}, {s7}, 7",

        // Diagonal step
        "vpaddd {s0}, {s0}, {m6}",
        "vpaddd {s1}, {s1}, {m9}",
        "vpaddd {s2}, {s2}, {m11}",
        "vpaddd {s3}, {s3}, {m8}",
        "vpaddd {s0}, {s0}, {s5}",
        "vpaddd {s1}, {s1}, {s6}",
        "vpaddd {s2}, {s2}, {s7}",
        "vpaddd {s3}, {s3}, {s4}",
        "vpxord {s15}, {s15}, {s0}",
        "vpxord {s12}, {s12}, {s1}",
        "vpxord {s13}, {s13}, {s2}",
        "vpxord {s14}, {s14}, {s3}",
        "vprord {s15}, {s15}, 16",
        "vprord {s12}, {s12}, 16",
        "vprord {s13}, {s13}, 16",
        "vprord {s14}, {s14}, 16",
        "vpaddd {s10}, {s10}, {s15}",
        "vpaddd {s11}, {s11}, {s12}",
        "vpaddd {s8}, {s8}, {s13}",
        "vpaddd {s9}, {s9}, {s14}",
        "vpxord {s5}, {s5}, {s10}",
        "vpxord {s6}, {s6}, {s11}",
        "vpxord {s7}, {s7}, {s8}",
        "vpxord {s4}, {s4}, {s9}",
        "vprord {s5}, {s5}, 12",
        "vprord {s6}, {s6}, 12",
        "vprord {s7}, {s7}, 12",
        "vprord {s4}, {s4}, 12",
        "vpaddd {s0}, {s0}, {m5}",
        "vpaddd {s1}, {s1}, {m0}",
        "vpaddd {s2}, {s2}, {m15}",
        "vpaddd {s3}, {s3}, {m1}",
        "vpaddd {s0}, {s0}, {s5}",
        "vpaddd {s1}, {s1}, {s6}",
        "vpaddd {s2}, {s2}, {s7}",
        "vpaddd {s3}, {s3}, {s4}",
        "vpxord {s15}, {s15}, {s0}",
        "vpxord {s12}, {s12}, {s1}",
        "vpxord {s13}, {s13}, {s2}",
        "vpxord {s14}, {s14}, {s3}",
        "vprord {s15}, {s15}, 8",
        "vprord {s12}, {s12}, 8",
        "vprord {s13}, {s13}, 8",
        "vprord {s14}, {s14}, 8",
        "vpaddd {s10}, {s10}, {s15}",
        "vpaddd {s11}, {s11}, {s12}",
        "vpaddd {s8}, {s8}, {s13}",
        "vpaddd {s9}, {s9}, {s14}",
        "vpxord {s5}, {s5}, {s10}",
        "vpxord {s6}, {s6}, {s11}",
        "vpxord {s7}, {s7}, {s8}",
        "vpxord {s4}, {s4}, {s9}",
        "vprord {s5}, {s5}, 7",
        "vprord {s6}, {s6}, 7",
        "vprord {s7}, {s7}, 7",
        "vprord {s4}, {s4}, 7",

        // ═══════════════════════════════════════════════════════════════════
        // ROUND 3 - Message schedule: [10,7,12,9,14,3,13,15,4,0,11,2,5,8,1,6]
        // ═══════════════════════════════════════════════════════════════════

        // Column step
        "vpaddd {s0}, {s0}, {m10}",
        "vpaddd {s1}, {s1}, {m12}",
        "vpaddd {s2}, {s2}, {m14}",
        "vpaddd {s3}, {s3}, {m13}",
        "vpaddd {s0}, {s0}, {s4}",
        "vpaddd {s1}, {s1}, {s5}",
        "vpaddd {s2}, {s2}, {s6}",
        "vpaddd {s3}, {s3}, {s7}",
        "vpxord {s12}, {s12}, {s0}",
        "vpxord {s13}, {s13}, {s1}",
        "vpxord {s14}, {s14}, {s2}",
        "vpxord {s15}, {s15}, {s3}",
        "vprord {s12}, {s12}, 16",
        "vprord {s13}, {s13}, 16",
        "vprord {s14}, {s14}, 16",
        "vprord {s15}, {s15}, 16",
        "vpaddd {s8}, {s8}, {s12}",
        "vpaddd {s9}, {s9}, {s13}",
        "vpaddd {s10}, {s10}, {s14}",
        "vpaddd {s11}, {s11}, {s15}",
        "vpxord {s4}, {s4}, {s8}",
        "vpxord {s5}, {s5}, {s9}",
        "vpxord {s6}, {s6}, {s10}",
        "vpxord {s7}, {s7}, {s11}",
        "vprord {s4}, {s4}, 12",
        "vprord {s5}, {s5}, 12",
        "vprord {s6}, {s6}, 12",
        "vprord {s7}, {s7}, 12",
        "vpaddd {s0}, {s0}, {m7}",
        "vpaddd {s1}, {s1}, {m9}",
        "vpaddd {s2}, {s2}, {m3}",
        "vpaddd {s3}, {s3}, {m15}",
        "vpaddd {s0}, {s0}, {s4}",
        "vpaddd {s1}, {s1}, {s5}",
        "vpaddd {s2}, {s2}, {s6}",
        "vpaddd {s3}, {s3}, {s7}",
        "vpxord {s12}, {s12}, {s0}",
        "vpxord {s13}, {s13}, {s1}",
        "vpxord {s14}, {s14}, {s2}",
        "vpxord {s15}, {s15}, {s3}",
        "vprord {s12}, {s12}, 8",
        "vprord {s13}, {s13}, 8",
        "vprord {s14}, {s14}, 8",
        "vprord {s15}, {s15}, 8",
        "vpaddd {s8}, {s8}, {s12}",
        "vpaddd {s9}, {s9}, {s13}",
        "vpaddd {s10}, {s10}, {s14}",
        "vpaddd {s11}, {s11}, {s15}",
        "vpxord {s4}, {s4}, {s8}",
        "vpxord {s5}, {s5}, {s9}",
        "vpxord {s6}, {s6}, {s10}",
        "vpxord {s7}, {s7}, {s11}",
        "vprord {s4}, {s4}, 7",
        "vprord {s5}, {s5}, 7",
        "vprord {s6}, {s6}, 7",
        "vprord {s7}, {s7}, 7",

        // Diagonal step
        "vpaddd {s0}, {s0}, {m4}",
        "vpaddd {s1}, {s1}, {m11}",
        "vpaddd {s2}, {s2}, {m5}",
        "vpaddd {s3}, {s3}, {m1}",
        "vpaddd {s0}, {s0}, {s5}",
        "vpaddd {s1}, {s1}, {s6}",
        "vpaddd {s2}, {s2}, {s7}",
        "vpaddd {s3}, {s3}, {s4}",
        "vpxord {s15}, {s15}, {s0}",
        "vpxord {s12}, {s12}, {s1}",
        "vpxord {s13}, {s13}, {s2}",
        "vpxord {s14}, {s14}, {s3}",
        "vprord {s15}, {s15}, 16",
        "vprord {s12}, {s12}, 16",
        "vprord {s13}, {s13}, 16",
        "vprord {s14}, {s14}, 16",
        "vpaddd {s10}, {s10}, {s15}",
        "vpaddd {s11}, {s11}, {s12}",
        "vpaddd {s8}, {s8}, {s13}",
        "vpaddd {s9}, {s9}, {s14}",
        "vpxord {s5}, {s5}, {s10}",
        "vpxord {s6}, {s6}, {s11}",
        "vpxord {s7}, {s7}, {s8}",
        "vpxord {s4}, {s4}, {s9}",
        "vprord {s5}, {s5}, 12",
        "vprord {s6}, {s6}, 12",
        "vprord {s7}, {s7}, 12",
        "vprord {s4}, {s4}, 12",
        "vpaddd {s0}, {s0}, {m0}",
        "vpaddd {s1}, {s1}, {m2}",
        "vpaddd {s2}, {s2}, {m8}",
        "vpaddd {s3}, {s3}, {m6}",
        "vpaddd {s0}, {s0}, {s5}",
        "vpaddd {s1}, {s1}, {s6}",
        "vpaddd {s2}, {s2}, {s7}",
        "vpaddd {s3}, {s3}, {s4}",
        "vpxord {s15}, {s15}, {s0}",
        "vpxord {s12}, {s12}, {s1}",
        "vpxord {s13}, {s13}, {s2}",
        "vpxord {s14}, {s14}, {s3}",
        "vprord {s15}, {s15}, 8",
        "vprord {s12}, {s12}, 8",
        "vprord {s13}, {s13}, 8",
        "vprord {s14}, {s14}, 8",
        "vpaddd {s10}, {s10}, {s15}",
        "vpaddd {s11}, {s11}, {s12}",
        "vpaddd {s8}, {s8}, {s13}",
        "vpaddd {s9}, {s9}, {s14}",
        "vpxord {s5}, {s5}, {s10}",
        "vpxord {s6}, {s6}, {s11}",
        "vpxord {s7}, {s7}, {s8}",
        "vpxord {s4}, {s4}, {s9}",
        "vprord {s5}, {s5}, 7",
        "vprord {s6}, {s6}, 7",
        "vprord {s7}, {s7}, 7",
        "vprord {s4}, {s4}, 7",

        // ═══════════════════════════════════════════════════════════════════
        // ROUND 4 - Message schedule: [12,13,9,11,15,10,14,8,7,2,5,3,0,1,6,4]
        // ═══════════════════════════════════════════════════════════════════

        // Column step
        "vpaddd {s0}, {s0}, {m12}",
        "vpaddd {s1}, {s1}, {m9}",
        "vpaddd {s2}, {s2}, {m15}",
        "vpaddd {s3}, {s3}, {m14}",
        "vpaddd {s0}, {s0}, {s4}",
        "vpaddd {s1}, {s1}, {s5}",
        "vpaddd {s2}, {s2}, {s6}",
        "vpaddd {s3}, {s3}, {s7}",
        "vpxord {s12}, {s12}, {s0}",
        "vpxord {s13}, {s13}, {s1}",
        "vpxord {s14}, {s14}, {s2}",
        "vpxord {s15}, {s15}, {s3}",
        "vprord {s12}, {s12}, 16",
        "vprord {s13}, {s13}, 16",
        "vprord {s14}, {s14}, 16",
        "vprord {s15}, {s15}, 16",
        "vpaddd {s8}, {s8}, {s12}",
        "vpaddd {s9}, {s9}, {s13}",
        "vpaddd {s10}, {s10}, {s14}",
        "vpaddd {s11}, {s11}, {s15}",
        "vpxord {s4}, {s4}, {s8}",
        "vpxord {s5}, {s5}, {s9}",
        "vpxord {s6}, {s6}, {s10}",
        "vpxord {s7}, {s7}, {s11}",
        "vprord {s4}, {s4}, 12",
        "vprord {s5}, {s5}, 12",
        "vprord {s6}, {s6}, 12",
        "vprord {s7}, {s7}, 12",
        "vpaddd {s0}, {s0}, {m13}",
        "vpaddd {s1}, {s1}, {m11}",
        "vpaddd {s2}, {s2}, {m10}",
        "vpaddd {s3}, {s3}, {m8}",
        "vpaddd {s0}, {s0}, {s4}",
        "vpaddd {s1}, {s1}, {s5}",
        "vpaddd {s2}, {s2}, {s6}",
        "vpaddd {s3}, {s3}, {s7}",
        "vpxord {s12}, {s12}, {s0}",
        "vpxord {s13}, {s13}, {s1}",
        "vpxord {s14}, {s14}, {s2}",
        "vpxord {s15}, {s15}, {s3}",
        "vprord {s12}, {s12}, 8",
        "vprord {s13}, {s13}, 8",
        "vprord {s14}, {s14}, 8",
        "vprord {s15}, {s15}, 8",
        "vpaddd {s8}, {s8}, {s12}",
        "vpaddd {s9}, {s9}, {s13}",
        "vpaddd {s10}, {s10}, {s14}",
        "vpaddd {s11}, {s11}, {s15}",
        "vpxord {s4}, {s4}, {s8}",
        "vpxord {s5}, {s5}, {s9}",
        "vpxord {s6}, {s6}, {s10}",
        "vpxord {s7}, {s7}, {s11}",
        "vprord {s4}, {s4}, 7",
        "vprord {s5}, {s5}, 7",
        "vprord {s6}, {s6}, 7",
        "vprord {s7}, {s7}, 7",

        // Diagonal step
        "vpaddd {s0}, {s0}, {m7}",
        "vpaddd {s1}, {s1}, {m5}",
        "vpaddd {s2}, {s2}, {m0}",
        "vpaddd {s3}, {s3}, {m6}",
        "vpaddd {s0}, {s0}, {s5}",
        "vpaddd {s1}, {s1}, {s6}",
        "vpaddd {s2}, {s2}, {s7}",
        "vpaddd {s3}, {s3}, {s4}",
        "vpxord {s15}, {s15}, {s0}",
        "vpxord {s12}, {s12}, {s1}",
        "vpxord {s13}, {s13}, {s2}",
        "vpxord {s14}, {s14}, {s3}",
        "vprord {s15}, {s15}, 16",
        "vprord {s12}, {s12}, 16",
        "vprord {s13}, {s13}, 16",
        "vprord {s14}, {s14}, 16",
        "vpaddd {s10}, {s10}, {s15}",
        "vpaddd {s11}, {s11}, {s12}",
        "vpaddd {s8}, {s8}, {s13}",
        "vpaddd {s9}, {s9}, {s14}",
        "vpxord {s5}, {s5}, {s10}",
        "vpxord {s6}, {s6}, {s11}",
        "vpxord {s7}, {s7}, {s8}",
        "vpxord {s4}, {s4}, {s9}",
        "vprord {s5}, {s5}, 12",
        "vprord {s6}, {s6}, 12",
        "vprord {s7}, {s7}, 12",
        "vprord {s4}, {s4}, 12",
        "vpaddd {s0}, {s0}, {m2}",
        "vpaddd {s1}, {s1}, {m3}",
        "vpaddd {s2}, {s2}, {m1}",
        "vpaddd {s3}, {s3}, {m4}",
        "vpaddd {s0}, {s0}, {s5}",
        "vpaddd {s1}, {s1}, {s6}",
        "vpaddd {s2}, {s2}, {s7}",
        "vpaddd {s3}, {s3}, {s4}",
        "vpxord {s15}, {s15}, {s0}",
        "vpxord {s12}, {s12}, {s1}",
        "vpxord {s13}, {s13}, {s2}",
        "vpxord {s14}, {s14}, {s3}",
        "vprord {s15}, {s15}, 8",
        "vprord {s12}, {s12}, 8",
        "vprord {s13}, {s13}, 8",
        "vprord {s14}, {s14}, 8",
        "vpaddd {s10}, {s10}, {s15}",
        "vpaddd {s11}, {s11}, {s12}",
        "vpaddd {s8}, {s8}, {s13}",
        "vpaddd {s9}, {s9}, {s14}",
        "vpxord {s5}, {s5}, {s10}",
        "vpxord {s6}, {s6}, {s11}",
        "vpxord {s7}, {s7}, {s8}",
        "vpxord {s4}, {s4}, {s9}",
        "vprord {s5}, {s5}, 7",
        "vprord {s6}, {s6}, 7",
        "vprord {s7}, {s7}, 7",
        "vprord {s4}, {s4}, 7",

        // ═══════════════════════════════════════════════════════════════════
        // ROUND 5 - Message schedule: [9,14,11,5,8,12,15,1,13,3,0,10,2,6,4,7]
        // ═══════════════════════════════════════════════════════════════════

        // Column step
        "vpaddd {s0}, {s0}, {m9}",
        "vpaddd {s1}, {s1}, {m11}",
        "vpaddd {s2}, {s2}, {m8}",
        "vpaddd {s3}, {s3}, {m15}",
        "vpaddd {s0}, {s0}, {s4}",
        "vpaddd {s1}, {s1}, {s5}",
        "vpaddd {s2}, {s2}, {s6}",
        "vpaddd {s3}, {s3}, {s7}",
        "vpxord {s12}, {s12}, {s0}",
        "vpxord {s13}, {s13}, {s1}",
        "vpxord {s14}, {s14}, {s2}",
        "vpxord {s15}, {s15}, {s3}",
        "vprord {s12}, {s12}, 16",
        "vprord {s13}, {s13}, 16",
        "vprord {s14}, {s14}, 16",
        "vprord {s15}, {s15}, 16",
        "vpaddd {s8}, {s8}, {s12}",
        "vpaddd {s9}, {s9}, {s13}",
        "vpaddd {s10}, {s10}, {s14}",
        "vpaddd {s11}, {s11}, {s15}",
        "vpxord {s4}, {s4}, {s8}",
        "vpxord {s5}, {s5}, {s9}",
        "vpxord {s6}, {s6}, {s10}",
        "vpxord {s7}, {s7}, {s11}",
        "vprord {s4}, {s4}, 12",
        "vprord {s5}, {s5}, 12",
        "vprord {s6}, {s6}, 12",
        "vprord {s7}, {s7}, 12",
        "vpaddd {s0}, {s0}, {m14}",
        "vpaddd {s1}, {s1}, {m5}",
        "vpaddd {s2}, {s2}, {m12}",
        "vpaddd {s3}, {s3}, {m1}",
        "vpaddd {s0}, {s0}, {s4}",
        "vpaddd {s1}, {s1}, {s5}",
        "vpaddd {s2}, {s2}, {s6}",
        "vpaddd {s3}, {s3}, {s7}",
        "vpxord {s12}, {s12}, {s0}",
        "vpxord {s13}, {s13}, {s1}",
        "vpxord {s14}, {s14}, {s2}",
        "vpxord {s15}, {s15}, {s3}",
        "vprord {s12}, {s12}, 8",
        "vprord {s13}, {s13}, 8",
        "vprord {s14}, {s14}, 8",
        "vprord {s15}, {s15}, 8",
        "vpaddd {s8}, {s8}, {s12}",
        "vpaddd {s9}, {s9}, {s13}",
        "vpaddd {s10}, {s10}, {s14}",
        "vpaddd {s11}, {s11}, {s15}",
        "vpxord {s4}, {s4}, {s8}",
        "vpxord {s5}, {s5}, {s9}",
        "vpxord {s6}, {s6}, {s10}",
        "vpxord {s7}, {s7}, {s11}",
        "vprord {s4}, {s4}, 7",
        "vprord {s5}, {s5}, 7",
        "vprord {s6}, {s6}, 7",
        "vprord {s7}, {s7}, 7",

        // Diagonal step
        "vpaddd {s0}, {s0}, {m13}",
        "vpaddd {s1}, {s1}, {m0}",
        "vpaddd {s2}, {s2}, {m2}",
        "vpaddd {s3}, {s3}, {m4}",
        "vpaddd {s0}, {s0}, {s5}",
        "vpaddd {s1}, {s1}, {s6}",
        "vpaddd {s2}, {s2}, {s7}",
        "vpaddd {s3}, {s3}, {s4}",
        "vpxord {s15}, {s15}, {s0}",
        "vpxord {s12}, {s12}, {s1}",
        "vpxord {s13}, {s13}, {s2}",
        "vpxord {s14}, {s14}, {s3}",
        "vprord {s15}, {s15}, 16",
        "vprord {s12}, {s12}, 16",
        "vprord {s13}, {s13}, 16",
        "vprord {s14}, {s14}, 16",
        "vpaddd {s10}, {s10}, {s15}",
        "vpaddd {s11}, {s11}, {s12}",
        "vpaddd {s8}, {s8}, {s13}",
        "vpaddd {s9}, {s9}, {s14}",
        "vpxord {s5}, {s5}, {s10}",
        "vpxord {s6}, {s6}, {s11}",
        "vpxord {s7}, {s7}, {s8}",
        "vpxord {s4}, {s4}, {s9}",
        "vprord {s5}, {s5}, 12",
        "vprord {s6}, {s6}, 12",
        "vprord {s7}, {s7}, 12",
        "vprord {s4}, {s4}, 12",
        "vpaddd {s0}, {s0}, {m3}",
        "vpaddd {s1}, {s1}, {m10}",
        "vpaddd {s2}, {s2}, {m6}",
        "vpaddd {s3}, {s3}, {m7}",
        "vpaddd {s0}, {s0}, {s5}",
        "vpaddd {s1}, {s1}, {s6}",
        "vpaddd {s2}, {s2}, {s7}",
        "vpaddd {s3}, {s3}, {s4}",
        "vpxord {s15}, {s15}, {s0}",
        "vpxord {s12}, {s12}, {s1}",
        "vpxord {s13}, {s13}, {s2}",
        "vpxord {s14}, {s14}, {s3}",
        "vprord {s15}, {s15}, 8",
        "vprord {s12}, {s12}, 8",
        "vprord {s13}, {s13}, 8",
        "vprord {s14}, {s14}, 8",
        "vpaddd {s10}, {s10}, {s15}",
        "vpaddd {s11}, {s11}, {s12}",
        "vpaddd {s8}, {s8}, {s13}",
        "vpaddd {s9}, {s9}, {s14}",
        "vpxord {s5}, {s5}, {s10}",
        "vpxord {s6}, {s6}, {s11}",
        "vpxord {s7}, {s7}, {s8}",
        "vpxord {s4}, {s4}, {s9}",
        "vprord {s5}, {s5}, 7",
        "vprord {s6}, {s6}, 7",
        "vprord {s7}, {s7}, 7",
        "vprord {s4}, {s4}, 7",

        // ═══════════════════════════════════════════════════════════════════
        // ROUND 6 - Message schedule: [11,15,5,0,1,9,8,6,14,10,2,12,3,4,7,13]
        // ═══════════════════════════════════════════════════════════════════

        // Column step
        "vpaddd {s0}, {s0}, {m11}",
        "vpaddd {s1}, {s1}, {m5}",
        "vpaddd {s2}, {s2}, {m1}",
        "vpaddd {s3}, {s3}, {m8}",
        "vpaddd {s0}, {s0}, {s4}",
        "vpaddd {s1}, {s1}, {s5}",
        "vpaddd {s2}, {s2}, {s6}",
        "vpaddd {s3}, {s3}, {s7}",
        "vpxord {s12}, {s12}, {s0}",
        "vpxord {s13}, {s13}, {s1}",
        "vpxord {s14}, {s14}, {s2}",
        "vpxord {s15}, {s15}, {s3}",
        "vprord {s12}, {s12}, 16",
        "vprord {s13}, {s13}, 16",
        "vprord {s14}, {s14}, 16",
        "vprord {s15}, {s15}, 16",
        "vpaddd {s8}, {s8}, {s12}",
        "vpaddd {s9}, {s9}, {s13}",
        "vpaddd {s10}, {s10}, {s14}",
        "vpaddd {s11}, {s11}, {s15}",
        "vpxord {s4}, {s4}, {s8}",
        "vpxord {s5}, {s5}, {s9}",
        "vpxord {s6}, {s6}, {s10}",
        "vpxord {s7}, {s7}, {s11}",
        "vprord {s4}, {s4}, 12",
        "vprord {s5}, {s5}, 12",
        "vprord {s6}, {s6}, 12",
        "vprord {s7}, {s7}, 12",
        "vpaddd {s0}, {s0}, {m15}",
        "vpaddd {s1}, {s1}, {m0}",
        "vpaddd {s2}, {s2}, {m9}",
        "vpaddd {s3}, {s3}, {m6}",
        "vpaddd {s0}, {s0}, {s4}",
        "vpaddd {s1}, {s1}, {s5}",
        "vpaddd {s2}, {s2}, {s6}",
        "vpaddd {s3}, {s3}, {s7}",
        "vpxord {s12}, {s12}, {s0}",
        "vpxord {s13}, {s13}, {s1}",
        "vpxord {s14}, {s14}, {s2}",
        "vpxord {s15}, {s15}, {s3}",
        "vprord {s12}, {s12}, 8",
        "vprord {s13}, {s13}, 8",
        "vprord {s14}, {s14}, 8",
        "vprord {s15}, {s15}, 8",
        "vpaddd {s8}, {s8}, {s12}",
        "vpaddd {s9}, {s9}, {s13}",
        "vpaddd {s10}, {s10}, {s14}",
        "vpaddd {s11}, {s11}, {s15}",
        "vpxord {s4}, {s4}, {s8}",
        "vpxord {s5}, {s5}, {s9}",
        "vpxord {s6}, {s6}, {s10}",
        "vpxord {s7}, {s7}, {s11}",
        "vprord {s4}, {s4}, 7",
        "vprord {s5}, {s5}, 7",
        "vprord {s6}, {s6}, 7",
        "vprord {s7}, {s7}, 7",

        // Diagonal step
        "vpaddd {s0}, {s0}, {m14}",
        "vpaddd {s1}, {s1}, {m2}",
        "vpaddd {s2}, {s2}, {m3}",
        "vpaddd {s3}, {s3}, {m7}",
        "vpaddd {s0}, {s0}, {s5}",
        "vpaddd {s1}, {s1}, {s6}",
        "vpaddd {s2}, {s2}, {s7}",
        "vpaddd {s3}, {s3}, {s4}",
        "vpxord {s15}, {s15}, {s0}",
        "vpxord {s12}, {s12}, {s1}",
        "vpxord {s13}, {s13}, {s2}",
        "vpxord {s14}, {s14}, {s3}",
        "vprord {s15}, {s15}, 16",
        "vprord {s12}, {s12}, 16",
        "vprord {s13}, {s13}, 16",
        "vprord {s14}, {s14}, 16",
        "vpaddd {s10}, {s10}, {s15}",
        "vpaddd {s11}, {s11}, {s12}",
        "vpaddd {s8}, {s8}, {s13}",
        "vpaddd {s9}, {s9}, {s14}",
        "vpxord {s5}, {s5}, {s10}",
        "vpxord {s6}, {s6}, {s11}",
        "vpxord {s7}, {s7}, {s8}",
        "vpxord {s4}, {s4}, {s9}",
        "vprord {s5}, {s5}, 12",
        "vprord {s6}, {s6}, 12",
        "vprord {s7}, {s7}, 12",
        "vprord {s4}, {s4}, 12",
        "vpaddd {s0}, {s0}, {m10}",
        "vpaddd {s1}, {s1}, {m12}",
        "vpaddd {s2}, {s2}, {m4}",
        "vpaddd {s3}, {s3}, {m13}",
        "vpaddd {s0}, {s0}, {s5}",
        "vpaddd {s1}, {s1}, {s6}",
        "vpaddd {s2}, {s2}, {s7}",
        "vpaddd {s3}, {s3}, {s4}",
        "vpxord {s15}, {s15}, {s0}",
        "vpxord {s12}, {s12}, {s1}",
        "vpxord {s13}, {s13}, {s2}",
        "vpxord {s14}, {s14}, {s3}",
        "vprord {s15}, {s15}, 8",
        "vprord {s12}, {s12}, 8",
        "vprord {s13}, {s13}, 8",
        "vprord {s14}, {s14}, 8",
        "vpaddd {s10}, {s10}, {s15}",
        "vpaddd {s11}, {s11}, {s12}",
        "vpaddd {s8}, {s8}, {s13}",
        "vpaddd {s9}, {s9}, {s14}",
        "vpxord {s5}, {s5}, {s10}",
        "vpxord {s6}, {s6}, {s11}",
        "vpxord {s7}, {s7}, {s8}",
        "vpxord {s4}, {s4}, {s9}",
        "vprord {s5}, {s5}, 7",
        "vprord {s6}, {s6}, 7",
        "vprord {s7}, {s7}, 7",
        "vprord {s4}, {s4}, 7",

        // Register operands
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

// ═══════════════════════════════════════════════════════════════════════════════
// COMPLETE HASH FUNCTION USING MONOLITHIC COMPRESSION
// ═══════════════════════════════════════════════════════════════════════════════

/// Pre-computed broadcast IV vectors for 512-bit lanes.
#[cfg(target_arch = "x86_64")]
const IV_BROADCAST_512_0: __m512i = unsafe {
    core::mem::transmute::<[u32; 16], __m512i>([IV[0]; 16])
};
#[cfg(target_arch = "x86_64")]
const IV_BROADCAST_512_1: __m512i = unsafe {
    core::mem::transmute::<[u32; 16], __m512i>([IV[1]; 16])
};
#[cfg(target_arch = "x86_64")]
const IV_BROADCAST_512_2: __m512i = unsafe {
    core::mem::transmute::<[u32; 16], __m512i>([IV[2]; 16])
};
#[cfg(target_arch = "x86_64")]
const IV_BROADCAST_512_3: __m512i = unsafe {
    core::mem::transmute::<[u32; 16], __m512i>([IV[3]; 16])
};

/// Transpose 16 x __m512i vectors (16x16 matrix of 32-bit words).
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f")]
#[inline]
unsafe fn transpose_vecs_512(vecs: &mut [__m512i; 16]) {
    #[inline(always)]
    unsafe fn unpack_lo_128(a: __m512i, b: __m512i) -> __m512i {
        _mm512_shuffle_i32x4(a, b, 0x88)
    }
    #[inline(always)]
    unsafe fn unpack_hi_128(a: __m512i, b: __m512i) -> __m512i {
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
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f")]
#[inline]
unsafe fn load_transpose_msg_16(base_ptr: *const u8, block_idx: usize) -> [__m512i; 16] {
    const CHUNK_LEN: usize = 1024;
    const BLOCK_LEN: usize = 64;
    let block_offset = block_idx * BLOCK_LEN;

    let mut vecs: [__m512i; 16] = [_mm512_setzero_si512(); 16];
    vecs[0] = _mm512_loadu_si512((base_ptr.add(0 * CHUNK_LEN + block_offset)) as *const __m512i);
    vecs[1] = _mm512_loadu_si512((base_ptr.add(1 * CHUNK_LEN + block_offset)) as *const __m512i);
    vecs[2] = _mm512_loadu_si512((base_ptr.add(2 * CHUNK_LEN + block_offset)) as *const __m512i);
    vecs[3] = _mm512_loadu_si512((base_ptr.add(3 * CHUNK_LEN + block_offset)) as *const __m512i);
    vecs[4] = _mm512_loadu_si512((base_ptr.add(4 * CHUNK_LEN + block_offset)) as *const __m512i);
    vecs[5] = _mm512_loadu_si512((base_ptr.add(5 * CHUNK_LEN + block_offset)) as *const __m512i);
    vecs[6] = _mm512_loadu_si512((base_ptr.add(6 * CHUNK_LEN + block_offset)) as *const __m512i);
    vecs[7] = _mm512_loadu_si512((base_ptr.add(7 * CHUNK_LEN + block_offset)) as *const __m512i);
    vecs[8] = _mm512_loadu_si512((base_ptr.add(8 * CHUNK_LEN + block_offset)) as *const __m512i);
    vecs[9] = _mm512_loadu_si512((base_ptr.add(9 * CHUNK_LEN + block_offset)) as *const __m512i);
    vecs[10] = _mm512_loadu_si512((base_ptr.add(10 * CHUNK_LEN + block_offset)) as *const __m512i);
    vecs[11] = _mm512_loadu_si512((base_ptr.add(11 * CHUNK_LEN + block_offset)) as *const __m512i);
    vecs[12] = _mm512_loadu_si512((base_ptr.add(12 * CHUNK_LEN + block_offset)) as *const __m512i);
    vecs[13] = _mm512_loadu_si512((base_ptr.add(13 * CHUNK_LEN + block_offset)) as *const __m512i);
    vecs[14] = _mm512_loadu_si512((base_ptr.add(14 * CHUNK_LEN + block_offset)) as *const __m512i);
    vecs[15] = _mm512_loadu_si512((base_ptr.add(15 * CHUNK_LEN + block_offset)) as *const __m512i);

    transpose_vecs_512(&mut vecs);
    vecs
}

/// Hash 16 contiguous chunks using monolithic assembly compression.
///
/// This function processes 16 chunks (16KB total) in parallel using the
/// fully-unrolled monolithic assembly compression.
///
/// # Safety
/// - Requires AVX-512F support
/// - `base_ptr` must point to at least 16KB of valid data
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f")]
pub unsafe fn hash_16_chunks_monolithic(
    key: &[u32; 8],
    base_ptr: *const u8,
    chunk_counters: &[u64; 16],
    base_flags: u8,
) -> [[u32; 8]; 16] {
    const CHUNK_START: u8 = 1;
    const CHUNK_END: u8 = 2;

    // Initialize CV state from key
    let mut cv0 = _mm512_set1_epi32(key[0] as i32);
    let mut cv1 = _mm512_set1_epi32(key[1] as i32);
    let mut cv2 = _mm512_set1_epi32(key[2] as i32);
    let mut cv3 = _mm512_set1_epi32(key[3] as i32);
    let mut cv4 = _mm512_set1_epi32(key[4] as i32);
    let mut cv5 = _mm512_set1_epi32(key[5] as i32);
    let mut cv6 = _mm512_set1_epi32(key[6] as i32);
    let mut cv7 = _mm512_set1_epi32(key[7] as i32);

    // Counter vectors
    let counter_lo = _mm512_setr_epi32(
        chunk_counters[0] as i32, chunk_counters[1] as i32,
        chunk_counters[2] as i32, chunk_counters[3] as i32,
        chunk_counters[4] as i32, chunk_counters[5] as i32,
        chunk_counters[6] as i32, chunk_counters[7] as i32,
        chunk_counters[8] as i32, chunk_counters[9] as i32,
        chunk_counters[10] as i32, chunk_counters[11] as i32,
        chunk_counters[12] as i32, chunk_counters[13] as i32,
        chunk_counters[14] as i32, chunk_counters[15] as i32,
    );
    let counter_hi = _mm512_setr_epi32(
        (chunk_counters[0] >> 32) as i32, (chunk_counters[1] >> 32) as i32,
        (chunk_counters[2] >> 32) as i32, (chunk_counters[3] >> 32) as i32,
        (chunk_counters[4] >> 32) as i32, (chunk_counters[5] >> 32) as i32,
        (chunk_counters[6] >> 32) as i32, (chunk_counters[7] >> 32) as i32,
        (chunk_counters[8] >> 32) as i32, (chunk_counters[9] >> 32) as i32,
        (chunk_counters[10] >> 32) as i32, (chunk_counters[11] >> 32) as i32,
        (chunk_counters[12] >> 32) as i32, (chunk_counters[13] >> 32) as i32,
        (chunk_counters[14] >> 32) as i32, (chunk_counters[15] >> 32) as i32,
    );
    let block_len = _mm512_set1_epi32(64);

    // Process all 16 blocks
    // Pre-compute flags for first, middle, and last blocks
    let flags_first = _mm512_set1_epi32((base_flags | CHUNK_START) as i32);
    let flags_middle = _mm512_set1_epi32(base_flags as i32);
    let flags_last = _mm512_set1_epi32((base_flags | CHUNK_END) as i32);

    for block_idx in 0..16 {
        let flags = if block_idx == 0 {
            flags_first
        } else if block_idx == 15 {
            flags_last
        } else {
            flags_middle
        };

        // Load and transpose message
        let msg = load_transpose_msg_16(base_ptr, block_idx);

        // Initialize compression state
        let mut state: [__m512i; 16] = [
            cv0, cv1, cv2, cv3, cv4, cv5, cv6, cv7,
            IV_BROADCAST_512_0, IV_BROADCAST_512_1,
            IV_BROADCAST_512_2, IV_BROADCAST_512_3,
            counter_lo, counter_hi, block_len, flags,
        ];

        // All 7 rounds in one monolithic assembly call
        compress_16blocks_monolithic(&mut state, &msg);

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

    // Transpose and output CVs
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_monolithic_compiles() {
        if !is_x86_feature_detected!("avx512f") {
            return;
        }

        unsafe {
            let mut state: [__m512i; 16] = core::array::from_fn(|_| _mm512_setzero_si512());
            let msg: [__m512i; 16] = core::array::from_fn(|_| _mm512_setzero_si512());
            compress_16blocks_monolithic(&mut state, &msg);
        }
    }

    #[test]
    fn test_hash_16_chunks_monolithic() {
        if !is_x86_feature_detected!("avx512f") {
            eprintln!("AVX-512 not supported, skipping test");
            return;
        }

        // Create test data: 16 chunks of 1024 bytes each
        let mut data = vec![0u8; 16 * 1024];
        for (i, byte) in data.iter_mut().enumerate() {
            *byte = (i % 256) as u8;
        }

        let key = IV;
        let counters: [u64; 16] = core::array::from_fn(|i| i as u64);

        unsafe {
            let cvs = hash_16_chunks_monolithic(&key, data.as_ptr(), &counters, 0);

            // Basic sanity check: all CVs should be different
            for i in 0..16 {
                for j in (i + 1)..16 {
                    assert_ne!(cvs[i], cvs[j], "CVs {} and {} should differ", i, j);
                }
            }

            // Verify each CV has reasonable values (non-zero)
            for (i, cv) in cvs.iter().enumerate() {
                let all_zero = cv.iter().all(|&x| x == 0);
                assert!(!all_zero, "CV {} should not be all zeros", i);
            }
        }
    }

    #[test]
    fn bench_apex_scaling() {
        if !is_x86_feature_detected!("avx512f") {
            eprintln!("AVX-512 not supported, skipping benchmark");
            return;
        }

        use std::time::Instant;
        use crate::blake3_ultra::hash_apex;

        let sizes_mb = [64, 128, 256, 512];

        eprintln!("\n=== Apex Performance Scaling ===");
        eprintln!("{:>8} {:>14} {:>10} {:>12}", "Size", "Throughput", "Time", "vs blake3");

        for size_mb in sizes_mb {
            let size = size_mb * 1024 * 1024;
            let data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
            let iterations = (500 / size_mb).max(5) as usize;

            // Warm up
            for _ in 0..2 {
                let _ = hash_apex(&data);
                let _ = blake3::hash(&data);
            }

            // Apex
            let start = Instant::now();
            for _ in 0..iterations {
                let _ = hash_apex(&data);
            }
            let apex_elapsed = start.elapsed();

            // blake3 reference
            let start = Instant::now();
            for _ in 0..iterations {
                let _ = blake3::hash(&data);
            }
            let blake3_elapsed = start.elapsed();

            let apex_gib_s = (iterations as f64 * size as f64) / (apex_elapsed.as_secs_f64() * 1024.0 * 1024.0 * 1024.0);
            let blake3_gib_s = (iterations as f64 * size as f64) / (blake3_elapsed.as_secs_f64() * 1024.0 * 1024.0 * 1024.0);
            let time_ms = apex_elapsed.as_millis() as f64 / iterations as f64;

            eprintln!("{:>6}MB {:>12.2} GiB/s {:>8.1} ms {:>10.2}x",
                size_mb, apex_gib_s, time_ms, apex_gib_s / blake3_gib_s);
        }
    }

    #[test]
    fn bench_apex_monolithic_scaling() {
        if !is_x86_feature_detected!("avx512f") {
            eprintln!("AVX-512 not supported, skipping benchmark");
            return;
        }

        use std::time::Instant;
        use crate::blake3_ultra::{hash_apex, hash_apex_monolithic};

        let sizes_mb = [64, 128, 256, 512];

        eprintln!("\n=== Apex Monolithic vs Regular Apex ===");
        eprintln!("{:>8} {:>14} {:>14} {:>10}", "Size", "Apex Mono", "Apex Ptr", "Speedup");

        for size_mb in sizes_mb {
            let size = size_mb * 1024 * 1024;
            let data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
            let iterations = (500 / size_mb).max(5) as usize;

            // Warm up
            for _ in 0..2 {
                let _ = hash_apex_monolithic(&data);
                let _ = hash_apex(&data);
            }

            // Apex monolithic
            let start = Instant::now();
            for _ in 0..iterations {
                let _ = hash_apex_monolithic(&data);
            }
            let mono_elapsed = start.elapsed();

            // Apex regular (pointer-based)
            let start = Instant::now();
            for _ in 0..iterations {
                let _ = hash_apex(&data);
            }
            let apex_elapsed = start.elapsed();

            let mono_gib_s = (iterations as f64 * size as f64) / (mono_elapsed.as_secs_f64() * 1024.0 * 1024.0 * 1024.0);
            let apex_gib_s = (iterations as f64 * size as f64) / (apex_elapsed.as_secs_f64() * 1024.0 * 1024.0 * 1024.0);

            eprintln!("{:>6}MB {:>12.2} GiB/s {:>12.2} GiB/s {:>8.2}x",
                size_mb, mono_gib_s, apex_gib_s, mono_gib_s / apex_gib_s);
        }
    }

    #[test]
    fn bench_monolithic_vs_blake3_crate() {
        if !is_x86_feature_detected!("avx512f") || !is_x86_feature_detected!("avx512bw") {
            eprintln!("AVX-512 not supported, skipping benchmark");
            return;
        }

        use std::time::Instant;

        // Create 16KB of test data
        let data: Vec<u8> = (0..16 * 1024).map(|i| (i % 256) as u8).collect();
        let key = IV;
        let counters: [u64; 16] = core::array::from_fn(|i| i as u64);
        let iterations = 50000;

        // Warm up
        for _ in 0..1000 {
            unsafe { hash_16_chunks_monolithic(&key, data.as_ptr(), &counters, 0); }
        }
        for _ in 0..1000 {
            let _ = blake3::hash(&data);
        }

        // Benchmark monolithic
        let start = Instant::now();
        for _ in 0..iterations {
            unsafe {
                let _ = hash_16_chunks_monolithic(&key, data.as_ptr(), &counters, 0);
            }
        }
        let monolithic_elapsed = start.elapsed();

        // Benchmark reference blake3
        let start = Instant::now();
        for _ in 0..iterations {
            let _ = blake3::hash(&data);
        }
        let blake3_elapsed = start.elapsed();

        let mono_gib_s = (iterations as f64 * 16.0 * 1024.0) / (monolithic_elapsed.as_secs_f64() * 1024.0 * 1024.0 * 1024.0);
        let blake3_gib_s = (iterations as f64 * 16.0 * 1024.0) / (blake3_elapsed.as_secs_f64() * 1024.0 * 1024.0 * 1024.0);

        eprintln!("\n=== 16KB Hash Performance ===");
        eprintln!("Monolithic: {:.2} GiB/s ({:.2} µs/hash)", mono_gib_s, monolithic_elapsed.as_nanos() as f64 / iterations as f64 / 1000.0);
        eprintln!("blake3 crate: {:.2} GiB/s ({:.2} µs/hash)", blake3_gib_s, blake3_elapsed.as_nanos() as f64 / iterations as f64 / 1000.0);
        eprintln!("Ratio: {:.2}x", mono_gib_s / blake3_gib_s);
    }

    #[test]
    fn test_monolithic_matches_per_round_asm() {
        if !is_x86_feature_detected!("avx512f") || !is_x86_feature_detected!("avx512bw") {
            eprintln!("AVX-512 not supported, skipping test");
            return;
        }

        use crate::blake3_simd::parallel16::hash_16_chunks_asm;

        // Create test data: 16 chunks of 1024 bytes each
        let mut data = vec![0u8; 16 * 1024];
        for (i, byte) in data.iter_mut().enumerate() {
            // Use a pattern that exercises different code paths
            *byte = ((i * 31 + 17) % 256) as u8;
        }

        let key = IV;
        let counters: [u64; 16] = core::array::from_fn(|i| i as u64);

        unsafe {
            let monolithic_cvs = hash_16_chunks_monolithic(&key, data.as_ptr(), &counters, 0);
            let per_round_cvs = hash_16_chunks_asm(&key, data.as_ptr(), &counters, 0);

            // Compare all 16 CVs
            for i in 0..16 {
                assert_eq!(
                    monolithic_cvs[i], per_round_cvs[i],
                    "CV {} differs: monolithic={:?} vs per-round={:?}",
                    i, monolithic_cvs[i], per_round_cvs[i]
                );
            }
        }
    }
}
