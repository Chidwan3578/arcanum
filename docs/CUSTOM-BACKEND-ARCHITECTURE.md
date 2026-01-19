# Arcanum Custom Backend Architecture

## Overview

This document outlines the architecture for implementing Arcanum's own cryptographic primitives, replacing RustCrypto dependencies with custom, optimized implementations.

## Current State

```
┌─────────────────────────────────────────────────────────────┐
│                    Arcanum Public API                        │
├─────────────────────────────────────────────────────────────┤
│  arcanum-hash  │  arcanum-signatures  │  arcanum-symmetric  │
├─────────────────────────────────────────────────────────────┤
│                   Thin Wrappers (Current)                    │
├─────────────────────────────────────────────────────────────┤
│   sha2   │  ed25519-dalek  │  aes-gcm  │  ml-kem  │  etc.  │
│   blake3 │  p256/k256      │  chacha20 │  ml-dsa  │        │
└─────────────────────────────────────────────────────────────┘
                         RustCrypto
```

## Target Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Arcanum Public API                        │
├─────────────────────────────────────────────────────────────┤
│  arcanum-hash  │  arcanum-signatures  │  arcanum-symmetric  │
├─────────────────────────────────────────────────────────────┤
│              Backend Selection Layer (New)                   │
│   ┌─────────────────────────────────────────────────────┐   │
│   │  feature = "backend-native"  (default, pure Rust)   │   │
│   │  feature = "backend-ring"    (BoringSSL assembly)   │   │
│   │  feature = "backend-rustcrypto" (legacy compat)     │   │
│   └─────────────────────────────────────────────────────┘   │
├─────────────────────────────────────────────────────────────┤
│                 arcanum-primitives (New)                     │
│  ┌────────────────────────────────────────────────────────┐ │
│  │  Native Implementations:                               │ │
│  │  - SHA-256/384/512 (SIMD-optimized)                   │ │
│  │  - BLAKE3 (parallel, SIMD)                            │ │
│  │  - ChaCha20-Poly1305                                  │ │
│  │  - AES-256-GCM (AES-NI intrinsics)                    │ │
│  │  - HKDF, HMAC                                         │ │
│  │  - Constant-time utilities                            │ │
│  └────────────────────────────────────────────────────────┘ │
├─────────────────────────────────────────────────────────────┤
│              arcanum-asm (Platform Assembly)                 │
│  x86_64: AVX2, AVX-512, AES-NI, CLMUL                       │
│  aarch64: NEON, AES, SHA                                     │
│  Fallback: Pure Rust (constant-time)                         │
└─────────────────────────────────────────────────────────────┘
```

---

## Phase 1: Foundation (Weeks 1-4)

### 1.1 Create `arcanum-primitives` Crate

New crate containing low-level cryptographic building blocks.

```
arcanum-primitives/
├── Cargo.toml
├── src/
│   ├── lib.rs
│   ├── backend.rs          # Backend trait definitions
│   ├── ct.rs               # Constant-time operations
│   ├── simd/
│   │   ├── mod.rs
│   │   ├── x86_64.rs       # AVX2/AVX-512 intrinsics
│   │   └── aarch64.rs      # NEON intrinsics
│   ├── hash/
│   │   ├── mod.rs
│   │   ├── sha256.rs       # Native SHA-256
│   │   ├── sha512.rs       # Native SHA-512
│   │   └── blake3.rs       # Native BLAKE3
│   ├── cipher/
│   │   ├── mod.rs
│   │   ├── chacha20.rs     # ChaCha20 stream cipher
│   │   └── aes.rs          # AES block cipher
│   ├── aead/
│   │   ├── mod.rs
│   │   ├── chacha20poly1305.rs
│   │   └── aes_gcm.rs
│   └── mac/
│       ├── mod.rs
│       ├── poly1305.rs
│       └── ghash.rs        # GCM authenticator
└── benches/
    └── primitives_bench.rs
```

### 1.2 Backend Trait System

```rust
// arcanum-primitives/src/backend.rs

/// Marker trait for cryptographic backends
pub trait Backend: Sized + Clone + 'static {
    /// Backend identifier for debugging/logging
    const NAME: &'static str;

    /// Whether this backend uses hardware acceleration
    const HW_ACCELERATED: bool;
}

/// Native pure-Rust backend
#[derive(Clone, Copy)]
pub struct NativeBackend;

impl Backend for NativeBackend {
    const NAME: &'static str = "native";
    const HW_ACCELERATED: bool = false;
}

/// Backend with SIMD acceleration
#[derive(Clone, Copy)]
pub struct SimdBackend;

impl Backend for SimdBackend {
    const NAME: &'static str = "simd";
    const HW_ACCELERATED: bool = true;
}

/// Runtime backend selection
pub enum DynamicBackend {
    Native,
    Simd,
    #[cfg(feature = "backend-ring")]
    Ring,
}

impl DynamicBackend {
    /// Auto-detect best available backend
    pub fn detect() -> Self {
        #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
        return Self::Simd;

        #[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
        return Self::Simd;

        Self::Native
    }
}
```

### 1.3 Constant-Time Utilities

```rust
// arcanum-primitives/src/ct.rs

use core::ops::{BitAnd, BitOr, BitXor, Not};

/// Constant-time byte representing a boolean
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct CtBool(u8);

impl CtBool {
    pub const TRUE: Self = Self(0xff);
    pub const FALSE: Self = Self(0x00);

    /// Create from a boolean (constant-time)
    #[inline]
    pub fn from_bool(b: bool) -> Self {
        Self((-(b as i8)) as u8)
    }

    /// Convert to bool (timing leak - use only at end of computation)
    #[inline]
    pub fn to_bool(self) -> bool {
        self.0 != 0
    }

    /// Constant-time select: returns a if self is true, b otherwise
    #[inline]
    pub fn select<T: CtSelect>(self, a: T, b: T) -> T {
        T::ct_select(self, a, b)
    }
}

/// Constant-time equality comparison
pub trait CtEq {
    fn ct_eq(&self, other: &Self) -> CtBool;

    fn ct_ne(&self, other: &Self) -> CtBool {
        self.ct_eq(other).not()
    }
}

/// Constant-time conditional selection
pub trait CtSelect: Sized {
    fn ct_select(condition: CtBool, a: Self, b: Self) -> Self;
}

impl CtEq for [u8] {
    #[inline]
    fn ct_eq(&self, other: &Self) -> CtBool {
        if self.len() != other.len() {
            return CtBool::FALSE;
        }

        let mut diff = 0u8;
        for (a, b) in self.iter().zip(other.iter()) {
            diff |= a ^ b;
        }

        // diff == 0 iff all bytes equal
        // Convert to constant-time bool
        let is_zero = ((diff as u16).wrapping_sub(1) >> 8) as u8;
        CtBool(is_zero)
    }
}
```

---

## Phase 2: Hash Functions (Weeks 5-8)

### 2.1 SHA-256 Implementation

Pure Rust implementation with SIMD optimization paths.

```rust
// arcanum-primitives/src/hash/sha256.rs

/// SHA-256 round constants
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    // ... remaining constants
];

/// SHA-256 initial hash values
const H_INIT: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// Native SHA-256 state
pub struct Sha256State {
    h: [u32; 8],
    buffer: [u8; 64],
    buffer_len: usize,
    total_len: u64,
}

impl Sha256State {
    pub fn new() -> Self {
        Self {
            h: H_INIT,
            buffer: [0u8; 64],
            buffer_len: 0,
            total_len: 0,
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        let mut offset = 0;
        self.total_len += data.len() as u64;

        // Fill buffer if partially filled
        if self.buffer_len > 0 {
            let space = 64 - self.buffer_len;
            let to_copy = data.len().min(space);
            self.buffer[self.buffer_len..self.buffer_len + to_copy]
                .copy_from_slice(&data[..to_copy]);
            self.buffer_len += to_copy;
            offset = to_copy;

            if self.buffer_len == 64 {
                self.compress_block(&self.buffer.clone());
                self.buffer_len = 0;
            }
        }

        // Process full blocks
        while offset + 64 <= data.len() {
            self.compress_block(&data[offset..offset + 64].try_into().unwrap());
            offset += 64;
        }

        // Buffer remainder
        if offset < data.len() {
            let remainder = data.len() - offset;
            self.buffer[..remainder].copy_from_slice(&data[offset..]);
            self.buffer_len = remainder;
        }
    }

    pub fn finalize(mut self) -> [u8; 32] {
        // Padding
        let bit_len = self.total_len * 8;
        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;

        if self.buffer_len > 56 {
            // Need two blocks
            self.buffer[self.buffer_len..64].fill(0);
            self.compress_block(&self.buffer.clone());
            self.buffer.fill(0);
        } else {
            self.buffer[self.buffer_len..56].fill(0);
        }

        // Append length in bits (big-endian)
        self.buffer[56..64].copy_from_slice(&bit_len.to_be_bytes());
        self.compress_block(&self.buffer.clone());

        // Output
        let mut output = [0u8; 32];
        for (i, word) in self.h.iter().enumerate() {
            output[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
        }
        output
    }

    #[inline(always)]
    fn compress_block(&mut self, block: &[u8; 64]) {
        // Choose implementation based on available features
        #[cfg(all(target_arch = "x86_64", target_feature = "sha"))]
        {
            self.compress_block_sha_ni(block);
            return;
        }

        #[cfg(all(target_arch = "aarch64", target_feature = "sha2"))]
        {
            self.compress_block_arm_sha2(block);
            return;
        }

        self.compress_block_portable(block);
    }

    fn compress_block_portable(&mut self, block: &[u8; 64]) {
        // Message schedule
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes(block[i * 4..(i + 1) * 4].try_into().unwrap());
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }

        // Working variables
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.h;

        // 64 rounds
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
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

        // Update state
        self.h[0] = self.h[0].wrapping_add(a);
        self.h[1] = self.h[1].wrapping_add(b);
        self.h[2] = self.h[2].wrapping_add(c);
        self.h[3] = self.h[3].wrapping_add(d);
        self.h[4] = self.h[4].wrapping_add(e);
        self.h[5] = self.h[5].wrapping_add(f);
        self.h[6] = self.h[6].wrapping_add(g);
        self.h[7] = self.h[7].wrapping_add(h);
    }

    #[cfg(all(target_arch = "x86_64", target_feature = "sha"))]
    fn compress_block_sha_ni(&mut self, block: &[u8; 64]) {
        // Intel SHA Extensions implementation
        use core::arch::x86_64::*;

        unsafe {
            // Load state
            let mut state0 = _mm_loadu_si128(self.h[0..4].as_ptr() as *const __m128i);
            let mut state1 = _mm_loadu_si128(self.h[4..8].as_ptr() as *const __m128i);

            // ... SHA-NI intrinsics implementation
        }
    }
}
```

### 2.2 BLAKE3 Implementation

```rust
// arcanum-primitives/src/hash/blake3.rs

/// BLAKE3 constants
const IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

const MSG_PERMUTATION: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

/// BLAKE3 domain flags
mod flags {
    pub const CHUNK_START: u8 = 1 << 0;
    pub const CHUNK_END: u8 = 1 << 1;
    pub const PARENT: u8 = 1 << 2;
    pub const ROOT: u8 = 1 << 3;
    pub const KEYED_HASH: u8 = 1 << 4;
    pub const DERIVE_KEY_CONTEXT: u8 = 1 << 5;
    pub const DERIVE_KEY_MATERIAL: u8 = 1 << 6;
}

/// BLAKE3 hasher
pub struct Blake3 {
    key: [u32; 8],
    cv_stack: Vec<[u32; 8]>,
    chunk_state: ChunkState,
    flags: u8,
}

struct ChunkState {
    cv: [u32; 8],
    chunk_counter: u64,
    buf: [u8; 64],
    buf_len: usize,
    blocks_compressed: u8,
    flags: u8,
}

impl Blake3 {
    pub fn new() -> Self {
        Self {
            key: IV,
            cv_stack: Vec::with_capacity(54), // Max tree depth
            chunk_state: ChunkState::new(&IV, 0, 0),
            flags: 0,
        }
    }

    pub fn keyed(key: &[u8; 32]) -> Self {
        let key_words = words_from_bytes(key);
        Self {
            key: key_words,
            cv_stack: Vec::with_capacity(54),
            chunk_state: ChunkState::new(&key_words, 0, flags::KEYED_HASH),
            flags: flags::KEYED_HASH,
        }
    }

    pub fn update(&mut self, mut input: &[u8]) {
        while !input.is_empty() {
            if self.chunk_state.len() == 1024 {
                let cv = self.chunk_state.output().chaining_value();
                let total_chunks = self.chunk_state.chunk_counter + 1;
                self.add_chunk_cv(cv, total_chunks);
                self.chunk_state = ChunkState::new(&self.key, total_chunks, self.flags);
            }

            let take = input.len().min(1024 - self.chunk_state.len());
            self.chunk_state.update(&input[..take]);
            input = &input[take..];
        }
    }

    pub fn finalize(&self) -> [u8; 32] {
        self.finalize_xof().take::<32>()
    }

    fn g(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, mx: u32, my: u32) {
        state[a] = state[a].wrapping_add(state[b]).wrapping_add(mx);
        state[d] = (state[d] ^ state[a]).rotate_right(16);
        state[c] = state[c].wrapping_add(state[d]);
        state[b] = (state[b] ^ state[c]).rotate_right(12);
        state[a] = state[a].wrapping_add(state[b]).wrapping_add(my);
        state[d] = (state[d] ^ state[a]).rotate_right(8);
        state[c] = state[c].wrapping_add(state[d]);
        state[b] = (state[b] ^ state[c]).rotate_right(7);
    }

    fn compress(
        cv: &[u32; 8],
        block: &[u8; 64],
        counter: u64,
        block_len: u32,
        flags: u8,
    ) -> [u32; 16] {
        let m = words_from_bytes(block);
        let mut state = [
            cv[0], cv[1], cv[2], cv[3],
            cv[4], cv[5], cv[6], cv[7],
            IV[0], IV[1], IV[2], IV[3],
            counter as u32, (counter >> 32) as u32, block_len, flags as u32,
        ];

        let mut m_sched = m;

        // 7 rounds
        for _ in 0..7 {
            // Column step
            Self::g(&mut state, 0, 4, 8, 12, m_sched[0], m_sched[1]);
            Self::g(&mut state, 1, 5, 9, 13, m_sched[2], m_sched[3]);
            Self::g(&mut state, 2, 6, 10, 14, m_sched[4], m_sched[5]);
            Self::g(&mut state, 3, 7, 11, 15, m_sched[6], m_sched[7]);

            // Diagonal step
            Self::g(&mut state, 0, 5, 10, 15, m_sched[8], m_sched[9]);
            Self::g(&mut state, 1, 6, 11, 12, m_sched[10], m_sched[11]);
            Self::g(&mut state, 2, 7, 8, 13, m_sched[12], m_sched[13]);
            Self::g(&mut state, 3, 4, 9, 14, m_sched[14], m_sched[15]);

            // Permute message schedule
            m_sched = permute(m_sched);
        }

        // Feed-forward
        for i in 0..8 {
            state[i] ^= state[i + 8];
            state[i + 8] ^= cv[i];
        }

        state
    }
}

#[inline(always)]
fn words_from_bytes(bytes: &[u8]) -> [u32; 16] {
    let mut words = [0u32; 16];
    for (i, chunk) in bytes.chunks(4).enumerate().take(16) {
        words[i] = u32::from_le_bytes(chunk.try_into().unwrap_or([0; 4]));
    }
    words
}

#[inline(always)]
fn permute(m: [u32; 16]) -> [u32; 16] {
    let mut permuted = [0u32; 16];
    for (i, &idx) in MSG_PERMUTATION.iter().enumerate() {
        permuted[i] = m[idx];
    }
    permuted
}
```

---

## Phase 3: Symmetric Ciphers (Weeks 9-12)

### 3.1 ChaCha20 Implementation

```rust
// arcanum-primitives/src/cipher/chacha20.rs

/// ChaCha20 quarter round
#[inline(always)]
fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(16);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(12);

    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(8);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(7);
}

/// ChaCha20 block function
pub fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let mut state = [0u32; 16];

    // "expand 32-byte k"
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;

    // Key
    for i in 0..8 {
        state[4 + i] = u32::from_le_bytes(key[i * 4..(i + 1) * 4].try_into().unwrap());
    }

    // Counter
    state[12] = counter;

    // Nonce
    for i in 0..3 {
        state[13 + i] = u32::from_le_bytes(nonce[i * 4..(i + 1) * 4].try_into().unwrap());
    }

    let initial_state = state;

    // 20 rounds (10 double-rounds)
    for _ in 0..10 {
        // Column rounds
        quarter_round(&mut state, 0, 4, 8, 12);
        quarter_round(&mut state, 1, 5, 9, 13);
        quarter_round(&mut state, 2, 6, 10, 14);
        quarter_round(&mut state, 3, 7, 11, 15);

        // Diagonal rounds
        quarter_round(&mut state, 0, 5, 10, 15);
        quarter_round(&mut state, 1, 6, 11, 12);
        quarter_round(&mut state, 2, 7, 8, 13);
        quarter_round(&mut state, 3, 4, 9, 14);
    }

    // Add initial state
    for i in 0..16 {
        state[i] = state[i].wrapping_add(initial_state[i]);
    }

    // Serialize
    let mut output = [0u8; 64];
    for (i, word) in state.iter().enumerate() {
        output[i * 4..(i + 1) * 4].copy_from_slice(&word.to_le_bytes());
    }

    output
}

/// ChaCha20 stream cipher
pub struct ChaCha20 {
    key: [u8; 32],
    nonce: [u8; 12],
    counter: u32,
    buffer: [u8; 64],
    buffer_pos: usize,
}

impl ChaCha20 {
    pub fn new(key: &[u8; 32], nonce: &[u8; 12]) -> Self {
        Self {
            key: *key,
            nonce: *nonce,
            counter: 0,
            buffer: [0u8; 64],
            buffer_pos: 64, // Empty buffer
        }
    }

    pub fn apply_keystream(&mut self, data: &mut [u8]) {
        for byte in data.iter_mut() {
            if self.buffer_pos >= 64 {
                self.buffer = chacha20_block(&self.key, self.counter, &self.nonce);
                self.counter += 1;
                self.buffer_pos = 0;
            }
            *byte ^= self.buffer[self.buffer_pos];
            self.buffer_pos += 1;
        }
    }
}
```

### 3.2 Poly1305 Implementation

```rust
// arcanum-primitives/src/mac/poly1305.rs

/// Poly1305 authenticator
pub struct Poly1305 {
    r: [u32; 5],   // Clamped key
    h: [u32; 5],   // Accumulator
    pad: [u32; 4], // Pad from key
}

impl Poly1305 {
    pub fn new(key: &[u8; 32]) -> Self {
        // r = key[0..16] with clamping
        let mut r = [0u32; 5];
        r[0] = u32::from_le_bytes(key[0..4].try_into().unwrap()) & 0x0fff_fffc;
        r[1] = u32::from_le_bytes(key[4..8].try_into().unwrap()) & 0x0fff_fffc;
        r[2] = u32::from_le_bytes(key[8..12].try_into().unwrap()) & 0x0fff_fffc;
        r[3] = u32::from_le_bytes(key[12..16].try_into().unwrap()) & 0x0fff_fffc;
        r[4] = 0;

        // Clamp r
        r[0] &= 0x0fff_fffc;
        r[1] &= 0x0fff_fffc;
        r[2] &= 0x0fff_fffc;
        r[3] &= 0x0fff_fffc;

        // pad = key[16..32]
        let mut pad = [0u32; 4];
        for i in 0..4 {
            pad[i] = u32::from_le_bytes(key[16 + i * 4..20 + i * 4].try_into().unwrap());
        }

        Self {
            r,
            h: [0u32; 5],
            pad,
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        for chunk in data.chunks(16) {
            self.block(chunk, chunk.len() < 16);
        }
    }

    fn block(&mut self, block: &[u8], partial: bool) {
        // ... Poly1305 block processing
        // Uses 130-bit arithmetic emulated with u32s
    }

    pub fn finalize(mut self) -> [u8; 16] {
        // Final reduction and add pad
        let mut tag = [0u8; 16];
        // ... finalization
        tag
    }
}
```

---

## Phase 4: AEAD Constructions (Weeks 13-16)

### 4.1 ChaCha20-Poly1305

```rust
// arcanum-primitives/src/aead/chacha20poly1305.rs

use crate::cipher::chacha20::ChaCha20;
use crate::mac::poly1305::Poly1305;

pub struct ChaCha20Poly1305;

impl ChaCha20Poly1305 {
    pub fn encrypt(
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        plaintext: &[u8],
    ) -> (Vec<u8>, [u8; 16]) {
        // Generate Poly1305 key from first ChaCha20 block
        let poly_key = chacha20_block(key, 0, nonce);
        let poly_key: [u8; 32] = poly_key[..32].try_into().unwrap();

        // Encrypt plaintext
        let mut ciphertext = plaintext.to_vec();
        let mut cipher = ChaCha20::new(key, nonce);
        cipher.counter = 1; // Skip first block (used for poly key)
        cipher.apply_keystream(&mut ciphertext);

        // Compute tag
        let mut poly = Poly1305::new(&poly_key);
        poly.update(aad);
        poly.update(&pad16(aad.len()));
        poly.update(&ciphertext);
        poly.update(&pad16(ciphertext.len()));
        poly.update(&(aad.len() as u64).to_le_bytes());
        poly.update(&(ciphertext.len() as u64).to_le_bytes());
        let tag = poly.finalize();

        (ciphertext, tag)
    }

    pub fn decrypt(
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8; 16],
    ) -> Result<Vec<u8>, AuthError> {
        // Generate Poly1305 key
        let poly_key = chacha20_block(key, 0, nonce);
        let poly_key: [u8; 32] = poly_key[..32].try_into().unwrap();

        // Verify tag first (constant-time)
        let mut poly = Poly1305::new(&poly_key);
        poly.update(aad);
        poly.update(&pad16(aad.len()));
        poly.update(ciphertext);
        poly.update(&pad16(ciphertext.len()));
        poly.update(&(aad.len() as u64).to_le_bytes());
        poly.update(&(ciphertext.len() as u64).to_le_bytes());
        let computed_tag = poly.finalize();

        if !constant_time_eq(&computed_tag, tag) {
            return Err(AuthError);
        }

        // Decrypt
        let mut plaintext = ciphertext.to_vec();
        let mut cipher = ChaCha20::new(key, nonce);
        cipher.counter = 1;
        cipher.apply_keystream(&mut plaintext);

        Ok(plaintext)
    }
}
```

---

## Phase 5: Integration (Weeks 17-20)

### 5.1 Backend Selection in arcanum-hash

```rust
// arcanum-hash/src/sha2_impl.rs

#[cfg(feature = "backend-native")]
use arcanum_primitives::hash::sha256::Sha256State as Sha256Inner;

#[cfg(all(feature = "backend-rustcrypto", not(feature = "backend-native")))]
use sha2::Sha256 as Sha256Inner;

pub struct Sha256 {
    #[cfg(feature = "backend-native")]
    inner: Sha256State,

    #[cfg(all(feature = "backend-rustcrypto", not(feature = "backend-native")))]
    inner: sha2::Sha256,
}
```

### 5.2 Feature Flags

```toml
# arcanum-hash/Cargo.toml
[features]
default = ["backend-native", "sha2", "blake3"]

# Backend selection
backend-native = ["arcanum-primitives"]
backend-rustcrypto = ["sha2", "blake3"]
backend-ring = ["ring"]

# Algorithms
sha2 = []
sha3 = []
blake3 = []
```

---

## Security Requirements

### Constant-Time Operations

All implementations MUST be constant-time for:
- Key comparisons
- MAC verification
- Conditional operations on secret data

### Memory Handling

- All secret key material MUST be zeroized on drop
- Stack buffers containing secrets MUST be zeroized
- No logging of sensitive data

### Testing Requirements

1. **Known Answer Tests (KAT)**: Test vectors from NIST/RFCs
2. **Property Tests**: Quickcheck/proptest for random inputs
3. **Timing Tests**: Verify constant-time behavior with dudect
4. **Fuzzing**: OSS-Fuzz integration

### Audit Plan

| Phase | Algorithm | Audit Type | Estimated Cost |
|-------|-----------|------------|----------------|
| 2 | SHA-256 | Code review | $15k |
| 2 | BLAKE3 | Code review | $15k |
| 3 | ChaCha20 | Code review | $10k |
| 3 | Poly1305 | Code review + timing | $20k |
| 4 | ChaCha20-Poly1305 | Full audit | $30k |
| - | Full suite | Comprehensive | $100k+ |

---

## Implementation Priorities

### Must Have (Phase 1-2)
- [ ] Constant-time utilities
- [ ] SHA-256 (portable + SHA-NI)
- [ ] BLAKE3 (portable)
- [ ] Backend selection framework

### Should Have (Phase 3-4)
- [ ] SHA-512
- [ ] ChaCha20-Poly1305
- [ ] HKDF/HMAC

### Nice to Have (Phase 5+)
- [ ] AES-GCM (AES-NI only)
- [ ] AVX-512 optimizations
- [ ] ARM Cryptography Extensions

### Keep External
- [ ] Ed25519 (ed25519-dalek - well audited)
- [ ] ECDSA (complex, audited implementations exist)
- [ ] ML-KEM/ML-DSA (too new, rapid changes)

---

## Risk Matrix

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Side-channel vulnerability | Medium | Critical | Constant-time testing, audit |
| Performance regression | Medium | Medium | Extensive benchmarking |
| Implementation bug | High | Critical | Property testing, KAT, fuzzing |
| Upstream changes | Low | Low | Version pinning |
| Maintenance burden | High | Medium | Clear ownership, documentation |

---

## Decision Points

1. **AES-GCM**: Implement native or use ring backend?
   - ring is 2-3x faster due to AES-NI+CLMUL assembly
   - Recommendation: **Use ring for AES-GCM**

2. **Ed25519**: Implement native?
   - ed25519-dalek is well-audited and fast
   - Field arithmetic is complex and error-prone
   - Recommendation: **Keep ed25519-dalek**

3. **ML-KEM/ML-DSA**: Implement native?
   - Standards still being finalized
   - Existing implementations track spec changes
   - Recommendation: **Keep external until stable**

---

## Summary

This phased approach allows Arcanum to:
1. Own critical hash function implementations
2. Control performance optimizations (SIMD, assembly)
3. Maintain API stability regardless of upstream changes
4. Keep well-audited external implementations for complex algorithms

Total estimated effort: 20 weeks for core functionality
Total estimated audit cost: $90-150k for production readiness
