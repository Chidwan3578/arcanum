//! # Arcanum Primitives
//!
//! Native cryptographic primitive implementations for the Arcanum engine.
//!
//! This crate provides pure-Rust implementations of core cryptographic
//! algorithms with optional SIMD acceleration.
//!
//! ## Design Goals
//!
//! 1. **Constant-time by default**: All operations on secret data are timing-safe
//! 2. **Zero dependencies on RustCrypto**: Standalone implementations
//! 3. **SIMD acceleration**: Optional AVX2/AVX-512/NEON when available
//! 4. **Memory safety**: Automatic zeroization of sensitive data
//!
//! ## Implemented Algorithms
//!
//! ### Hash Functions
//! - SHA-256, SHA-384, SHA-512 (FIPS 180-4 compliant)
//! - BLAKE3 (keyed hashing supported)
//!
//! ### Stream Ciphers
//! - ChaCha20 (RFC 8439)
//!
//! ### MACs
//! - Poly1305 (RFC 8439)
//! - HMAC (RFC 2104)
//!
//! ### AEAD
//! - ChaCha20-Poly1305 (RFC 8439)
//! - XChaCha20-Poly1305 (extended 24-byte nonce)

#![cfg_attr(not(feature = "std"), no_std)]
#![warn(missing_docs, rust_2018_idioms)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod ct;
pub mod backend;

#[cfg(feature = "sha2")]
pub mod sha2;

// SIMD-accelerated SHA-2 (SHA-NI)
#[cfg(all(feature = "sha2", feature = "simd"))]
#[allow(unsafe_code)]
pub mod sha2_simd;

#[cfg(feature = "blake3")]
pub mod blake3;

// SIMD-accelerated BLAKE3
#[cfg(all(feature = "blake3", feature = "simd"))]
#[allow(unsafe_code)]
pub mod blake3_simd;

// Turbo BLAKE3 with novel optimizations
#[cfg(all(feature = "blake3", feature = "simd"))]
#[allow(unsafe_code)]
pub mod blake3_turbo;

// Hyper BLAKE3 with multi-threading
#[cfg(all(feature = "blake3", feature = "simd"))]
#[allow(unsafe_code)]
pub mod blake3_hyper;

// Assembly-optimized BLAKE3 (AVX-512 only)
#[cfg(all(feature = "blake3", feature = "simd", target_arch = "x86_64"))]
#[allow(unsafe_code)]
pub mod blake3_asm;

// Ultra BLAKE3 with novel optimizations (prefetching, SIMD parent reduction)
#[cfg(all(feature = "blake3", feature = "simd", target_arch = "x86_64"))]
#[allow(unsafe_code)]
pub mod blake3_ultra;

// Monolithic assembly BLAKE3 (all 7 rounds in one asm! block)
#[cfg(all(feature = "blake3", feature = "simd", target_arch = "x86_64"))]
#[allow(unsafe_code)]
pub mod blake3_monolithic;

// CUDA-accelerated BLAKE3 for batch hashing on NVIDIA GPUs
// Optimized for RTX 4500 Ada Lovelace (sm_89) and similar architectures
#[cfg(feature = "cuda")]
#[allow(unsafe_code)]
pub mod blake3_cuda_ffi;

#[cfg(feature = "chacha20")]
pub mod chacha20;

// SIMD implementations (requires unsafe for intrinsics)
#[cfg(all(feature = "chacha20", feature = "simd"))]
#[allow(unsafe_code)]
pub mod chacha20_simd;

#[cfg(feature = "poly1305")]
pub mod poly1305;

// SIMD-accelerated Poly1305
#[cfg(all(feature = "poly1305", feature = "simd"))]
#[allow(unsafe_code)]
pub mod poly1305_simd;

#[cfg(feature = "chacha20poly1305")]
pub mod chacha20poly1305;

// Fused operations for improved cache performance
#[cfg(feature = "chacha20poly1305")]
pub mod fused;

// Batch processing for parallel SIMD operations
#[cfg(feature = "sha2")]
pub mod batch;

// Re-exports
pub use ct::{CtBool, CtEq, CtSelect};
pub use backend::{Backend, NativeBackend};

/// Prelude for convenient imports
pub mod prelude {
    pub use crate::ct::{CtBool, CtEq, CtSelect};
    pub use crate::backend::Backend;

    #[cfg(feature = "sha2")]
    pub use crate::sha2::{Sha256, Sha384, Sha512};

    #[cfg(feature = "blake3")]
    pub use crate::blake3::Blake3;

    #[cfg(feature = "chacha20poly1305")]
    pub use crate::chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305};
}
