//! BLAKE2 hash functions.
//!
//! BLAKE2 is a fast cryptographic hash function:
//! - **BLAKE2b**: Optimized for 64-bit platforms, up to 64-byte output
//! - **BLAKE2s**: Optimized for 8-32 bit platforms, up to 32-byte output

use crate::traits::{HashOutput, Hasher};
use blake2::{Blake2b512, Blake2s256, Digest};

// ═══════════════════════════════════════════════════════════════════════════════
// BLAKE2b
// ═══════════════════════════════════════════════════════════════════════════════

/// BLAKE2b hash function (512-bit output).
///
/// Optimized for 64-bit platforms. Faster than SHA-2 while providing
/// equivalent security.
#[derive(Clone)]
pub struct Blake2b {
    inner: Blake2b512,
}

impl Default for Blake2b {
    fn default() -> Self {
        Self::new()
    }
}

impl Hasher for Blake2b {
    const OUTPUT_SIZE: usize = 64;
    const BLOCK_SIZE: usize = 128;
    const ALGORITHM: &'static str = "BLAKE2b-512";

    fn new() -> Self {
        Self {
            inner: Blake2b512::new(),
        }
    }

    fn update(&mut self, data: &[u8]) {
        Digest::update(&mut self.inner, data);
    }

    fn finalize(self) -> HashOutput {
        let result = self.inner.finalize();
        HashOutput::from_array(result.into())
    }

    fn reset(&mut self) {
        self.inner = Blake2b512::new();
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// BLAKE2s
// ═══════════════════════════════════════════════════════════════════════════════

/// BLAKE2s hash function (256-bit output).
///
/// Optimized for 8-32 bit platforms. Good choice for embedded systems.
#[derive(Clone)]
pub struct Blake2s {
    inner: Blake2s256,
}

impl Default for Blake2s {
    fn default() -> Self {
        Self::new()
    }
}

impl Hasher for Blake2s {
    const OUTPUT_SIZE: usize = 32;
    const BLOCK_SIZE: usize = 64;
    const ALGORITHM: &'static str = "BLAKE2s-256";

    fn new() -> Self {
        Self {
            inner: Blake2s256::new(),
        }
    }

    fn update(&mut self, data: &[u8]) {
        Digest::update(&mut self.inner, data);
    }

    fn finalize(self) -> HashOutput {
        let result = self.inner.finalize();
        HashOutput::from_array(result.into())
    }

    fn reset(&mut self) {
        self.inner = Blake2s256::new();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blake2b_empty() {
        let hash = Blake2b::hash(b"");
        // BLAKE2b-512 of empty string
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn test_blake2b_hello() {
        let hash = Blake2b::hash(b"hello");
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn test_blake2s_empty() {
        let hash = Blake2s::hash(b"");
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_blake2s_hello() {
        let hash = Blake2s::hash(b"hello");
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_blake2b_incremental() {
        let mut hasher = Blake2b::new();
        hasher.update(b"hel");
        hasher.update(b"lo");
        let hash = hasher.finalize();

        assert_eq!(hash, Blake2b::hash(b"hello"));
    }
}
