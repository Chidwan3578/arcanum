//! SHA-2 hash functions.
//!
//! The SHA-2 family is the current NIST standard for cryptographic hashing.
//!
//! - **SHA-256**: 256-bit output, most widely used
//! - **SHA-384**: 384-bit output, truncated SHA-512
//! - **SHA-512**: 512-bit output, faster on 64-bit platforms

use crate::traits::{HashOutput, Hasher};
use digest::Digest;

// ═══════════════════════════════════════════════════════════════════════════════
// SHA-256
// ═══════════════════════════════════════════════════════════════════════════════

/// SHA-256 hash function.
///
/// The most commonly used hash function, providing 256-bit (32 byte) output.
#[derive(Clone)]
pub struct Sha256 {
    inner: sha2::Sha256,
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Hasher for Sha256 {
    const OUTPUT_SIZE: usize = 32;
    const BLOCK_SIZE: usize = 64;
    const ALGORITHM: &'static str = "SHA-256";

    fn new() -> Self {
        Self {
            inner: sha2::Sha256::new(),
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
        self.inner = sha2::Sha256::new();
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// SHA-384
// ═══════════════════════════════════════════════════════════════════════════════

/// SHA-384 hash function.
///
/// A truncated version of SHA-512, providing 384-bit (48 byte) output.
#[derive(Clone)]
pub struct Sha384 {
    inner: sha2::Sha384,
}

impl Default for Sha384 {
    fn default() -> Self {
        Self::new()
    }
}

impl Hasher for Sha384 {
    const OUTPUT_SIZE: usize = 48;
    const BLOCK_SIZE: usize = 128;
    const ALGORITHM: &'static str = "SHA-384";

    fn new() -> Self {
        Self {
            inner: sha2::Sha384::new(),
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
        self.inner = sha2::Sha384::new();
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// SHA-512
// ═══════════════════════════════════════════════════════════════════════════════

/// SHA-512 hash function.
///
/// Provides 512-bit (64 byte) output. Faster than SHA-256 on 64-bit platforms.
#[derive(Clone)]
pub struct Sha512 {
    inner: sha2::Sha512,
}

impl Default for Sha512 {
    fn default() -> Self {
        Self::new()
    }
}

impl Hasher for Sha512 {
    const OUTPUT_SIZE: usize = 64;
    const BLOCK_SIZE: usize = 128;
    const ALGORITHM: &'static str = "SHA-512";

    fn new() -> Self {
        Self {
            inner: sha2::Sha512::new(),
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
        self.inner = sha2::Sha512::new();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_empty() {
        let hash = Sha256::hash(b"");
        assert_eq!(
            hash.to_hex(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_sha256_hello() {
        let hash = Sha256::hash(b"hello");
        assert_eq!(
            hash.to_hex(),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn test_sha256_incremental() {
        let mut hasher = Sha256::new();
        hasher.update(b"hel");
        hasher.update(b"lo");
        let hash = hasher.finalize();

        assert_eq!(hash, Sha256::hash(b"hello"));
    }

    #[test]
    fn test_sha384_empty() {
        let hash = Sha384::hash(b"");
        assert_eq!(
            hash.to_hex(),
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
        );
    }

    #[test]
    fn test_sha512_empty() {
        let hash = Sha512::hash(b"");
        assert_eq!(
            hash.to_hex(),
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        );
    }

    #[test]
    fn test_verify() {
        let data = b"test data";
        let hash = Sha256::hash(data);
        assert!(Sha256::verify(data, &hash));
        assert!(!Sha256::verify(b"wrong data", &hash));
    }
}
