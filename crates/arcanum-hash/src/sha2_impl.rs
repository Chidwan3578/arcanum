//! SHA-2 hash functions.
//!
//! The SHA-2 family is the current NIST standard for cryptographic hashing.
//!
//! - **SHA-256**: 256-bit output, most widely used
//! - **SHA-384**: 384-bit output, truncated SHA-512
//! - **SHA-512**: 512-bit output, faster on 64-bit platforms
//!
//! # Backend Selection
//!
//! This module supports two backends:
//! - `backend-native` (default): Uses Arcanum's native implementations
//! - `backend-rustcrypto`: Uses RustCrypto's sha2 crate

use crate::traits::{HashOutput, Hasher};

// ═══════════════════════════════════════════════════════════════════════════════
// BACKEND SELECTION
// ═══════════════════════════════════════════════════════════════════════════════

/// Use native Arcanum primitives when backend-native is enabled
#[cfg(feature = "backend-native")]
mod backend {
    pub use arcanum_primitives::sha2::{Sha256 as Sha256Inner, Sha384 as Sha384Inner, Sha512 as Sha512Inner};
}

/// Fall back to RustCrypto when backend-native is not enabled
#[cfg(not(feature = "backend-native"))]
mod backend {
    pub use sha2::{Sha256 as Sha256Inner, Sha384 as Sha384Inner, Sha512 as Sha512Inner};
}

// ═══════════════════════════════════════════════════════════════════════════════
// SHA-256
// ═══════════════════════════════════════════════════════════════════════════════

/// SHA-256 hash function.
///
/// The most commonly used hash function, providing 256-bit (32 byte) output.
#[derive(Clone)]
pub struct Sha256 {
    #[cfg(feature = "backend-native")]
    inner: backend::Sha256Inner,

    #[cfg(not(feature = "backend-native"))]
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
        #[cfg(feature = "backend-native")]
        {
            Self {
                inner: backend::Sha256Inner::new(),
            }
        }

        #[cfg(not(feature = "backend-native"))]
        {
            use digest::Digest;
            Self {
                inner: sha2::Sha256::new(),
            }
        }
    }

    fn update(&mut self, data: &[u8]) {
        #[cfg(feature = "backend-native")]
        {
            self.inner.update(data);
        }

        #[cfg(not(feature = "backend-native"))]
        {
            use digest::Digest;
            Digest::update(&mut self.inner, data);
        }
    }

    fn finalize(self) -> HashOutput {
        #[cfg(feature = "backend-native")]
        {
            let result = self.inner.finalize();
            HashOutput::from_array(result)
        }

        #[cfg(not(feature = "backend-native"))]
        {
            use digest::Digest;
            let result = self.inner.finalize();
            HashOutput::from_array(result.into())
        }
    }

    fn reset(&mut self) {
        #[cfg(feature = "backend-native")]
        {
            self.inner = backend::Sha256Inner::new();
        }

        #[cfg(not(feature = "backend-native"))]
        {
            use digest::Digest;
            self.inner = sha2::Sha256::new();
        }
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
    #[cfg(feature = "backend-native")]
    inner: backend::Sha384Inner,

    #[cfg(not(feature = "backend-native"))]
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
        #[cfg(feature = "backend-native")]
        {
            Self {
                inner: backend::Sha384Inner::new(),
            }
        }

        #[cfg(not(feature = "backend-native"))]
        {
            use digest::Digest;
            Self {
                inner: sha2::Sha384::new(),
            }
        }
    }

    fn update(&mut self, data: &[u8]) {
        #[cfg(feature = "backend-native")]
        {
            self.inner.update(data);
        }

        #[cfg(not(feature = "backend-native"))]
        {
            use digest::Digest;
            Digest::update(&mut self.inner, data);
        }
    }

    fn finalize(self) -> HashOutput {
        #[cfg(feature = "backend-native")]
        {
            let result = self.inner.finalize();
            HashOutput::from_array(result)
        }

        #[cfg(not(feature = "backend-native"))]
        {
            use digest::Digest;
            let result = self.inner.finalize();
            HashOutput::from_array(result.into())
        }
    }

    fn reset(&mut self) {
        #[cfg(feature = "backend-native")]
        {
            self.inner = backend::Sha384Inner::new();
        }

        #[cfg(not(feature = "backend-native"))]
        {
            use digest::Digest;
            self.inner = sha2::Sha384::new();
        }
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
    #[cfg(feature = "backend-native")]
    inner: backend::Sha512Inner,

    #[cfg(not(feature = "backend-native"))]
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
        #[cfg(feature = "backend-native")]
        {
            Self {
                inner: backend::Sha512Inner::new(),
            }
        }

        #[cfg(not(feature = "backend-native"))]
        {
            use digest::Digest;
            Self {
                inner: sha2::Sha512::new(),
            }
        }
    }

    fn update(&mut self, data: &[u8]) {
        #[cfg(feature = "backend-native")]
        {
            self.inner.update(data);
        }

        #[cfg(not(feature = "backend-native"))]
        {
            use digest::Digest;
            Digest::update(&mut self.inner, data);
        }
    }

    fn finalize(self) -> HashOutput {
        #[cfg(feature = "backend-native")]
        {
            let result = self.inner.finalize();
            HashOutput::from_array(result)
        }

        #[cfg(not(feature = "backend-native"))]
        {
            use digest::Digest;
            let result = self.inner.finalize();
            HashOutput::from_array(result.into())
        }
    }

    fn reset(&mut self) {
        #[cfg(feature = "backend-native")]
        {
            self.inner = backend::Sha512Inner::new();
        }

        #[cfg(not(feature = "backend-native"))]
        {
            use digest::Digest;
            self.inner = sha2::Sha512::new();
        }
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

    /// Verify that native and RustCrypto backends produce identical output
    #[cfg(all(feature = "backend-native", feature = "sha2"))]
    #[test]
    fn test_backend_compatibility_sha256() {
        use digest::Digest;

        let test_data = b"The quick brown fox jumps over the lazy dog";

        // Native backend
        let native_hash = Sha256::hash(test_data);

        // RustCrypto backend
        let mut rustcrypto = sha2::Sha256::new();
        Digest::update(&mut rustcrypto, test_data);
        let rustcrypto_hash: [u8; 32] = rustcrypto.finalize().into();

        assert_eq!(native_hash.as_bytes(), &rustcrypto_hash);
    }

    /// Verify that native and RustCrypto backends produce identical output for SHA-384
    #[cfg(all(feature = "backend-native", feature = "sha2"))]
    #[test]
    fn test_backend_compatibility_sha384() {
        use digest::Digest;

        let test_data = b"The quick brown fox jumps over the lazy dog";

        // Native backend
        let native_hash = Sha384::hash(test_data);

        // RustCrypto backend
        let mut rustcrypto = sha2::Sha384::new();
        Digest::update(&mut rustcrypto, test_data);
        let rustcrypto_hash: [u8; 48] = rustcrypto.finalize().into();

        assert_eq!(native_hash.as_bytes(), &rustcrypto_hash);
    }

    /// Verify that native and RustCrypto backends produce identical output for SHA-512
    #[cfg(all(feature = "backend-native", feature = "sha2"))]
    #[test]
    fn test_backend_compatibility_sha512() {
        use digest::Digest;

        let test_data = b"The quick brown fox jumps over the lazy dog";

        // Native backend
        let native_hash = Sha512::hash(test_data);

        // RustCrypto backend
        let mut rustcrypto = sha2::Sha512::new();
        Digest::update(&mut rustcrypto, test_data);
        let rustcrypto_hash: [u8; 64] = rustcrypto.finalize().into();

        assert_eq!(native_hash.as_bytes(), &rustcrypto_hash);
    }
}
