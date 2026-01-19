//! BLAKE3 hash function.
//!
//! BLAKE3 is an extremely fast cryptographic hash function:
//! - Faster than MD5 while being cryptographically secure
//! - Parallelizable (scales with CPU cores)
//! - Supports keyed hashing and key derivation
//! - Extendable output (XOF)

use crate::traits::{ExtendableOutput, HashOutput, Hasher, KeyDerivation};
use arcanum_core::error::Result;

/// BLAKE3 hash function.
///
/// The fastest cryptographic hash function available:
/// - 256-bit default output
/// - Built-in KDF mode
/// - Built-in keyed MAC mode
/// - Extendable output
#[derive(Clone)]
pub struct Blake3 {
    inner: blake3::Hasher,
}

impl Default for Blake3 {
    fn default() -> Self {
        <Self as Hasher>::new()
    }
}

impl Hasher for Blake3 {
    const OUTPUT_SIZE: usize = 32;
    const BLOCK_SIZE: usize = 64;
    const ALGORITHM: &'static str = "BLAKE3";

    fn new() -> Self {
        Self {
            inner: blake3::Hasher::new(),
        }
    }

    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    fn finalize(self) -> HashOutput {
        let hash = self.inner.finalize();
        HashOutput::from_array(*hash.as_bytes())
    }

    fn reset(&mut self) {
        self.inner.reset();
    }
}

impl ExtendableOutput for Blake3 {
    const ALGORITHM: &'static str = "BLAKE3";

    fn new() -> Self {
        Self {
            inner: blake3::Hasher::new(),
        }
    }

    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    fn squeeze(&mut self, output: &mut [u8]) {
        let mut reader = self.inner.finalize_xof();
        reader.fill(output);
    }

    fn finalize_xof(self, output_len: usize) -> Vec<u8> {
        let mut output = vec![0u8; output_len];
        let mut reader = self.inner.finalize_xof();
        reader.fill(&mut output);
        output
    }
}

impl Blake3 {
    /// Create a keyed hasher (MAC mode).
    ///
    /// The key must be exactly 32 bytes.
    pub fn new_keyed(key: &[u8; 32]) -> Self {
        Self {
            inner: blake3::Hasher::new_keyed(key),
        }
    }

    /// Create a key derivation hasher.
    ///
    /// The context string should be unique to the application.
    pub fn new_derive_key(context: &str) -> Self {
        Self {
            inner: blake3::Hasher::new_derive_key(context),
        }
    }

    /// Compute a keyed hash (MAC).
    pub fn keyed_hash(key: &[u8; 32], data: &[u8]) -> HashOutput {
        let hash = blake3::keyed_hash(key, data);
        HashOutput::from_array(*hash.as_bytes())
    }

    /// Derive a key using BLAKE3's built-in KDF.
    pub fn derive_key(context: &str, key_material: &[u8], output_len: usize) -> Vec<u8> {
        let mut hasher = blake3::Hasher::new_derive_key(context);
        hasher.update(key_material);
        let mut output = vec![0u8; output_len];
        let mut reader = hasher.finalize_xof();
        reader.fill(&mut output);
        output
    }

    /// Derive a fixed-size key.
    pub fn derive_key_array<const N: usize>(context: &str, key_material: &[u8]) -> [u8; N] {
        let mut hasher = blake3::Hasher::new_derive_key(context);
        hasher.update(key_material);
        let mut output = [0u8; N];
        let mut reader = hasher.finalize_xof();
        reader.fill(&mut output);
        output
    }
}

impl KeyDerivation for Blake3 {
    const ALGORITHM: &'static str = "BLAKE3-KDF";

    fn derive(
        ikm: &[u8],
        _salt: Option<&[u8]>,
        info: Option<&[u8]>,
        output_len: usize,
    ) -> Result<Vec<u8>> {
        // BLAKE3 KDF uses context string instead of salt
        // We use info as the context, defaulting to empty
        let context = info
            .map(|i| String::from_utf8_lossy(i).into_owned())
            .unwrap_or_else(|| "arcanum-blake3-kdf".to_string());

        Ok(Self::derive_key(&context, ikm, output_len))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blake3_empty() {
        let hash = Blake3::hash(b"");
        assert_eq!(
            hash.to_hex(),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
    }

    #[test]
    fn test_blake3_hello() {
        let hash = Blake3::hash(b"hello");
        assert_eq!(
            hash.to_hex(),
            "ea8f163db38682925e4491c5e58d4bb3506ef8c14eb78a86e908c5624a67200f"
        );
    }

    #[test]
    fn test_blake3_keyed() {
        let key = [0u8; 32];
        let hash = Blake3::keyed_hash(&key, b"hello");
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_blake3_xof() {
        let output = Blake3::hash_xof(b"hello", 64);
        assert_eq!(output.len(), 64);

        // First 32 bytes should match standard hash
        let standard = Blake3::hash(b"hello");
        assert_eq!(&output[..32], standard.as_bytes());
    }

    #[test]
    fn test_blake3_derive_key() {
        let key = Blake3::derive_key("my-app-encryption-key", b"master-secret", 32);
        assert_eq!(key.len(), 32);

        // Same input should produce same output
        let key2 = Blake3::derive_key("my-app-encryption-key", b"master-secret", 32);
        assert_eq!(key, key2);

        // Different context should produce different output
        let key3 = Blake3::derive_key("different-context", b"master-secret", 32);
        assert_ne!(key, key3);
    }

    #[test]
    fn test_blake3_incremental() {
        let mut hasher = <Blake3 as Hasher>::new();
        Hasher::update(&mut hasher, b"hel");
        Hasher::update(&mut hasher, b"lo");
        let hash = hasher.finalize();

        assert_eq!(hash, Blake3::hash(b"hello"));
    }
}
