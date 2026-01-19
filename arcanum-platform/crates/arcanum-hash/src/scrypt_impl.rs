//! scrypt password hashing.
//!
//! scrypt is a memory-hard password hashing function designed to be
//! expensive to attack with custom hardware.

use crate::traits::PasswordHash;
use arcanum_core::error::{Error, Result};
use scrypt::{
    password_hash::{PasswordHasher, PasswordVerifier, SaltString},
    Params, Scrypt as ScryptInner,
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

/// scrypt parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScryptParams {
    /// Log2 of the CPU/memory cost parameter (default: 15, meaning 2^15)
    pub log_n: u8,
    /// Block size parameter (default: 8)
    pub r: u32,
    /// Parallelization parameter (default: 1)
    pub p: u32,
    /// Output length in bytes (default: 32)
    pub output_len: usize,
}

impl Default for ScryptParams {
    fn default() -> Self {
        Self::moderate()
    }
}

impl std::fmt::Display for ScryptParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "scrypt(N=2^{}, r={}, p={})",
            self.log_n, self.r, self.p
        )
    }
}

impl ScryptParams {
    /// Create custom parameters.
    pub fn new(log_n: u8, r: u32, p: u32) -> Self {
        Self {
            log_n,
            r,
            p,
            output_len: 32,
        }
    }

    /// Create a builder for custom parameters.
    ///
    /// # Example
    ///
    /// ```rust
    /// use arcanum_hash::ScryptParams;
    ///
    /// let params = ScryptParams::builder()
    ///     .log_n(15)           // N = 2^15 = 32768
    ///     .block_size(8)       // r = 8
    ///     .parallelism(1)      // p = 1
    ///     .build();
    /// ```
    pub fn builder() -> ScryptParamsBuilder {
        ScryptParamsBuilder::default()
    }

    /// Low security parameters (for testing).
    ///
    /// log_n: 12, r: 8, p: 1 (~4 MiB memory)
    pub fn low() -> Self {
        Self {
            log_n: 12,
            r: 8,
            p: 1,
            output_len: 32,
        }
    }

    /// Moderate security parameters.
    ///
    /// log_n: 15, r: 8, p: 1 (~32 MiB memory)
    pub fn moderate() -> Self {
        Self {
            log_n: 15,
            r: 8,
            p: 1,
            output_len: 32,
        }
    }

    /// High security parameters.
    ///
    /// log_n: 17, r: 8, p: 1 (~128 MiB memory)
    pub fn high() -> Self {
        Self {
            log_n: 17,
            r: 8,
            p: 1,
            output_len: 32,
        }
    }

    /// Interactive parameters (fast response time).
    ///
    /// log_n: 14, r: 8, p: 1 (~16 MiB memory)
    pub fn interactive() -> Self {
        Self {
            log_n: 14,
            r: 8,
            p: 1,
            output_len: 32,
        }
    }

    /// Sensitive parameters (for highly sensitive data).
    ///
    /// log_n: 20, r: 8, p: 1 (~1 GiB memory)
    pub fn sensitive() -> Self {
        Self {
            log_n: 20,
            r: 8,
            p: 1,
            output_len: 32,
        }
    }
}

/// Builder for scrypt parameters.
///
/// Provides a fluent API for configuring scrypt with named parameters.
///
/// # Example
///
/// ```rust
/// use arcanum_hash::ScryptParams;
///
/// // Using the builder pattern
/// let params = ScryptParams::builder()
///     .log_n(16)           // N = 2^16 = 65536 iterations
///     .block_size(8)       // r = 8 (block size)
///     .parallelism(2)      // p = 2 (parallel threads)
///     .output_len(32)      // 32-byte output
///     .build();
///
/// // Memory usage: N * r * 128 bytes = 65536 * 8 * 128 = 64 MiB
/// ```
#[derive(Debug, Clone)]
pub struct ScryptParamsBuilder {
    log_n: u8,
    r: u32,
    p: u32,
    output_len: usize,
}

impl Default for ScryptParamsBuilder {
    fn default() -> Self {
        // Start with moderate defaults
        Self {
            log_n: 15,      // N = 2^15 = 32768
            r: 8,           // Block size
            p: 1,           // Parallelism
            output_len: 32, // 256-bit output
        }
    }
}

impl ScryptParamsBuilder {
    /// Set the log2 of the CPU/memory cost parameter (N = 2^log_n).
    ///
    /// Higher values increase memory usage exponentially.
    /// Memory usage: N * r * 128 bytes
    ///
    /// Recommended minimum: 14 (16 MiB with r=8)
    pub fn log_n(mut self, log_n: u8) -> Self {
        self.log_n = log_n;
        self
    }

    /// Set N directly (will be converted to log_n).
    ///
    /// N must be a power of 2. If not, it will be rounded down to the nearest power of 2.
    ///
    /// # Example
    ///
    /// ```rust
    /// use arcanum_hash::ScryptParams;
    ///
    /// let params = ScryptParams::builder()
    ///     .n(32768)  // Same as log_n(15)
    ///     .build();
    /// ```
    pub fn n(mut self, n: u32) -> Self {
        // Calculate log2(n)
        self.log_n = (32 - n.leading_zeros() - 1) as u8;
        self
    }

    /// Set the block size parameter (r).
    ///
    /// Larger values increase memory usage linearly.
    /// Memory usage: N * r * 128 bytes
    ///
    /// Recommended: 8
    pub fn block_size(mut self, r: u32) -> Self {
        self.r = r;
        self
    }

    /// Alias for `block_size()`.
    pub fn r(mut self, r: u32) -> Self {
        self.r = r;
        self
    }

    /// Set the parallelization parameter (p).
    ///
    /// Higher values allow more parallel computation.
    /// Note: scrypt parallelism is different from Argon2 parallelism.
    ///
    /// Recommended: 1 for most cases
    pub fn parallelism(mut self, p: u32) -> Self {
        self.p = p;
        self
    }

    /// Alias for `parallelism()`.
    pub fn p(mut self, p: u32) -> Self {
        self.p = p;
        self
    }

    /// Set output length in bytes.
    ///
    /// Default: 32 (256 bits). Common values: 16, 32, 64
    pub fn output_len(mut self, len: usize) -> Self {
        self.output_len = len;
        self
    }

    /// Configure for a target memory usage (approximately).
    ///
    /// This sets log_n based on the target memory size in MiB.
    /// Actual memory usage: 2^log_n * r * 128 bytes
    ///
    /// # Example
    ///
    /// ```rust
    /// use arcanum_hash::ScryptParams;
    ///
    /// let params = ScryptParams::builder()
    ///     .memory_mib(64)  // ~64 MiB memory usage
    ///     .build();
    /// ```
    pub fn memory_mib(mut self, mib: u32) -> Self {
        // Memory = 2^log_n * r * 128 bytes
        // mib * 1024 * 1024 = 2^log_n * r * 128
        // 2^log_n = mib * 1024 * 1024 / (r * 128)
        // 2^log_n = mib * 8192 / r
        let n = (mib as u64 * 8192) / self.r as u64;
        self.log_n = (64 - n.leading_zeros() - 1) as u8;
        self
    }

    /// Build the parameters.
    pub fn build(self) -> ScryptParams {
        ScryptParams {
            log_n: self.log_n,
            r: self.r,
            p: self.p,
            output_len: self.output_len,
        }
    }
}

/// scrypt password hashing.
pub struct Scrypt;

impl PasswordHash for Scrypt {
    type Params = ScryptParams;
    const ALGORITHM: &'static str = "scrypt";

    fn hash_password(password: &[u8], params: &Self::Params) -> Result<String> {
        let salt = SaltString::generate(&mut OsRng);

        let scrypt_params = Params::new(params.log_n, params.r, params.p, params.output_len)
            .map_err(|e| Error::InternalError(e.to_string()))?;

        let hash = ScryptInner
            .hash_password_customized(password, None, None, scrypt_params, &salt)
            .map_err(|e| Error::InternalError(e.to_string()))?;

        Ok(hash.to_string())
    }

    fn verify_password(password: &[u8], hash: &str) -> Result<bool> {
        let parsed_hash = scrypt::password_hash::PasswordHash::new(hash)
            .map_err(|e| Error::ParseError(e.to_string()))?;

        Ok(ScryptInner.verify_password(password, &parsed_hash).is_ok())
    }

    fn derive_key(
        password: &[u8],
        salt: &[u8],
        params: &Self::Params,
        output_len: usize,
    ) -> Result<Vec<u8>> {
        let scrypt_params = Params::new(params.log_n, params.r, params.p, output_len)
            .map_err(|e| Error::InternalError(e.to_string()))?;

        let mut output = vec![0u8; output_len];
        scrypt::scrypt(password, salt, &scrypt_params, &mut output)
            .map_err(|_| Error::KeyDerivationFailed)?;

        Ok(output)
    }
}

impl Scrypt {
    /// Hash a password with default (moderate) parameters.
    pub fn hash(password: &[u8]) -> Result<String> {
        Self::hash_password(password, &ScryptParams::default())
    }

    /// Verify a password against a hash.
    pub fn verify(password: &[u8], hash: &str) -> Result<bool> {
        Self::verify_password(password, hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_verify() {
        let password = b"correct horse battery staple";
        let hash = Scrypt::hash_password(password, &ScryptParams::low()).unwrap();

        assert!(Scrypt::verify_password(password, &hash).unwrap());
        assert!(!Scrypt::verify_password(b"wrong password", &hash).unwrap());
    }

    #[test]
    fn test_derive_key() {
        let password = b"password";
        let salt = b"somesalt12345678";

        let key1 = Scrypt::derive_key(password, salt, &ScryptParams::low(), 32).unwrap();
        let key2 = Scrypt::derive_key(password, salt, &ScryptParams::low(), 32).unwrap();

        assert_eq!(key1, key2);
        assert_eq!(key1.len(), 32);
    }

    #[test]
    fn test_hash_format() {
        let password = b"test";
        let hash = Scrypt::hash_password(password, &ScryptParams::low()).unwrap();

        assert!(hash.starts_with("$scrypt$"));
    }

    #[test]
    fn test_params_display() {
        let params = ScryptParams::moderate();
        let display = params.to_string();
        assert!(display.contains("scrypt"));
        assert!(display.contains("N=2^15"));
        assert!(display.contains("r=8"));
        assert!(display.contains("p=1"));
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // BUILDER PATTERN TESTS
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_builder_defaults() {
        let params = ScryptParams::builder().build();

        // Should match moderate defaults
        assert_eq!(params.log_n, 15);
        assert_eq!(params.r, 8);
        assert_eq!(params.p, 1);
        assert_eq!(params.output_len, 32);
    }

    #[test]
    fn test_builder_log_n() {
        let params = ScryptParams::builder()
            .log_n(17)
            .build();

        assert_eq!(params.log_n, 17);
    }

    #[test]
    fn test_builder_n_direct() {
        let params = ScryptParams::builder()
            .n(32768)  // 2^15
            .build();

        assert_eq!(params.log_n, 15);
    }

    #[test]
    fn test_builder_block_size() {
        let params = ScryptParams::builder()
            .block_size(16)
            .build();

        assert_eq!(params.r, 16);
    }

    #[test]
    fn test_builder_parallelism() {
        let params = ScryptParams::builder()
            .parallelism(4)
            .build();

        assert_eq!(params.p, 4);
    }

    #[test]
    fn test_builder_full_config() {
        let params = ScryptParams::builder()
            .log_n(16)
            .block_size(8)
            .parallelism(2)
            .output_len(64)
            .build();

        assert_eq!(params.log_n, 16);
        assert_eq!(params.r, 8);
        assert_eq!(params.p, 2);
        assert_eq!(params.output_len, 64);
    }

    #[test]
    fn test_builder_memory_mib() {
        // 32 MiB with r=8: 32 * 8192 / 8 = 32768 = 2^15
        let params = ScryptParams::builder()
            .memory_mib(32)
            .build();

        assert_eq!(params.log_n, 15);
    }

    #[test]
    fn test_builder_produces_valid_hash() {
        let params = ScryptParams::builder()
            .log_n(12)
            .block_size(8)
            .parallelism(1)
            .build();

        let password = b"test password";
        let hash = Scrypt::hash_password(password, &params).unwrap();

        assert!(Scrypt::verify_password(password, &hash).unwrap());
    }

    #[test]
    fn test_builder_aliases() {
        let params1 = ScryptParams::builder()
            .r(8)
            .p(2)
            .build();

        let params2 = ScryptParams::builder()
            .block_size(8)
            .parallelism(2)
            .build();

        assert_eq!(params1.r, params2.r);
        assert_eq!(params1.p, params2.p);
    }
}
