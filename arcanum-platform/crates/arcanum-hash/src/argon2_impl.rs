//! Argon2 password hashing.
//!
//! Argon2 is the winner of the Password Hashing Competition (PHC) and the
//! recommended algorithm for password hashing. It provides:
//!
//! - **Memory-hardness**: Resistant to GPU/ASIC attacks
//! - **Time-hardness**: Configurable computation time
//! - **Parallelism**: Can utilize multiple cores
//!
//! We use **Argon2id** which combines Argon2i and Argon2d for best security.

use crate::traits::PasswordHash;
use arcanum_core::error::{Error, Result};
use argon2::{
    password_hash::{PasswordHasher, PasswordVerifier, SaltString},
    Algorithm, Argon2 as Argon2Inner, Params, Version,
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

/// Argon2id parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Argon2Params {
    /// Memory cost in KiB (default: 64 MiB)
    pub memory_cost: u32,
    /// Time cost (iterations) (default: 3)
    pub time_cost: u32,
    /// Parallelism (lanes) (default: 4)
    pub parallelism: u32,
    /// Output length in bytes (default: 32)
    pub output_len: usize,
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self::moderate()
    }
}

impl std::fmt::Display for Argon2Params {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let memory_mib = self.memory_cost / 1024;
        write!(
            f,
            "Argon2id(m={}MiB, t={}, p={})",
            memory_mib, self.time_cost, self.parallelism
        )
    }
}

impl Argon2Params {
    /// Create custom parameters.
    pub fn new(memory_cost: u32, time_cost: u32, parallelism: u32) -> Self {
        Self {
            memory_cost,
            time_cost,
            parallelism,
            output_len: 32,
        }
    }

    /// Create a builder for custom parameters.
    ///
    /// # Example
    ///
    /// ```rust
    /// use arcanum_hash::Argon2Params;
    ///
    /// let params = Argon2Params::builder()
    ///     .memory_mib(64)      // 64 MiB
    ///     .iterations(3)
    ///     .parallelism(4)
    ///     .build();
    /// ```
    pub fn builder() -> Argon2ParamsBuilder {
        Argon2ParamsBuilder::default()
    }

    /// Low security parameters (for testing or low-security contexts).
    ///
    /// Memory: 16 MiB, Time: 2, Parallelism: 1
    pub fn low() -> Self {
        Self {
            memory_cost: 16 * 1024,
            time_cost: 2,
            parallelism: 1,
            output_len: 32,
        }
    }

    /// Moderate security parameters (good balance).
    ///
    /// Memory: 64 MiB, Time: 3, Parallelism: 4
    pub fn moderate() -> Self {
        Self {
            memory_cost: 64 * 1024,
            time_cost: 3,
            parallelism: 4,
            output_len: 32,
        }
    }

    /// High security parameters (for sensitive data).
    ///
    /// Memory: 256 MiB, Time: 4, Parallelism: 4
    pub fn high() -> Self {
        Self {
            memory_cost: 256 * 1024,
            time_cost: 4,
            parallelism: 4,
            output_len: 32,
        }
    }

    /// Maximum security parameters (for extremely sensitive data).
    ///
    /// Memory: 1 GiB, Time: 6, Parallelism: 4
    pub fn maximum() -> Self {
        Self {
            memory_cost: 1024 * 1024,
            time_cost: 6,
            parallelism: 4,
            output_len: 32,
        }
    }

    /// OWASP recommended parameters (2024).
    ///
    /// Memory: 19 MiB, Time: 2, Parallelism: 1
    pub fn owasp() -> Self {
        Self {
            memory_cost: 19 * 1024,
            time_cost: 2,
            parallelism: 1,
            output_len: 32,
        }
    }
}

/// Builder for Argon2 parameters.
///
/// Provides a fluent API for configuring Argon2 with named parameters.
///
/// # Example
///
/// ```rust
/// use arcanum_hash::Argon2Params;
///
/// // Using convenient MiB/GiB helpers
/// let params = Argon2Params::builder()
///     .memory_mib(128)     // 128 MiB
///     .iterations(4)
///     .parallelism(4)
///     .output_len(32)
///     .build();
///
/// // Or using raw KiB values
/// let params = Argon2Params::builder()
///     .memory_kib(131072)  // 128 MiB in KiB
///     .iterations(4)
///     .build();
/// ```
#[derive(Debug, Clone)]
pub struct Argon2ParamsBuilder {
    memory_cost: u32,
    time_cost: u32,
    parallelism: u32,
    output_len: usize,
}

impl Default for Argon2ParamsBuilder {
    fn default() -> Self {
        // Start with moderate defaults
        Self {
            memory_cost: 64 * 1024,  // 64 MiB
            time_cost: 3,
            parallelism: 4,
            output_len: 32,
        }
    }
}

impl Argon2ParamsBuilder {
    /// Set memory cost in KiB.
    ///
    /// Minimum: 8 KiB (8 * 1024 bytes)
    pub fn memory_kib(mut self, kib: u32) -> Self {
        self.memory_cost = kib;
        self
    }

    /// Set memory cost in MiB (convenience method).
    ///
    /// Example: `memory_mib(64)` = 64 MiB = 65536 KiB
    pub fn memory_mib(mut self, mib: u32) -> Self {
        self.memory_cost = mib * 1024;
        self
    }

    /// Set memory cost in GiB (convenience method).
    ///
    /// Example: `memory_gib(1)` = 1 GiB = 1048576 KiB
    pub fn memory_gib(mut self, gib: u32) -> Self {
        self.memory_cost = gib * 1024 * 1024;
        self
    }

    /// Set time cost (number of iterations).
    ///
    /// Higher = slower but more secure. Minimum: 1, recommended: 3+
    pub fn iterations(mut self, iterations: u32) -> Self {
        self.time_cost = iterations;
        self
    }

    /// Alias for `iterations()`.
    pub fn time_cost(mut self, time_cost: u32) -> Self {
        self.time_cost = time_cost;
        self
    }

    /// Set parallelism (number of lanes).
    ///
    /// Should match available CPU cores. Minimum: 1
    pub fn parallelism(mut self, parallelism: u32) -> Self {
        self.parallelism = parallelism;
        self
    }

    /// Alias for `parallelism()`.
    pub fn lanes(mut self, lanes: u32) -> Self {
        self.parallelism = lanes;
        self
    }

    /// Set output length in bytes.
    ///
    /// Default: 32 (256 bits). Common values: 16, 32, 64
    pub fn output_len(mut self, len: usize) -> Self {
        self.output_len = len;
        self
    }

    /// Build the parameters.
    pub fn build(self) -> Argon2Params {
        Argon2Params {
            memory_cost: self.memory_cost,
            time_cost: self.time_cost,
            parallelism: self.parallelism,
            output_len: self.output_len,
        }
    }
}

/// Argon2id password hashing.
///
/// # Example
///
/// ```rust,no_run
/// use arcanum_hash::prelude::*;
///
/// // Hash a password with default (moderate) parameters
/// let hash = Argon2::hash_password(b"my_password", &Argon2Params::default())?;
///
/// // Verify a password
/// let is_valid = Argon2::verify_password(b"my_password", &hash)?;
/// assert!(is_valid);
///
/// // Use custom parameters
/// let params = Argon2Params::builder()
///     .memory_mib(128)
///     .iterations(4)
///     .parallelism(8)
///     .build();
/// let hash = Argon2::hash_password(b"strong_password", &params)?;
/// # Ok::<(), arcanum_core::error::Error>(())
/// ```
pub struct Argon2;

impl PasswordHash for Argon2 {
    type Params = Argon2Params;
    const ALGORITHM: &'static str = "Argon2id";

    fn hash_password(password: &[u8], params: &Self::Params) -> Result<String> {
        let salt = SaltString::generate(&mut OsRng);

        let argon2_params = Params::new(
            params.memory_cost,
            params.time_cost,
            params.parallelism,
            Some(params.output_len),
        )
        .map_err(|e| Error::InternalError(e.to_string()))?;

        let argon2 = Argon2Inner::new(Algorithm::Argon2id, Version::V0x13, argon2_params);

        let hash = argon2
            .hash_password(password, &salt)
            .map_err(|e| Error::InternalError(e.to_string()))?;

        Ok(hash.to_string())
    }

    fn verify_password(password: &[u8], hash: &str) -> Result<bool> {
        let parsed_hash = argon2::PasswordHash::new(hash)
            .map_err(|e| Error::ParseError(e.to_string()))?;

        let argon2 = Argon2Inner::default();

        Ok(argon2.verify_password(password, &parsed_hash).is_ok())
    }

    fn derive_key(
        password: &[u8],
        salt: &[u8],
        params: &Self::Params,
        output_len: usize,
    ) -> Result<Vec<u8>> {
        let argon2_params = Params::new(
            params.memory_cost,
            params.time_cost,
            params.parallelism,
            Some(output_len),
        )
        .map_err(|e| Error::InternalError(e.to_string()))?;

        let argon2 = Argon2Inner::new(Algorithm::Argon2id, Version::V0x13, argon2_params);

        let mut output = vec![0u8; output_len];
        argon2
            .hash_password_into(password, salt, &mut output)
            .map_err(|_| Error::KeyDerivationFailed)?;

        Ok(output)
    }
}

impl Argon2 {
    /// Hash a password with default (moderate) parameters.
    pub fn hash(password: &[u8]) -> Result<String> {
        Self::hash_password(password, &Argon2Params::default())
    }

    /// Verify a password against a hash.
    pub fn verify(password: &[u8], hash: &str) -> Result<bool> {
        Self::verify_password(password, hash)
    }

    /// Derive a 256-bit key from a password.
    pub fn derive_key_256(password: &[u8], salt: &[u8]) -> Result<[u8; 32]> {
        let key = Self::derive_key(password, salt, &Argon2Params::default(), 32)?;
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&key);
        Ok(arr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_verify() {
        let password = b"correct horse battery staple";
        let hash = Argon2::hash_password(password, &Argon2Params::low()).unwrap();

        // Correct password should verify
        assert!(Argon2::verify_password(password, &hash).unwrap());

        // Wrong password should fail
        assert!(!Argon2::verify_password(b"wrong password", &hash).unwrap());
    }

    #[test]
    fn test_hash_format() {
        let password = b"test";
        let hash = Argon2::hash_password(password, &Argon2Params::low()).unwrap();

        // Should be in PHC string format
        assert!(hash.starts_with("$argon2id$"));
    }

    #[test]
    fn test_derive_key() {
        let password = b"password";
        let salt = b"somesalt12345678"; // 16 bytes minimum

        let key1 = Argon2::derive_key(password, salt, &Argon2Params::low(), 32).unwrap();
        let key2 = Argon2::derive_key(password, salt, &Argon2Params::low(), 32).unwrap();

        // Same inputs should produce same output
        assert_eq!(key1, key2);
        assert_eq!(key1.len(), 32);

        // Different password should produce different key
        let key3 = Argon2::derive_key(b"different", salt, &Argon2Params::low(), 32).unwrap();
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_different_salts() {
        let password = b"password";
        let hash1 = Argon2::hash_password(password, &Argon2Params::low()).unwrap();
        let hash2 = Argon2::hash_password(password, &Argon2Params::low()).unwrap();

        // Different salts should produce different hashes
        assert_ne!(hash1, hash2);

        // Both should still verify
        assert!(Argon2::verify_password(password, &hash1).unwrap());
        assert!(Argon2::verify_password(password, &hash2).unwrap());
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // BUILDER PATTERN TESTS
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_builder_defaults() {
        let params = Argon2Params::builder().build();

        // Should match moderate defaults
        assert_eq!(params.memory_cost, 64 * 1024);
        assert_eq!(params.time_cost, 3);
        assert_eq!(params.parallelism, 4);
        assert_eq!(params.output_len, 32);
    }

    #[test]
    fn test_builder_memory_mib() {
        let params = Argon2Params::builder()
            .memory_mib(128)
            .build();

        assert_eq!(params.memory_cost, 128 * 1024);
    }

    #[test]
    fn test_builder_memory_gib() {
        let params = Argon2Params::builder()
            .memory_gib(1)
            .build();

        assert_eq!(params.memory_cost, 1024 * 1024);
    }

    #[test]
    fn test_builder_full_config() {
        let params = Argon2Params::builder()
            .memory_mib(256)
            .iterations(5)
            .parallelism(8)
            .output_len(64)
            .build();

        assert_eq!(params.memory_cost, 256 * 1024);
        assert_eq!(params.time_cost, 5);
        assert_eq!(params.parallelism, 8);
        assert_eq!(params.output_len, 64);
    }

    #[test]
    fn test_builder_produces_valid_hash() {
        let params = Argon2Params::builder()
            .memory_mib(16)
            .iterations(2)
            .parallelism(1)
            .build();

        let password = b"test password";
        let hash = Argon2::hash_password(password, &params).unwrap();

        assert!(Argon2::verify_password(password, &hash).unwrap());
    }

    #[test]
    fn test_params_display() {
        let params = Argon2Params::moderate();
        let display = params.to_string();
        assert!(display.contains("Argon2id"));
        assert!(display.contains("64MiB"));
        assert!(display.contains("t=3"));
        assert!(display.contains("p=4"));
    }
}
