//! Traits for symmetric encryption algorithms.

use arcanum_core::error::{Error, Result};
use std::sync::atomic::{AtomicU64, Ordering};

// ═══════════════════════════════════════════════════════════════════════════════
// NONCE STRATEGY
// ═══════════════════════════════════════════════════════════════════════════════

/// Strategy for nonce generation in AEAD ciphers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NonceStrategy {
    /// Generate a random nonce for each encryption (recommended for most cases).
    #[default]
    Random,
    /// Use a counter-based nonce (useful for high-performance scenarios).
    /// The counter starts at 0 and increments for each encryption.
    Counter,
    /// Use a counter starting at a specific value.
    CounterFrom(u64),
}

impl std::fmt::Display for NonceStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NonceStrategy::Random => write!(f, "random"),
            NonceStrategy::Counter => write!(f, "counter(0)"),
            NonceStrategy::CounterFrom(n) => write!(f, "counter({})", n),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// CIPHER BUILDER
// ═══════════════════════════════════════════════════════════════════════════════

/// Builder for configuring AEAD cipher instances.
///
/// # Example
///
/// ```rust,no_run
/// use arcanum_symmetric::prelude::*;
///
/// let key = Aes256Gcm::generate_key();
/// let cipher = CipherBuilder::<Aes256Gcm>::new()
///     .key(&key)
///     .nonce_strategy(NonceStrategy::Random)
///     .build()?;
///
/// let ciphertext = cipher.encrypt(b"secret message")?;
/// let plaintext = cipher.decrypt(&ciphertext)?;
/// # Ok::<(), arcanum_core::error::Error>(())
/// ```
#[derive(Debug)]
pub struct CipherBuilder<C: Cipher> {
    key: Option<Vec<u8>>,
    nonce_strategy: NonceStrategy,
    _marker: std::marker::PhantomData<C>,
}

impl<C: Cipher> Default for CipherBuilder<C> {
    fn default() -> Self {
        Self::new()
    }
}

impl<C: Cipher> CipherBuilder<C> {
    /// Create a new cipher builder.
    pub fn new() -> Self {
        Self {
            key: None,
            nonce_strategy: NonceStrategy::Random,
            _marker: std::marker::PhantomData,
        }
    }

    /// Set the encryption key.
    pub fn key(mut self, key: &[u8]) -> Self {
        self.key = Some(key.to_vec());
        self
    }

    /// Set the nonce generation strategy.
    pub fn nonce_strategy(mut self, strategy: NonceStrategy) -> Self {
        self.nonce_strategy = strategy;
        self
    }

    /// Build the cipher instance.
    ///
    /// Returns an error if the key is not set or has invalid length.
    pub fn build(self) -> Result<CipherInstance<C>> {
        let key = self.key.ok_or_else(|| Error::InvalidParameterContext {
            name: "key".to_string(),
            reason: "key is required".to_string(),
        })?;

        if key.len() != C::KEY_SIZE {
            return Err(Error::InvalidKeyLength {
                expected: C::KEY_SIZE,
                actual: key.len(),
            });
        }

        let counter = match self.nonce_strategy {
            NonceStrategy::Counter => AtomicU64::new(0),
            NonceStrategy::CounterFrom(n) => AtomicU64::new(n),
            NonceStrategy::Random => AtomicU64::new(0), // Not used
        };

        Ok(CipherInstance {
            key,
            nonce_strategy: self.nonce_strategy,
            counter,
            _marker: std::marker::PhantomData,
        })
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// CIPHER INSTANCE
// ═══════════════════════════════════════════════════════════════════════════════

/// A configured AEAD cipher instance ready for encryption/decryption.
///
/// This struct holds the key and manages nonce generation based on the
/// configured strategy.
///
/// # Thread Safety
///
/// `CipherInstance` is thread-safe when using counter-based nonces.
/// The counter is atomically incremented for each encryption.
pub struct CipherInstance<C: Cipher> {
    key: Vec<u8>,
    nonce_strategy: NonceStrategy,
    counter: AtomicU64,
    _marker: std::marker::PhantomData<C>,
}

impl<C: Cipher> std::fmt::Debug for CipherInstance<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CipherInstance")
            .field("algorithm", &C::ALGORITHM)
            .field("key", &"[REDACTED]")
            .field("nonce_strategy", &self.nonce_strategy)
            .finish()
    }
}

impl<C: Cipher> CipherInstance<C> {
    /// Create a new cipher instance with a random nonce strategy.
    ///
    /// This is a shorthand for using the builder.
    pub fn new(key: &[u8]) -> Result<Self> {
        CipherBuilder::<C>::new().key(key).build()
    }

    /// Create a builder for this cipher type.
    pub fn builder() -> CipherBuilder<C> {
        CipherBuilder::new()
    }

    /// Get the algorithm name.
    pub fn algorithm(&self) -> &'static str {
        C::ALGORITHM
    }

    /// Get the current nonce strategy.
    pub fn nonce_strategy(&self) -> NonceStrategy {
        self.nonce_strategy
    }

    /// Generate a nonce based on the configured strategy.
    fn next_nonce(&self) -> Vec<u8> {
        match self.nonce_strategy {
            NonceStrategy::Random => C::generate_nonce(),
            NonceStrategy::Counter | NonceStrategy::CounterFrom(_) => {
                let count = self.counter.fetch_add(1, Ordering::SeqCst);
                let mut nonce = vec![0u8; C::NONCE_SIZE];
                // Put counter in the last 8 bytes (big-endian)
                let start = C::NONCE_SIZE.saturating_sub(8);
                nonce[start..].copy_from_slice(&count.to_be_bytes()[..C::NONCE_SIZE.min(8)]);
                nonce
            }
        }
    }

    /// Encrypt plaintext, returning sealed data with embedded nonce.
    ///
    /// The returned data format is: `[nonce || ciphertext || tag]`
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let nonce = self.next_nonce();
        let ciphertext = C::encrypt(&self.key, &nonce, plaintext, None)?;

        let mut sealed = Vec::with_capacity(C::NONCE_SIZE + ciphertext.len());
        sealed.extend_from_slice(&nonce);
        sealed.extend_from_slice(&ciphertext);
        Ok(sealed)
    }

    /// Encrypt plaintext with associated data.
    pub fn encrypt_with_aad(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let nonce = self.next_nonce();
        let ciphertext = C::encrypt(&self.key, &nonce, plaintext, Some(aad))?;

        let mut sealed = Vec::with_capacity(C::NONCE_SIZE + ciphertext.len());
        sealed.extend_from_slice(&nonce);
        sealed.extend_from_slice(&ciphertext);
        Ok(sealed)
    }

    /// Decrypt sealed data (with embedded nonce).
    pub fn decrypt(&self, sealed: &[u8]) -> Result<Vec<u8>> {
        if sealed.len() < C::NONCE_SIZE + C::TAG_SIZE {
            return Err(Error::CiphertextTooShort {
                minimum: C::NONCE_SIZE + C::TAG_SIZE,
            });
        }

        let (nonce, ciphertext) = sealed.split_at(C::NONCE_SIZE);
        C::decrypt(&self.key, nonce, ciphertext, None)
    }

    /// Decrypt sealed data with associated data verification.
    pub fn decrypt_with_aad(&self, sealed: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        if sealed.len() < C::NONCE_SIZE + C::TAG_SIZE {
            return Err(Error::CiphertextTooShort {
                minimum: C::NONCE_SIZE + C::TAG_SIZE,
            });
        }

        let (nonce, ciphertext) = sealed.split_at(C::NONCE_SIZE);
        C::decrypt(&self.key, nonce, ciphertext, Some(aad))
    }

    /// Encrypt with explicit nonce (advanced use).
    ///
    /// # Warning
    ///
    /// You are responsible for ensuring nonce uniqueness.
    /// Reusing a nonce with the same key is a critical security vulnerability.
    pub fn encrypt_with_nonce(&self, plaintext: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
        C::encrypt(&self.key, nonce, plaintext, None)
    }

    /// Decrypt with explicit nonce (advanced use).
    pub fn decrypt_with_nonce(&self, ciphertext: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
        C::decrypt(&self.key, nonce, ciphertext, None)
    }
}

// Implement Drop to zeroize the key
impl<C: Cipher> Drop for CipherInstance<C> {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.key.zeroize();
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// CIPHER TRAIT
// ═══════════════════════════════════════════════════════════════════════════════

/// Trait for AEAD (Authenticated Encryption with Associated Data) ciphers.
///
/// # Example
///
/// ```rust,no_run
/// use arcanum_symmetric::prelude::*;
///
/// // Generate a random key
/// let key = Aes256Gcm::generate_key();
/// let nonce = Aes256Gcm::generate_nonce();
///
/// // Encrypt with explicit nonce (advanced)
/// let ciphertext = Aes256Gcm::encrypt(&key, &nonce, b"secret", None)?;
/// let plaintext = Aes256Gcm::decrypt(&key, &nonce, &ciphertext, None)?;
///
/// // Or use the simpler seal/open API (recommended)
/// let sealed = Aes256Gcm::seal(&key, b"secret")?;
/// let opened = Aes256Gcm::open(&key, &sealed)?;
/// # Ok::<(), arcanum_core::error::Error>(())
/// ```
pub trait Cipher {
    /// Key size in bytes.
    const KEY_SIZE: usize;
    /// Nonce size in bytes.
    const NONCE_SIZE: usize;
    /// Authentication tag size in bytes.
    const TAG_SIZE: usize;
    /// Algorithm identifier.
    const ALGORITHM: &'static str;

    /// Generate a random key.
    fn generate_key() -> Vec<u8>;

    /// Generate a random nonce.
    fn generate_nonce() -> Vec<u8>;

    /// Encrypt plaintext with optional associated data.
    ///
    /// Returns ciphertext with authentication tag appended.
    fn encrypt(
        key: &[u8],
        nonce: &[u8],
        plaintext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>>;

    /// Decrypt ciphertext with optional associated data.
    ///
    /// Returns plaintext if authentication succeeds.
    fn decrypt(
        key: &[u8],
        nonce: &[u8],
        ciphertext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>>;

    /// Encrypt in place (for zero-copy scenarios).
    fn encrypt_in_place(
        key: &[u8],
        nonce: &[u8],
        associated_data: &[u8],
        buffer: &mut Vec<u8>,
    ) -> Result<()>;

    /// Decrypt in place (for zero-copy scenarios).
    fn decrypt_in_place(
        key: &[u8],
        nonce: &[u8],
        associated_data: &[u8],
        buffer: &mut Vec<u8>,
    ) -> Result<()>;

    // ═══════════════════════════════════════════════════════════════════════════
    // CONVENIENCE METHODS
    // ═══════════════════════════════════════════════════════════════════════════

    /// Seal plaintext with automatic nonce generation.
    ///
    /// This is the recommended API for most use cases. It:
    /// - Generates a random nonce automatically
    /// - Prepends the nonce to the ciphertext
    /// - Returns a single blob that can be stored/transmitted
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use arcanum_symmetric::prelude::*;
    ///
    /// let key = Aes256Gcm::generate_key();
    /// let sealed = Aes256Gcm::seal(&key, b"secret message")?;
    /// let opened = Aes256Gcm::open(&key, &sealed)?;
    /// # Ok::<(), arcanum_core::error::Error>(())
    /// ```
    fn seal(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        let nonce = Self::generate_nonce();
        let ciphertext = Self::encrypt(key, &nonce, plaintext, None)?;

        // Prepend nonce to ciphertext: [nonce || ciphertext]
        let mut sealed = Vec::with_capacity(Self::NONCE_SIZE + ciphertext.len());
        sealed.extend_from_slice(&nonce);
        sealed.extend_from_slice(&ciphertext);
        Ok(sealed)
    }

    /// Seal plaintext with associated data.
    ///
    /// Like `seal()`, but includes additional authenticated data (AAD).
    /// The AAD is authenticated but not encrypted - it must be provided
    /// again during `open_with_aad()`.
    fn seal_with_aad(key: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let nonce = Self::generate_nonce();
        let ciphertext = Self::encrypt(key, &nonce, plaintext, Some(aad))?;

        let mut sealed = Vec::with_capacity(Self::NONCE_SIZE + ciphertext.len());
        sealed.extend_from_slice(&nonce);
        sealed.extend_from_slice(&ciphertext);
        Ok(sealed)
    }

    /// Open sealed data (decrypt with embedded nonce).
    ///
    /// Extracts the nonce from the sealed data and decrypts.
    fn open(key: &[u8], sealed: &[u8]) -> Result<Vec<u8>> {
        if sealed.len() < Self::NONCE_SIZE + Self::TAG_SIZE {
            return Err(arcanum_core::error::Error::CiphertextTooShort {
                minimum: Self::NONCE_SIZE + Self::TAG_SIZE,
            });
        }

        let (nonce, ciphertext) = sealed.split_at(Self::NONCE_SIZE);
        Self::decrypt(key, nonce, ciphertext, None)
    }

    /// Open sealed data with associated data verification.
    fn open_with_aad(key: &[u8], sealed: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        if sealed.len() < Self::NONCE_SIZE + Self::TAG_SIZE {
            return Err(arcanum_core::error::Error::CiphertextTooShort {
                minimum: Self::NONCE_SIZE + Self::TAG_SIZE,
            });
        }

        let (nonce, ciphertext) = sealed.split_at(Self::NONCE_SIZE);
        Self::decrypt(key, nonce, ciphertext, Some(aad))
    }
}

/// Trait for stream ciphers.
pub trait StreamCipher {
    /// Key size in bytes.
    const KEY_SIZE: usize;
    /// Nonce size in bytes.
    const NONCE_SIZE: usize;
    /// Algorithm identifier.
    const ALGORITHM: &'static str;

    /// Create a new stream cipher instance.
    fn new(key: &[u8], nonce: &[u8]) -> Result<Self>
    where
        Self: Sized;

    /// Apply keystream to data (XOR operation).
    ///
    /// This is symmetric - the same operation encrypts and decrypts.
    fn apply_keystream(&mut self, data: &mut [u8]);

    /// Generate keystream bytes.
    fn keystream(&mut self, len: usize) -> Vec<u8> {
        let mut buf = vec![0u8; len];
        self.apply_keystream(&mut buf);
        buf
    }

    /// Seek to a position in the keystream (if supported).
    fn seek(&mut self, position: u64) -> Result<()>;

    /// Get current position in the keystream.
    fn position(&self) -> u64;
}
