//! Type-safe wrappers for cryptographic data.
//!
//! These types prevent accidentally mixing plaintext and ciphertext,
//! and provide convenient methods for common operations.

use arcanum_core::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::fmt;
use subtle::ConstantTimeEq;
use zeroize::ZeroizeOnDrop;

// ═══════════════════════════════════════════════════════════════════════════════
// PLAINTEXT
// ═══════════════════════════════════════════════════════════════════════════════

/// Type-safe wrapper for plaintext data.
///
/// Automatically zeroizes on drop to prevent sensitive data from lingering in memory.
///
/// # Example
///
/// ```rust
/// use arcanum_symmetric::types::Plaintext;
///
/// let plaintext = Plaintext::new(b"secret message".to_vec());
/// assert_eq!(plaintext.as_bytes(), b"secret message");
/// ```
#[derive(Clone, ZeroizeOnDrop)]
pub struct Plaintext {
    data: Vec<u8>,
}

impl Plaintext {
    /// Create a new plaintext from bytes.
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    /// Create from a byte slice.
    pub fn from_slice(data: &[u8]) -> Self {
        Self {
            data: data.to_vec(),
        }
    }

    /// Create from a string.
    pub fn from_string(s: &str) -> Self {
        Self {
            data: s.as_bytes().to_vec(),
        }
    }

    /// Access the plaintext bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Get the length in bytes.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Convert to a String (if valid UTF-8).
    pub fn to_string_lossy(&self) -> String {
        String::from_utf8_lossy(&self.data).into_owned()
    }

    /// Try to convert to a String.
    pub fn try_to_string(&self) -> Result<String> {
        String::from_utf8(self.data.clone())
            .map_err(|_| Error::EncodingError("invalid UTF-8 in plaintext".to_string()))
    }

    /// Consume and return the inner bytes.
    ///
    /// # Warning
    ///
    /// The returned bytes will NOT be automatically zeroized.
    /// Handle with care.
    pub fn into_bytes(mut self) -> Vec<u8> {
        std::mem::take(&mut self.data)
    }
}

impl AsRef<[u8]> for Plaintext {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl From<Vec<u8>> for Plaintext {
    fn from(data: Vec<u8>) -> Self {
        Self::new(data)
    }
}

impl From<&[u8]> for Plaintext {
    fn from(data: &[u8]) -> Self {
        Self::from_slice(data)
    }
}

impl From<&str> for Plaintext {
    fn from(s: &str) -> Self {
        Self::from_string(s)
    }
}

impl From<String> for Plaintext {
    fn from(s: String) -> Self {
        Self::new(s.into_bytes())
    }
}

impl fmt::Debug for Plaintext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Plaintext([REDACTED, {} bytes])", self.data.len())
    }
}

impl PartialEq for Plaintext {
    fn eq(&self, other: &Self) -> bool {
        // Constant-time comparison for security
        if self.data.len() != other.data.len() {
            return false;
        }
        self.data.as_slice().ct_eq(other.data.as_slice()).into()
    }
}

impl Eq for Plaintext {}

// ═══════════════════════════════════════════════════════════════════════════════
// CIPHERTEXT
// ═══════════════════════════════════════════════════════════════════════════════

/// Type-safe wrapper for ciphertext data.
///
/// Prevents accidentally treating ciphertext as plaintext or vice versa.
///
/// # Example
///
/// ```rust
/// use arcanum_symmetric::types::Ciphertext;
///
/// let ciphertext = Ciphertext::new(vec![0x01, 0x02, 0x03, 0x04]);
/// assert_eq!(ciphertext.len(), 4);
/// ```
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ciphertext {
    data: Vec<u8>,
}

impl Ciphertext {
    /// Create a new ciphertext from bytes.
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    /// Create from a byte slice.
    pub fn from_slice(data: &[u8]) -> Self {
        Self {
            data: data.to_vec(),
        }
    }

    /// Access the ciphertext bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Get the length in bytes.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Encode as hex string.
    pub fn to_hex(&self) -> String {
        hex::encode(&self.data)
    }

    /// Decode from hex string.
    pub fn from_hex(hex_str: &str) -> Result<Self> {
        let data = hex::decode(hex_str)
            .map_err(|_| Error::InvalidCiphertext)?;
        Ok(Self { data })
    }

    /// Encode as base64 string.
    pub fn to_base64(&self) -> String {
        use base64ct::{Base64, Encoding};
        Base64::encode_string(&self.data)
    }

    /// Decode from base64 string.
    pub fn from_base64(b64_str: &str) -> Result<Self> {
        use base64ct::{Base64, Encoding};
        let data = Base64::decode_vec(b64_str)
            .map_err(|_| Error::InvalidCiphertext)?;
        Ok(Self { data })
    }

    /// Consume and return the inner bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.data
    }
}

impl AsRef<[u8]> for Ciphertext {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl From<Vec<u8>> for Ciphertext {
    fn from(data: Vec<u8>) -> Self {
        Self::new(data)
    }
}

impl From<&[u8]> for Ciphertext {
    fn from(data: &[u8]) -> Self {
        Self::from_slice(data)
    }
}

impl fmt::Debug for Ciphertext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.data.len() <= 8 {
            write!(f, "Ciphertext({})", hex::encode(&self.data))
        } else {
            write!(
                f,
                "Ciphertext({}..., {} bytes)",
                hex::encode(&self.data[..8]),
                self.data.len()
            )
        }
    }
}

impl fmt::Display for Ciphertext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// NONCE
// ═══════════════════════════════════════════════════════════════════════════════

/// Type-safe wrapper for nonces/IVs.
///
/// Const generic `N` ensures correct nonce size at compile time.
///
/// # Example
///
/// ```rust
/// use arcanum_symmetric::types::Nonce;
///
/// // 12-byte nonce for AES-GCM
/// let nonce: Nonce<12> = Nonce::random();
/// assert_eq!(nonce.as_bytes().len(), 12);
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct Nonce<const N: usize> {
    bytes: [u8; N],
}

impl<const N: usize> Nonce<N> {
    /// Create a nonce from bytes.
    pub fn new(bytes: [u8; N]) -> Self {
        Self { bytes }
    }

    /// Create from a slice.
    pub fn from_slice(slice: &[u8]) -> Result<Self> {
        if slice.len() != N {
            return Err(Error::InvalidNonceLength {
                expected: N,
                actual: slice.len(),
            });
        }
        let mut bytes = [0u8; N];
        bytes.copy_from_slice(slice);
        Ok(Self { bytes })
    }

    /// Generate a random nonce.
    pub fn random() -> Self {
        use rand::RngCore;
        let mut bytes = [0u8; N];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        Self { bytes }
    }

    /// Create a zero nonce.
    pub fn zero() -> Self {
        Self { bytes: [0u8; N] }
    }

    /// Access the nonce bytes.
    pub fn as_bytes(&self) -> &[u8; N] {
        &self.bytes
    }

    /// Encode as hex.
    pub fn to_hex(&self) -> String {
        hex::encode(self.bytes)
    }

    /// Decode from hex.
    pub fn from_hex(hex_str: &str) -> Result<Self> {
        let bytes = hex::decode(hex_str)
            .map_err(|_| Error::InvalidNonceLength { expected: N, actual: 0 })?;
        Self::from_slice(&bytes)
    }
}

impl<const N: usize> AsRef<[u8]> for Nonce<N> {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl<const N: usize> fmt::Debug for Nonce<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Nonce<{}>({})", N, hex::encode(self.bytes))
    }
}

impl<const N: usize> fmt::Display for Nonce<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.bytes))
    }
}

/// 12-byte nonce for AES-GCM.
pub type Nonce96 = Nonce<12>;

/// 24-byte nonce for XChaCha20-Poly1305.
pub type Nonce192 = Nonce<24>;

/// 16-byte nonce/IV.
pub type Nonce128 = Nonce<16>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plaintext_zeroization() {
        let plaintext = Plaintext::from_string("secret");
        assert_eq!(plaintext.as_bytes(), b"secret");
        // Zeroization happens on drop
    }

    #[test]
    fn test_plaintext_debug_redacts() {
        let plaintext = Plaintext::from_string("secret password");
        let debug = format!("{:?}", plaintext);
        assert!(!debug.contains("secret"));
        assert!(debug.contains("REDACTED"));
    }

    #[test]
    fn test_ciphertext_hex() {
        let ct = Ciphertext::new(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(ct.to_hex(), "deadbeef");

        let restored = Ciphertext::from_hex("deadbeef").unwrap();
        assert_eq!(ct, restored);
    }

    #[test]
    fn test_ciphertext_base64() {
        let ct = Ciphertext::new(vec![0x01, 0x02, 0x03, 0x04]);
        let b64 = ct.to_base64();
        let restored = Ciphertext::from_base64(&b64).unwrap();
        assert_eq!(ct, restored);
    }

    #[test]
    fn test_nonce_random() {
        let n1: Nonce96 = Nonce::random();
        let n2: Nonce96 = Nonce::random();
        assert_ne!(n1.as_bytes(), n2.as_bytes());
    }

    #[test]
    fn test_nonce_from_slice() {
        let bytes = [1u8; 12];
        let nonce = Nonce96::from_slice(&bytes).unwrap();
        assert_eq!(nonce.as_bytes(), &bytes);
    }

    #[test]
    fn test_nonce_wrong_size() {
        let bytes = [1u8; 8];
        let result = Nonce96::from_slice(&bytes);
        assert!(result.is_err());
    }
}
