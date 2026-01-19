//! Base64 encoding utilities.
//!
//! Provides standard and URL-safe Base64 encoding/decoding using
//! constant-time implementations.

use crate::error::{FormatError, Result};

/// Base64 encoding and decoding.
///
/// Uses constant-time implementations to prevent timing attacks.
///
/// # Example
///
/// ```rust
/// use arcanum_formats::Base64;
///
/// let data = b"Hello, World!";
///
/// // Standard Base64
/// let encoded = Base64::encode(data);
/// let decoded = Base64::decode(&encoded).unwrap();
/// assert_eq!(decoded, data);
///
/// // URL-safe Base64
/// let url_encoded = Base64::encode_url_safe(data);
/// let url_decoded = Base64::decode_url_safe(&url_encoded).unwrap();
/// assert_eq!(url_decoded, data);
/// ```
pub struct Base64;

impl Base64 {
    /// Encode bytes as standard Base64.
    ///
    /// Uses the standard alphabet (A-Z, a-z, 0-9, +, /) with = padding.
    pub fn encode(data: &[u8]) -> String {
        use base64ct::Encoding;
        base64ct::Base64::encode_string(data)
    }

    /// Decode standard Base64 to bytes.
    pub fn decode(encoded: &str) -> Result<Vec<u8>> {
        use base64ct::Encoding;
        base64ct::Base64::decode_vec(encoded)
            .map_err(|e| FormatError::InvalidBase64(e.to_string()))
    }

    /// Encode bytes as URL-safe Base64.
    ///
    /// Uses URL-safe alphabet (A-Z, a-z, 0-9, -, _) with = padding.
    pub fn encode_url_safe(data: &[u8]) -> String {
        use base64ct::Encoding;
        base64ct::Base64Url::encode_string(data)
    }

    /// Decode URL-safe Base64 to bytes.
    pub fn decode_url_safe(encoded: &str) -> Result<Vec<u8>> {
        use base64ct::Encoding;
        base64ct::Base64Url::decode_vec(encoded)
            .map_err(|e| FormatError::InvalidBase64(e.to_string()))
    }

    /// Encode bytes as Base64 without padding.
    ///
    /// Some systems prefer unpadded Base64 for compactness.
    pub fn encode_no_pad(data: &[u8]) -> String {
        use base64ct::Encoding;
        base64ct::Base64Unpadded::encode_string(data)
    }

    /// Decode unpadded Base64 to bytes.
    pub fn decode_no_pad(encoded: &str) -> Result<Vec<u8>> {
        use base64ct::Encoding;
        base64ct::Base64Unpadded::decode_vec(encoded)
            .map_err(|e| FormatError::InvalidBase64(e.to_string()))
    }

    /// Encode bytes as URL-safe Base64 without padding.
    pub fn encode_url_safe_no_pad(data: &[u8]) -> String {
        use base64ct::Encoding;
        base64ct::Base64UrlUnpadded::encode_string(data)
    }

    /// Decode URL-safe unpadded Base64 to bytes.
    pub fn decode_url_safe_no_pad(encoded: &str) -> Result<Vec<u8>> {
        use base64ct::Encoding;
        base64ct::Base64UrlUnpadded::decode_vec(encoded)
            .map_err(|e| FormatError::InvalidBase64(e.to_string()))
    }

    /// Calculate the encoded length for given input length.
    pub fn encoded_len(input_len: usize) -> usize {
        // Base64 expands 3 bytes to 4 characters, with padding
        ((input_len + 2) / 3) * 4
    }

    /// Calculate the maximum decoded length for given encoded length.
    pub fn max_decoded_len(encoded_len: usize) -> usize {
        // Base64 contracts 4 characters to 3 bytes
        (encoded_len / 4) * 3
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_standard_base64() {
        let data = b"Hello, World!";
        let encoded = Base64::encode(data);
        let decoded = Base64::decode(&encoded).unwrap();

        assert_eq!(decoded, data);
        assert_eq!(encoded, "SGVsbG8sIFdvcmxkIQ==");
    }

    #[test]
    fn test_url_safe_base64() {
        let data = b"Hello, World!";
        let encoded = Base64::encode_url_safe(data);
        let decoded = Base64::decode_url_safe(&encoded).unwrap();

        assert_eq!(decoded, data);
        // URL-safe should not contain + or /
        assert!(!encoded.contains('+'));
        assert!(!encoded.contains('/'));
    }

    #[test]
    fn test_no_padding() {
        let data = b"Hello";
        let encoded = Base64::encode_no_pad(data);
        let decoded = Base64::decode_no_pad(&encoded).unwrap();

        assert_eq!(decoded, data);
        assert!(!encoded.contains('='));
    }

    #[test]
    fn test_url_safe_no_padding() {
        let data = b"Hello";
        let encoded = Base64::encode_url_safe_no_pad(data);
        let decoded = Base64::decode_url_safe_no_pad(&encoded).unwrap();

        assert_eq!(decoded, data);
        assert!(!encoded.contains('='));
        assert!(!encoded.contains('+'));
        assert!(!encoded.contains('/'));
    }

    #[test]
    fn test_empty_data() {
        let data: &[u8] = b"";
        let encoded = Base64::encode(data);
        let decoded = Base64::decode(&encoded).unwrap();

        assert_eq!(decoded, data);
        assert!(encoded.is_empty());
    }

    #[test]
    fn test_binary_data() {
        let data: Vec<u8> = (0..=255).collect();
        let encoded = Base64::encode(&data);
        let decoded = Base64::decode(&encoded).unwrap();

        assert_eq!(decoded, data);
    }

    #[test]
    fn test_invalid_base64() {
        let result = Base64::decode("not valid base64!!!");
        assert!(result.is_err());

        let result = Base64::decode("===");
        assert!(result.is_err());
    }

    #[test]
    fn test_encoded_len() {
        assert_eq!(Base64::encoded_len(0), 0);
        assert_eq!(Base64::encoded_len(1), 4);
        assert_eq!(Base64::encoded_len(2), 4);
        assert_eq!(Base64::encoded_len(3), 4);
        assert_eq!(Base64::encoded_len(4), 8);
    }

    #[test]
    fn test_roundtrip_various_lengths() {
        for len in 0..100 {
            let data: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let encoded = Base64::encode(&data);
            let decoded = Base64::decode(&encoded).unwrap();
            assert_eq!(decoded, data, "Failed for length {}", len);
        }
    }
}
