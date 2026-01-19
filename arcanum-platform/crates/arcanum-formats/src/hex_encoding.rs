//! Hexadecimal encoding utilities.
//!
//! Provides hex encoding/decoding for cryptographic data.

use crate::error::{FormatError, Result};

/// Hexadecimal encoding and decoding.
///
/// # Example
///
/// ```rust
/// use arcanum_formats::Hex;
///
/// let data = b"Hello";
///
/// // Lowercase hex (default)
/// let encoded = Hex::encode(data);
/// assert_eq!(encoded, "48656c6c6f");
///
/// // Uppercase hex
/// let upper = Hex::encode_upper(data);
/// assert_eq!(upper, "48656C6C6F");
///
/// // Decode (case-insensitive)
/// let decoded = Hex::decode(&encoded).unwrap();
/// assert_eq!(decoded, data);
/// ```
pub struct Hex;

impl Hex {
    /// Encode bytes as lowercase hexadecimal.
    pub fn encode(data: &[u8]) -> String {
        hex::encode(data)
    }

    /// Encode bytes as uppercase hexadecimal.
    pub fn encode_upper(data: &[u8]) -> String {
        hex::encode_upper(data)
    }

    /// Decode hexadecimal string to bytes.
    ///
    /// Accepts both lowercase and uppercase hex.
    pub fn decode(encoded: &str) -> Result<Vec<u8>> {
        hex::decode(encoded)
            .map_err(|e| FormatError::InvalidHex(e.to_string()))
    }

    /// Decode hexadecimal string with prefix handling.
    ///
    /// Strips "0x" or "0X" prefix if present.
    pub fn decode_with_prefix(encoded: &str) -> Result<Vec<u8>> {
        let cleaned = encoded
            .strip_prefix("0x")
            .or_else(|| encoded.strip_prefix("0X"))
            .unwrap_or(encoded);

        Self::decode(cleaned)
    }

    /// Encode with "0x" prefix.
    pub fn encode_with_prefix(data: &[u8]) -> String {
        format!("0x{}", hex::encode(data))
    }

    /// Calculate the encoded length for given input length.
    pub fn encoded_len(input_len: usize) -> usize {
        input_len * 2
    }

    /// Calculate the decoded length for given encoded length.
    pub fn decoded_len(encoded_len: usize) -> usize {
        encoded_len / 2
    }

    /// Validate that a string is valid hexadecimal.
    pub fn is_valid(s: &str) -> bool {
        s.chars().all(|c| c.is_ascii_hexdigit())
    }

    /// Validate hex string with optional "0x" prefix.
    pub fn is_valid_with_prefix(s: &str) -> bool {
        let cleaned = s
            .strip_prefix("0x")
            .or_else(|| s.strip_prefix("0X"))
            .unwrap_or(s);

        Self::is_valid(cleaned)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode() {
        let data = b"Hello, World!";
        let encoded = Hex::encode(data);
        let decoded = Hex::decode(&encoded).unwrap();

        assert_eq!(decoded, data);
    }

    #[test]
    fn test_lowercase() {
        let data = &[0xAB, 0xCD, 0xEF];
        let encoded = Hex::encode(data);

        assert_eq!(encoded, "abcdef");
    }

    #[test]
    fn test_uppercase() {
        let data = &[0xAB, 0xCD, 0xEF];
        let encoded = Hex::encode_upper(data);

        assert_eq!(encoded, "ABCDEF");
    }

    #[test]
    fn test_case_insensitive_decode() {
        let lower = Hex::decode("abcdef").unwrap();
        let upper = Hex::decode("ABCDEF").unwrap();
        let mixed = Hex::decode("AbCdEf").unwrap();

        assert_eq!(lower, upper);
        assert_eq!(lower, mixed);
    }

    #[test]
    fn test_prefix_handling() {
        let data = &[0x12, 0x34];

        let with_prefix = Hex::encode_with_prefix(data);
        assert_eq!(with_prefix, "0x1234");

        let decoded = Hex::decode_with_prefix(&with_prefix).unwrap();
        assert_eq!(decoded, data);

        // Works with uppercase prefix too
        let decoded = Hex::decode_with_prefix("0X1234").unwrap();
        assert_eq!(decoded, data);

        // Works without prefix
        let decoded = Hex::decode_with_prefix("1234").unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_empty_data() {
        let data: &[u8] = b"";
        let encoded = Hex::encode(data);
        let decoded = Hex::decode(&encoded).unwrap();

        assert!(encoded.is_empty());
        assert!(decoded.is_empty());
    }

    #[test]
    fn test_all_bytes() {
        let data: Vec<u8> = (0..=255).collect();
        let encoded = Hex::encode(&data);
        let decoded = Hex::decode(&encoded).unwrap();

        assert_eq!(decoded, data);
    }

    #[test]
    fn test_invalid_hex() {
        // Invalid character
        let result = Hex::decode("xyz");
        assert!(result.is_err());

        // Odd length
        let result = Hex::decode("abc");
        assert!(result.is_err());
    }

    #[test]
    fn test_is_valid() {
        assert!(Hex::is_valid("0123456789abcdef"));
        assert!(Hex::is_valid("0123456789ABCDEF"));
        assert!(Hex::is_valid(""));

        assert!(!Hex::is_valid("xyz"));
        assert!(!Hex::is_valid("0x1234")); // Without prefix handling
    }

    #[test]
    fn test_is_valid_with_prefix() {
        assert!(Hex::is_valid_with_prefix("0x1234"));
        assert!(Hex::is_valid_with_prefix("0X1234"));
        assert!(Hex::is_valid_with_prefix("1234"));

        assert!(!Hex::is_valid_with_prefix("0xXYZ"));
    }

    #[test]
    fn test_encoded_len() {
        assert_eq!(Hex::encoded_len(0), 0);
        assert_eq!(Hex::encoded_len(1), 2);
        assert_eq!(Hex::encoded_len(10), 20);
    }

    #[test]
    fn test_decoded_len() {
        assert_eq!(Hex::decoded_len(0), 0);
        assert_eq!(Hex::decoded_len(2), 1);
        assert_eq!(Hex::decoded_len(20), 10);
    }
}
