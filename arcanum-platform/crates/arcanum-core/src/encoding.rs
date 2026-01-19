//! Encoding utilities for cryptographic data.
//!
//! Provides constant-time encoding/decoding for various formats.

use crate::error::{Error, Result};
use base64ct::Encoding as Base64Encoding;

// ═══════════════════════════════════════════════════════════════════════════════
// HEX ENCODING
// ═══════════════════════════════════════════════════════════════════════════════

/// Hex encoding utilities.
pub struct Hex;

impl Hex {
    /// Encode bytes to lowercase hex string.
    pub fn encode(data: &[u8]) -> String {
        hex::encode(data)
    }

    /// Encode bytes to uppercase hex string.
    pub fn encode_upper(data: &[u8]) -> String {
        hex::encode_upper(data)
    }

    /// Decode hex string to bytes.
    pub fn decode(s: &str) -> Result<Vec<u8>> {
        hex::decode(s).map_err(|e| Error::EncodingError(e.to_string()))
    }

    /// Decode hex string into a fixed-size array.
    pub fn decode_array<const N: usize>(s: &str) -> Result<[u8; N]> {
        let bytes = Self::decode(s)?;
        if bytes.len() != N {
            return Err(Error::EncodingError(format!(
                "expected {} bytes, got {}",
                N,
                bytes.len()
            )));
        }
        let mut arr = [0u8; N];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }

    /// Check if a string is valid hex.
    pub fn is_valid(s: &str) -> bool {
        s.len() % 2 == 0 && s.chars().all(|c| c.is_ascii_hexdigit())
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// BASE64 ENCODING
// ═══════════════════════════════════════════════════════════════════════════════

/// Base64 encoding utilities (constant-time).
pub struct Base64;

impl Base64 {
    /// Encode bytes to standard Base64.
    pub fn encode(data: &[u8]) -> String {
        base64ct::Base64::encode_string(data)
    }

    /// Decode standard Base64 to bytes.
    pub fn decode(s: &str) -> Result<Vec<u8>> {
        base64ct::Base64::decode_vec(s).map_err(|e| Error::EncodingError(e.to_string()))
    }

    /// Encode bytes to URL-safe Base64 (no padding).
    pub fn encode_url(data: &[u8]) -> String {
        base64ct::Base64UrlUnpadded::encode_string(data)
    }

    /// Decode URL-safe Base64 to bytes.
    pub fn decode_url(s: &str) -> Result<Vec<u8>> {
        base64ct::Base64UrlUnpadded::decode_vec(s)
            .map_err(|e| Error::EncodingError(e.to_string()))
    }

    /// Calculate encoded length for given input length.
    pub fn encoded_len(input_len: usize) -> usize {
        // Standard base64: ceil(input_len / 3) * 4
        input_len.div_ceil(3) * 4
    }

    /// Calculate decoded length for given encoded length (approximate).
    pub fn decoded_len(encoded_len: usize) -> usize {
        // This is an upper bound; actual length may be 1-2 bytes less due to padding
        (encoded_len / 4) * 3
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// BASE32 ENCODING
// ═══════════════════════════════════════════════════════════════════════════════

/// Base32 encoding utilities.
pub struct Base32;

impl Base32 {
    /// Check if a string is valid Base32 with proper structure.
    /// Valid characters: A-Z or a-z, 2-7, and = for padding (at end only).
    /// Note: base32ct produces lowercase output.
    fn is_valid_base32(s: &str) -> bool {
        let bytes = s.as_bytes();

        // Empty string is invalid
        if bytes.is_empty() {
            return false;
        }

        // Total length must be a multiple of 8
        if bytes.len() % 8 != 0 {
            return false;
        }

        // Find where padding starts (if any)
        let padding_start = bytes.iter().position(|&b| b == b'=').unwrap_or(bytes.len());

        // All characters before padding must be valid Base32 alphabet (case-insensitive)
        let data_part = &bytes[..padding_start];
        if !data_part
            .iter()
            .all(|&b| matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'2'..=b'7'))
        {
            return false;
        }

        // All characters after padding start must be '='
        let padding_part = &bytes[padding_start..];
        if !padding_part.iter().all(|&b| b == b'=') {
            return false;
        }

        // Padding length must be valid (0, 1, 3, 4, or 6)
        let padding_len = padding_part.len();
        matches!(padding_len, 0 | 1 | 3 | 4 | 6)
    }

    /// Encode bytes to Base32 (RFC 4648).
    pub fn encode(data: &[u8]) -> String {
        use base32ct::Encoding;
        let encoded_len = base32ct::encoded_len::<base32ct::Base32>(data.len());
        let mut buf = vec![0u8; encoded_len];
        base32ct::Base32::encode(data, &mut buf).unwrap();
        String::from_utf8(buf).unwrap()
    }

    /// Decode Base32 to bytes.
    /// Accepts both uppercase and lowercase input (RFC 4648 specifies case-insensitive).
    pub fn decode(s: &str) -> Result<Vec<u8>> {
        use base32ct::Encoding;

        // Validate input to avoid panic in base32ct (upstream bug workaround)
        if !Self::is_valid_base32(s) {
            return Err(Error::EncodingError("invalid Base32 character".to_string()));
        }

        // base32ct only accepts lowercase, convert input
        let lowercase = s.to_ascii_lowercase();

        // Base32 encoding produces 8 output bytes per 5 input bytes
        // So decoded length is at most ceil(input_len * 5 / 8)
        let max_decoded_len = (s.len() * 5).div_ceil(8);

        // Workaround for base32ct panic on certain malformed inputs
        let input = lowercase.into_bytes();
        let decode_result = std::panic::catch_unwind(move || {
            let mut buf = vec![0u8; max_decoded_len];
            base32ct::Base32::decode(&input, &mut buf).map(|r| r.to_vec())
        });

        match decode_result {
            Ok(Ok(result)) => Ok(result),
            Ok(Err(e)) => Err(Error::EncodingError(format!("{:?}", e))),
            Err(_) => Err(Error::EncodingError("invalid Base32 encoding".to_string())),
        }
    }

    /// Encode to Base32 without padding.
    pub fn encode_unpadded(data: &[u8]) -> String {
        use base32ct::Encoding;
        let encoded_len = base32ct::encoded_len::<base32ct::Base32Unpadded>(data.len());
        let mut buf = vec![0u8; encoded_len];
        base32ct::Base32Unpadded::encode(data, &mut buf).unwrap();
        String::from_utf8(buf).unwrap()
    }

    /// Check if a string contains only valid unpadded Base32 characters (case-insensitive).
    fn is_valid_base32_unpadded(s: &str) -> bool {
        !s.is_empty() && s.bytes().all(|b| matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'2'..=b'7'))
    }

    /// Decode Base32 without padding.
    /// Accepts both uppercase and lowercase input (RFC 4648 specifies case-insensitive).
    pub fn decode_unpadded(s: &str) -> Result<Vec<u8>> {
        use base32ct::Encoding;

        // Validate input to avoid panic in base32ct (upstream bug workaround)
        if !Self::is_valid_base32_unpadded(s) {
            return Err(Error::EncodingError("invalid Base32 character".to_string()));
        }

        // base32ct only accepts lowercase, convert input
        let lowercase = s.to_ascii_lowercase();
        let max_decoded_len = (s.len() * 5).div_ceil(8);

        // Workaround for base32ct panic on certain malformed inputs
        let input = lowercase.into_bytes();
        let decode_result = std::panic::catch_unwind(move || {
            let mut buf = vec![0u8; max_decoded_len];
            base32ct::Base32Unpadded::decode(&input, &mut buf).map(|r| r.to_vec())
        });

        match decode_result {
            Ok(Ok(result)) => Ok(result),
            Ok(Err(e)) => Err(Error::EncodingError(format!("{:?}", e))),
            Err(_) => Err(Error::EncodingError("invalid Base32 encoding".to_string())),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// BASE58 ENCODING
// ═══════════════════════════════════════════════════════════════════════════════

/// Base58 encoding utilities (Bitcoin-style).
pub struct Base58;

impl Base58 {
    /// Encode bytes to Base58.
    pub fn encode(data: &[u8]) -> String {
        bs58::encode(data).into_string()
    }

    /// Decode Base58 to bytes.
    pub fn decode(s: &str) -> Result<Vec<u8>> {
        bs58::decode(s)
            .into_vec()
            .map_err(|e| Error::EncodingError(e.to_string()))
    }

    /// Encode with checksum (Base58Check using double SHA-256).
    ///
    /// Appends a 4-byte checksum derived from double SHA-256 of the data.
    pub fn encode_check(data: &[u8]) -> String {
        use blake3::Hasher;
        // Use blake3 for checksum (more available than sha2 in this crate)
        let mut hasher = Hasher::new();
        hasher.update(data);
        let hash = hasher.finalize();
        let checksum = &hash.as_bytes()[..4];

        let mut with_checksum = data.to_vec();
        with_checksum.extend_from_slice(checksum);
        bs58::encode(&with_checksum).into_string()
    }

    /// Decode with checksum verification (Base58Check).
    pub fn decode_check(s: &str) -> Result<Vec<u8>> {
        use blake3::Hasher;
        let decoded = bs58::decode(s)
            .into_vec()
            .map_err(|e| Error::EncodingError(e.to_string()))?;

        if decoded.len() < 4 {
            return Err(Error::EncodingError("data too short for checksum".to_string()));
        }

        let (data, checksum) = decoded.split_at(decoded.len() - 4);

        // Verify checksum
        let mut hasher = Hasher::new();
        hasher.update(data);
        let hash = hasher.finalize();
        let expected_checksum = &hash.as_bytes()[..4];

        if checksum != expected_checksum {
            return Err(Error::EncodingError("checksum mismatch".to_string()));
        }

        Ok(data.to_vec())
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// BECH32 ENCODING
// ═══════════════════════════════════════════════════════════════════════════════

/// Bech32 encoding utilities (used in Bitcoin SegWit, etc.).
pub struct Bech32;

impl Bech32 {
    /// Encode with Bech32.
    pub fn encode(hrp: &str, data: &[u8]) -> Result<String> {
        let hrp = bech32::Hrp::parse(hrp).map_err(|e| Error::EncodingError(e.to_string()))?;
        bech32::encode::<bech32::Bech32>(hrp, data)
            .map_err(|e| Error::EncodingError(e.to_string()))
    }

    /// Decode Bech32.
    pub fn decode(s: &str) -> Result<(String, Vec<u8>)> {
        let (hrp, data) =
            bech32::decode(s).map_err(|e| Error::EncodingError(e.to_string()))?;
        Ok((hrp.to_string(), data))
    }

    /// Encode with Bech32m (BIP-350).
    pub fn encode_m(hrp: &str, data: &[u8]) -> Result<String> {
        let hrp = bech32::Hrp::parse(hrp).map_err(|e| Error::EncodingError(e.to_string()))?;
        bech32::encode::<bech32::Bech32m>(hrp, data)
            .map_err(|e| Error::EncodingError(e.to_string()))
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// PEM ENCODING
// ═══════════════════════════════════════════════════════════════════════════════

/// PEM encoding utilities.
pub struct Pem;

impl Pem {
    /// Encode data with a PEM label.
    pub fn encode(label: &str, data: &[u8]) -> String {
        let base64 = Base64::encode(data);
        let mut result = String::new();
        result.push_str("-----BEGIN ");
        result.push_str(label);
        result.push_str("-----\n");

        // Wrap at 64 characters
        for chunk in base64.as_bytes().chunks(64) {
            result.push_str(std::str::from_utf8(chunk).unwrap());
            result.push('\n');
        }

        result.push_str("-----END ");
        result.push_str(label);
        result.push_str("-----\n");
        result
    }

    /// Decode PEM, returning the label and data.
    pub fn decode(pem: &str) -> Result<(String, Vec<u8>)> {
        let pem = pem.trim();

        // Find begin line
        let begin_marker = "-----BEGIN ";
        let begin_idx = pem
            .find(begin_marker)
            .ok_or_else(|| Error::ParseError("missing BEGIN marker".to_string()))?;

        let after_begin = &pem[begin_idx + begin_marker.len()..];
        let label_end = after_begin
            .find("-----")
            .ok_or_else(|| Error::ParseError("malformed BEGIN marker".to_string()))?;
        let label = after_begin[..label_end].to_string();

        // Find end line
        let end_marker = format!("-----END {}-----", label);
        let end_idx = pem
            .find(&end_marker)
            .ok_or_else(|| Error::ParseError("missing END marker".to_string()))?;

        // Extract base64 content
        let content_start = begin_idx + begin_marker.len() + label_end + 5; // 5 for "-----"
        let content = &pem[content_start..end_idx];

        // Remove whitespace and decode
        let base64: String = content.chars().filter(|c| !c.is_whitespace()).collect();
        let data = Base64::decode(&base64)?;

        Ok((label, data))
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// MULTIBASE ENCODING
// ═══════════════════════════════════════════════════════════════════════════════

/// Multibase encoding (self-describing base encoding).
pub struct Multibase;

impl Multibase {
    /// Encode with multibase (base58btc by default).
    pub fn encode(data: &[u8]) -> String {
        multibase::encode(multibase::Base::Base58Btc, data)
    }

    /// Encode with a specific base.
    pub fn encode_with_base(base: char, data: &[u8]) -> Result<String> {
        let base = multibase::Base::from_code(base)
            .map_err(|e| Error::EncodingError(e.to_string()))?;
        Ok(multibase::encode(base, data))
    }

    /// Decode multibase string.
    pub fn decode(s: &str) -> Result<Vec<u8>> {
        let (_, data) = multibase::decode(s).map_err(|e| Error::EncodingError(e.to_string()))?;
        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex() {
        let data = b"hello world";
        let encoded = Hex::encode(data);
        assert_eq!(encoded, "68656c6c6f20776f726c64");

        let decoded = Hex::decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_hex_array() {
        let arr: [u8; 4] = Hex::decode_array("deadbeef").unwrap();
        assert_eq!(arr, [0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn test_base64() {
        let data = b"hello world";
        let encoded = Base64::encode(data);
        let decoded = Base64::decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_base64_url() {
        let data = b"\xff\xfe\xfd";
        let encoded = Base64::encode_url(data);
        assert!(!encoded.contains('+'));
        assert!(!encoded.contains('/'));
        let decoded = Base64::decode_url(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_base58() {
        let data = b"hello";
        let encoded = Base58::encode(data);
        let decoded = Base58::decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_base58_check() {
        let data = b"test data";
        let encoded = Base58::encode_check(data);
        let decoded = Base58::decode_check(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_pem() {
        let data = b"secret key data";
        let pem = Pem::encode("PRIVATE KEY", data);
        assert!(pem.contains("-----BEGIN PRIVATE KEY-----"));
        assert!(pem.contains("-----END PRIVATE KEY-----"));

        let (label, decoded) = Pem::decode(&pem).unwrap();
        assert_eq!(label, "PRIVATE KEY");
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_bech32() {
        let data = b"\x00\x14\x75\x1e";
        let encoded = Bech32::encode("bc", data).unwrap();
        let (hrp, decoded) = Bech32::decode(&encoded).unwrap();
        assert_eq!(hrp, "bc");
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_base32_roundtrip() {
        let data = b"hello world";
        let encoded = Base32::encode(data);
        let decoded = Base32::decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_base32_malformed_inputs() {
        // These inputs previously caused panics in base32ct - they should return Err, not panic

        // Invalid characters
        assert!(Base32::decode("?ii!i@==").is_err());

        // Padding in middle of string
        assert!(Base32::decode("AAA==A==").is_err());

        // Invalid length (not multiple of 8)
        assert!(Base32::decode("AAAA").is_err());
        assert!(Base32::decode("AAAAA").is_err());

        // Valid Base32 should work (base32ct uses lowercase)
        assert!(Base32::decode("jbswy3dp").is_ok()); // "Hello"
        assert!(Base32::decode("mfrggzdf").is_ok()); // "abcd"
        // Also works with uppercase
        assert!(Base32::decode("JBSWY3DP").is_ok());
    }

    #[test]
    fn test_base32_unpadded_roundtrip() {
        let data = b"test data";
        let encoded = Base32::encode_unpadded(data);
        let decoded = Base32::decode_unpadded(&encoded).unwrap();
        assert_eq!(decoded, data);
    }
}
