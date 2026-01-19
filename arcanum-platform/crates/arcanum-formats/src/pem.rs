//! PEM (Privacy-Enhanced Mail) format encoding.
//!
//! PEM is a standard format for encoding binary data (like cryptographic keys)
//! as ASCII text with BEGIN/END markers.

use crate::error::{FormatError, Result};

/// PEM encoding and decoding.
///
/// # Format
///
/// ```text
/// -----BEGIN PRIVATE KEY-----
/// Base64EncodedDataHere...
/// -----END PRIVATE KEY-----
/// ```
///
/// # Example
///
/// ```rust
/// use arcanum_formats::Pem;
///
/// let key_data = vec![0u8; 32];
/// let pem = Pem::encode("PRIVATE KEY", &key_data);
///
/// assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----"));
/// assert!(pem.ends_with("-----END PRIVATE KEY-----\n"));
///
/// let (label, decoded) = Pem::decode(&pem).unwrap();
/// assert_eq!(label, "PRIVATE KEY");
/// assert_eq!(decoded, key_data);
/// ```
pub struct Pem;

impl Pem {
    /// Encode binary data as PEM.
    ///
    /// # Arguments
    ///
    /// * `label` - The type label (e.g., "PRIVATE KEY", "PUBLIC KEY", "CERTIFICATE")
    /// * `data` - The binary data to encode
    ///
    /// # Returns
    ///
    /// A PEM-encoded string.
    pub fn encode(label: &str, data: &[u8]) -> String {
        use base64ct::Encoding;

        let base64 = base64ct::Base64::encode_string(data);

        // Split into 64-character lines
        let lines: Vec<&str> = base64
            .as_bytes()
            .chunks(64)
            .map(|chunk| std::str::from_utf8(chunk).unwrap())
            .collect();

        format!(
            "-----BEGIN {}-----\n{}\n-----END {}-----\n",
            label,
            lines.join("\n"),
            label
        )
    }

    /// Decode PEM-encoded data.
    ///
    /// # Arguments
    ///
    /// * `pem` - The PEM-encoded string
    ///
    /// # Returns
    ///
    /// A tuple of (label, decoded_data).
    pub fn decode(pem: &str) -> Result<(String, Vec<u8>)> {
        use base64ct::Encoding;

        let pem = pem.trim();

        // Find BEGIN marker
        let begin_prefix = "-----BEGIN ";
        let begin_idx = pem.find(begin_prefix)
            .ok_or_else(|| FormatError::InvalidPem("missing BEGIN marker".into()))?;

        let after_begin = &pem[begin_idx + begin_prefix.len()..];
        let label_end = after_begin.find("-----")
            .ok_or_else(|| FormatError::InvalidPem("malformed BEGIN marker".into()))?;

        let label = after_begin[..label_end].to_string();

        // Find END marker
        let end_marker = format!("-----END {}-----", label);
        let end_idx = pem.find(&end_marker)
            .ok_or_else(|| FormatError::InvalidPem("missing END marker".into()))?;

        // Extract base64 content
        let begin_marker = format!("-----BEGIN {}-----", label);
        let content_start = pem.find(&begin_marker).unwrap() + begin_marker.len();
        let content = &pem[content_start..end_idx];

        // Remove whitespace and decode
        let base64: String = content.chars().filter(|c| !c.is_whitespace()).collect();

        let decoded = base64ct::Base64::decode_vec(&base64)
            .map_err(|e| FormatError::InvalidBase64(e.to_string()))?;

        Ok((label, decoded))
    }

    /// Decode PEM with expected label validation.
    ///
    /// # Arguments
    ///
    /// * `pem` - The PEM-encoded string
    /// * `expected_label` - The expected type label
    ///
    /// # Returns
    ///
    /// The decoded binary data.
    ///
    /// # Errors
    ///
    /// Returns an error if the label doesn't match.
    pub fn decode_with_label(pem: &str, expected_label: &str) -> Result<Vec<u8>> {
        let (label, data) = Self::decode(pem)?;

        if label != expected_label {
            return Err(FormatError::LabelMismatch {
                expected: expected_label.to_string(),
                actual: label,
            });
        }

        Ok(data)
    }

    /// Common label for private keys.
    pub const PRIVATE_KEY: &'static str = "PRIVATE KEY";

    /// Common label for public keys.
    pub const PUBLIC_KEY: &'static str = "PUBLIC KEY";

    /// Common label for certificates.
    pub const CERTIFICATE: &'static str = "CERTIFICATE";

    /// Common label for RSA private keys.
    pub const RSA_PRIVATE_KEY: &'static str = "RSA PRIVATE KEY";

    /// Common label for RSA public keys.
    pub const RSA_PUBLIC_KEY: &'static str = "RSA PUBLIC KEY";

    /// Common label for EC private keys.
    pub const EC_PRIVATE_KEY: &'static str = "EC PRIVATE KEY";

    /// Common label for encrypted private keys.
    pub const ENCRYPTED_PRIVATE_KEY: &'static str = "ENCRYPTED PRIVATE KEY";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode() {
        let data = vec![0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let pem = Pem::encode("TEST KEY", &data);

        let (label, decoded) = Pem::decode(&pem).unwrap();

        assert_eq!(label, "TEST KEY");
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_encode_format() {
        let data = vec![0u8; 32];
        let pem = Pem::encode("PRIVATE KEY", &data);

        assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----\n"));
        assert!(pem.ends_with("-----END PRIVATE KEY-----\n"));
    }

    #[test]
    fn test_decode_with_label() {
        let data = vec![1u8, 2, 3];
        let pem = Pem::encode("PUBLIC KEY", &data);

        // Correct label
        let decoded = Pem::decode_with_label(&pem, "PUBLIC KEY").unwrap();
        assert_eq!(decoded, data);

        // Wrong label
        let result = Pem::decode_with_label(&pem, "PRIVATE KEY");
        assert!(matches!(result, Err(FormatError::LabelMismatch { .. })));
    }

    #[test]
    fn test_long_data() {
        // Test with data that spans multiple lines
        let data = vec![42u8; 256];
        let pem = Pem::encode("LONG KEY", &data);

        let (label, decoded) = Pem::decode(&pem).unwrap();
        assert_eq!(label, "LONG KEY");
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_whitespace_tolerance() {
        let data = vec![1u8, 2, 3];
        let pem = Pem::encode("KEY", &data);

        // Add extra whitespace
        let pem_with_spaces = format!("\n\n  {}  \n\n", pem);

        let (label, decoded) = Pem::decode(&pem_with_spaces).unwrap();
        assert_eq!(label, "KEY");
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_invalid_pem() {
        // Missing BEGIN
        let result = Pem::decode("some random text");
        assert!(matches!(result, Err(FormatError::InvalidPem(_))));

        // Malformed
        let result = Pem::decode("-----BEGIN BROKEN");
        assert!(matches!(result, Err(FormatError::InvalidPem(_))));

        // Missing END
        let result = Pem::decode("-----BEGIN KEY-----\ndata\n");
        assert!(matches!(result, Err(FormatError::InvalidPem(_))));
    }

    #[test]
    fn test_empty_data() {
        let data: Vec<u8> = vec![];
        let pem = Pem::encode("EMPTY", &data);

        let (label, decoded) = Pem::decode(&pem).unwrap();
        assert_eq!(label, "EMPTY");
        assert!(decoded.is_empty());
    }
}
