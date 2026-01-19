//! Key metadata for lifecycle management.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Metadata associated with a stored key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMetadata {
    /// Unique identifier for this metadata entry.
    pub id: String,

    /// Algorithm the key is intended for.
    pub algorithm: String,

    /// When the key was created.
    pub created_at: DateTime<Utc>,

    /// When the key was last updated.
    pub updated_at: DateTime<Utc>,

    /// When the key expires (if applicable).
    pub expires_at: Option<DateTime<Utc>>,

    /// Whether the key has been revoked.
    pub revoked: bool,

    /// When the key was revoked (if applicable).
    pub revoked_at: Option<DateTime<Utc>>,

    /// Reason for revocation (if applicable).
    pub revocation_reason: Option<String>,

    /// Key version for rotation tracking.
    pub version: u32,

    /// Optional description.
    pub description: Option<String>,

    /// Optional tags for categorization.
    pub tags: Vec<String>,

    /// Custom attributes.
    pub attributes: std::collections::HashMap<String, String>,
}

impl KeyMetadata {
    /// Create new metadata for a key.
    ///
    /// # Arguments
    ///
    /// * `algorithm` - The algorithm this key is used for
    pub fn new(algorithm: impl Into<String>) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4().to_string(),
            algorithm: algorithm.into(),
            created_at: now,
            updated_at: now,
            expires_at: None,
            revoked: false,
            revoked_at: None,
            revocation_reason: None,
            version: 1,
            description: None,
            tags: Vec::new(),
            attributes: std::collections::HashMap::new(),
        }
    }

    /// Create metadata with an expiration time.
    ///
    /// # Arguments
    ///
    /// * `algorithm` - The algorithm this key is used for
    /// * `expires_at` - When the key should expire
    pub fn with_expiration(algorithm: impl Into<String>, expires_at: DateTime<Utc>) -> Self {
        let mut meta = Self::new(algorithm);
        meta.expires_at = Some(expires_at);
        meta
    }

    /// Set the expiration time.
    pub fn set_expiration(&mut self, expires_at: DateTime<Utc>) -> &mut Self {
        self.expires_at = Some(expires_at);
        self.updated_at = Utc::now();
        self
    }

    /// Set the description.
    pub fn set_description(&mut self, description: impl Into<String>) -> &mut Self {
        self.description = Some(description.into());
        self.updated_at = Utc::now();
        self
    }

    /// Add a tag.
    pub fn add_tag(&mut self, tag: impl Into<String>) -> &mut Self {
        self.tags.push(tag.into());
        self.updated_at = Utc::now();
        self
    }

    /// Add a custom attribute.
    pub fn add_attribute(&mut self, key: impl Into<String>, value: impl Into<String>) -> &mut Self {
        self.attributes.insert(key.into(), value.into());
        self.updated_at = Utc::now();
        self
    }

    /// Check if the key is expired.
    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            Utc::now() > expires_at
        } else {
            false
        }
    }

    /// Check if the key is valid (not expired and not revoked).
    pub fn is_valid(&self) -> bool {
        !self.revoked && !self.is_expired()
    }

    /// Revoke the key.
    ///
    /// # Arguments
    ///
    /// * `reason` - Optional reason for revocation
    pub fn revoke(&mut self, reason: Option<String>) {
        self.revoked = true;
        self.revoked_at = Some(Utc::now());
        self.revocation_reason = reason;
        self.updated_at = Utc::now();
    }

    /// Increment the version (for key rotation).
    pub fn increment_version(&mut self) {
        self.version += 1;
        self.updated_at = Utc::now();
    }

    /// Update the updated_at timestamp.
    pub fn touch(&mut self) {
        self.updated_at = Utc::now();
    }

    /// Serialize to JSON.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Deserialize from JSON.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Serialize to binary format.
    pub fn to_bytes(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(self)
    }

    /// Deserialize from binary format.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }
}

impl Default for KeyMetadata {
    fn default() -> Self {
        Self::new("unknown")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn test_new_metadata() {
        let meta = KeyMetadata::new("AES-256-GCM");
        assert_eq!(meta.algorithm, "AES-256-GCM");
        assert_eq!(meta.version, 1);
        assert!(!meta.revoked);
        assert!(meta.is_valid());
    }

    #[test]
    fn test_expiration() {
        let future = Utc::now() + Duration::hours(1);
        let meta = KeyMetadata::with_expiration("AES-256-GCM", future);
        assert!(!meta.is_expired());
        assert!(meta.is_valid());

        let past = Utc::now() - Duration::hours(1);
        let expired_meta = KeyMetadata::with_expiration("AES-256-GCM", past);
        assert!(expired_meta.is_expired());
        assert!(!expired_meta.is_valid());
    }

    #[test]
    fn test_revocation() {
        let mut meta = KeyMetadata::new("Ed25519");
        assert!(meta.is_valid());

        meta.revoke(Some("Key compromised".into()));
        assert!(meta.revoked);
        assert!(!meta.is_valid());
        assert_eq!(meta.revocation_reason, Some("Key compromised".into()));
    }

    #[test]
    fn test_serialization() {
        let mut meta = KeyMetadata::new("ChaCha20-Poly1305");
        meta.set_description("Test key");
        meta.add_tag("test");
        meta.add_attribute("environment", "development");

        let json = meta.to_json().unwrap();
        let restored = KeyMetadata::from_json(&json).unwrap();
        assert_eq!(restored.algorithm, meta.algorithm);
        assert_eq!(restored.description, meta.description);

        let bytes = meta.to_bytes().unwrap();
        let restored = KeyMetadata::from_bytes(&bytes).unwrap();
        assert_eq!(restored.algorithm, meta.algorithm);
    }

    #[test]
    fn test_version_increment() {
        let mut meta = KeyMetadata::new("RSA-4096");
        assert_eq!(meta.version, 1);

        meta.increment_version();
        assert_eq!(meta.version, 2);

        meta.increment_version();
        assert_eq!(meta.version, 3);
    }
}
