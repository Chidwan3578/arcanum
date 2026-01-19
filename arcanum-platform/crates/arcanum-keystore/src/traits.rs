//! Core traits for key storage backends.

use crate::error::Result;
use crate::metadata::KeyMetadata;
use async_trait::async_trait;

/// Trait for key storage backends.
///
/// Implementations must be thread-safe and support concurrent access.
#[async_trait]
pub trait KeyStore: Send + Sync {
    /// Store a key with optional metadata.
    ///
    /// # Arguments
    ///
    /// * `id` - Unique identifier for the key
    /// * `key_data` - The raw key bytes
    /// * `metadata` - Optional metadata about the key
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - A key with this ID already exists (use `update` instead)
    /// - The storage backend fails
    async fn store(&self, id: &str, key_data: &[u8], metadata: Option<&KeyMetadata>) -> Result<()>;

    /// Retrieve a key by ID.
    ///
    /// # Arguments
    ///
    /// * `id` - The key identifier
    ///
    /// # Returns
    ///
    /// The key data if found, or `None` if the key doesn't exist.
    async fn get(&self, id: &str) -> Result<Option<Vec<u8>>>;

    /// Retrieve a key with its metadata.
    ///
    /// # Arguments
    ///
    /// * `id` - The key identifier
    ///
    /// # Returns
    ///
    /// A tuple of (key_data, metadata) if found.
    async fn get_with_metadata(&self, id: &str) -> Result<Option<(Vec<u8>, KeyMetadata)>>;

    /// Update an existing key.
    ///
    /// # Arguments
    ///
    /// * `id` - The key identifier
    /// * `key_data` - The new key bytes
    /// * `metadata` - Optional updated metadata
    ///
    /// # Errors
    ///
    /// Returns an error if the key doesn't exist.
    async fn update(&self, id: &str, key_data: &[u8], metadata: Option<&KeyMetadata>) -> Result<()>;

    /// Delete a key.
    ///
    /// # Arguments
    ///
    /// * `id` - The key identifier
    ///
    /// # Returns
    ///
    /// `true` if the key was deleted, `false` if it didn't exist.
    async fn delete(&self, id: &str) -> Result<bool>;

    /// Check if a key exists.
    ///
    /// # Arguments
    ///
    /// * `id` - The key identifier
    async fn exists(&self, id: &str) -> Result<bool>;

    /// List all key IDs in the store.
    async fn list(&self) -> Result<Vec<String>>;

    /// Get metadata for a key without retrieving the key data.
    ///
    /// # Arguments
    ///
    /// * `id` - The key identifier
    async fn get_metadata(&self, id: &str) -> Result<Option<KeyMetadata>>;

    /// Update only the metadata for a key.
    ///
    /// # Arguments
    ///
    /// * `id` - The key identifier
    /// * `metadata` - The new metadata
    async fn update_metadata(&self, id: &str, metadata: &KeyMetadata) -> Result<()>;

    /// Clear all keys from the store.
    ///
    /// # Warning
    ///
    /// This permanently deletes all keys. Use with caution.
    async fn clear(&self) -> Result<()>;

    /// Get the number of keys in the store.
    async fn count(&self) -> Result<usize>;
}
