//! In-memory key storage backend.
//!
//! This backend stores keys in memory. Keys are automatically zeroized
//! when removed or when the store is dropped.
//!
//! Best used for:
//! - Testing
//! - Ephemeral keys
//! - Short-lived sessions

use crate::error::{KeyStoreError, Result};
use crate::metadata::KeyMetadata;
use crate::traits::KeyStore;
use async_trait::async_trait;
use parking_lot::RwLock;
use std::collections::HashMap;
use zeroize::Zeroize;

/// Entry in the memory store.
struct KeyEntry {
    data: Vec<u8>,
    metadata: KeyMetadata,
}

impl Drop for KeyEntry {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

/// In-memory key storage backend.
///
/// Thread-safe and automatically zeroizes key data on removal.
///
/// # Example
///
/// ```rust,no_run
/// use arcanum_keystore::{MemoryKeyStore, KeyStore, KeyMetadata};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let store = MemoryKeyStore::new();
///
/// // Store a key
/// let key = vec![0u8; 32];
/// store.store("my-key", &key, None).await?;
///
/// // Retrieve it
/// let retrieved = store.get("my-key").await?.unwrap();
/// assert_eq!(retrieved, key);
/// # Ok(())
/// # }
/// ```
pub struct MemoryKeyStore {
    keys: RwLock<HashMap<String, KeyEntry>>,
}

impl MemoryKeyStore {
    /// Create a new empty in-memory key store.
    pub fn new() -> Self {
        Self {
            keys: RwLock::new(HashMap::new()),
        }
    }

    /// Create a new store with pre-allocated capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            keys: RwLock::new(HashMap::with_capacity(capacity)),
        }
    }
}

impl Default for MemoryKeyStore {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for MemoryKeyStore {
    fn drop(&mut self) {
        // Clear all keys - their Drop impl will zeroize the data
        self.keys.write().clear();
    }
}

#[async_trait]
impl KeyStore for MemoryKeyStore {
    async fn store(&self, id: &str, key_data: &[u8], metadata: Option<&KeyMetadata>) -> Result<()> {
        let mut keys = self.keys.write();

        if keys.contains_key(id) {
            return Err(KeyStoreError::KeyAlreadyExistsByName(id.to_string()));
        }

        let meta = metadata.cloned().unwrap_or_else(|| KeyMetadata::new("unknown"));

        keys.insert(
            id.to_string(),
            KeyEntry {
                data: key_data.to_vec(),
                metadata: meta,
            },
        );

        Ok(())
    }

    async fn get(&self, id: &str) -> Result<Option<Vec<u8>>> {
        let keys = self.keys.read();

        match keys.get(id) {
            Some(entry) => {
                if !entry.metadata.is_valid() {
                    if entry.metadata.revoked {
                        return Err(KeyStoreError::KeyRevoked(id.to_string()));
                    }
                    if entry.metadata.is_expired() {
                        return Err(KeyStoreError::KeyExpired(id.to_string()));
                    }
                }
                Ok(Some(entry.data.clone()))
            }
            None => Ok(None),
        }
    }

    async fn get_with_metadata(&self, id: &str) -> Result<Option<(Vec<u8>, KeyMetadata)>> {
        let keys = self.keys.read();

        match keys.get(id) {
            Some(entry) => {
                if !entry.metadata.is_valid() {
                    if entry.metadata.revoked {
                        return Err(KeyStoreError::KeyRevoked(id.to_string()));
                    }
                    if entry.metadata.is_expired() {
                        return Err(KeyStoreError::KeyExpired(id.to_string()));
                    }
                }
                Ok(Some((entry.data.clone(), entry.metadata.clone())))
            }
            None => Ok(None),
        }
    }

    async fn update(&self, id: &str, key_data: &[u8], metadata: Option<&KeyMetadata>) -> Result<()> {
        let mut keys = self.keys.write();

        match keys.get_mut(id) {
            Some(entry) => {
                // Zeroize old data
                entry.data.zeroize();
                entry.data = key_data.to_vec();

                if let Some(meta) = metadata {
                    entry.metadata = meta.clone();
                } else {
                    entry.metadata.touch();
                    entry.metadata.increment_version();
                }

                Ok(())
            }
            None => Err(KeyStoreError::KeyNotFoundByName(id.to_string())),
        }
    }

    async fn delete(&self, id: &str) -> Result<bool> {
        let mut keys = self.keys.write();
        // The entry's Drop impl will zeroize the data
        Ok(keys.remove(id).is_some())
    }

    async fn exists(&self, id: &str) -> Result<bool> {
        Ok(self.keys.read().contains_key(id))
    }

    async fn list(&self) -> Result<Vec<String>> {
        Ok(self.keys.read().keys().cloned().collect())
    }

    async fn get_metadata(&self, id: &str) -> Result<Option<KeyMetadata>> {
        Ok(self.keys.read().get(id).map(|e| e.metadata.clone()))
    }

    async fn update_metadata(&self, id: &str, metadata: &KeyMetadata) -> Result<()> {
        let mut keys = self.keys.write();

        match keys.get_mut(id) {
            Some(entry) => {
                entry.metadata = metadata.clone();
                Ok(())
            }
            None => Err(KeyStoreError::KeyNotFoundByName(id.to_string())),
        }
    }

    async fn clear(&self) -> Result<()> {
        self.keys.write().clear();
        Ok(())
    }

    async fn count(&self) -> Result<usize> {
        Ok(self.keys.read().len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_store_and_get() {
        let store = MemoryKeyStore::new();
        let key = vec![1u8, 2, 3, 4, 5];

        store.store("test", &key, None).await.unwrap();
        let retrieved = store.get("test").await.unwrap().unwrap();

        assert_eq!(retrieved, key);
    }

    #[tokio::test]
    async fn test_store_duplicate_fails() {
        let store = MemoryKeyStore::new();
        let key = vec![1u8, 2, 3];

        store.store("test", &key, None).await.unwrap();
        let result = store.store("test", &key, None).await;

        assert!(matches!(result, Err(KeyStoreError::KeyAlreadyExistsByName(_))));
    }

    #[tokio::test]
    async fn test_get_nonexistent() {
        let store = MemoryKeyStore::new();
        let result = store.get("nonexistent").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_update() {
        let store = MemoryKeyStore::new();
        let key1 = vec![1u8, 2, 3];
        let key2 = vec![4u8, 5, 6];

        store.store("test", &key1, None).await.unwrap();
        store.update("test", &key2, None).await.unwrap();

        let retrieved = store.get("test").await.unwrap().unwrap();
        assert_eq!(retrieved, key2);
    }

    #[tokio::test]
    async fn test_update_nonexistent_fails() {
        let store = MemoryKeyStore::new();
        let result = store.update("nonexistent", &[1, 2, 3], None).await;
        assert!(matches!(result, Err(KeyStoreError::KeyNotFoundByName(_))));
    }

    #[tokio::test]
    async fn test_delete() {
        let store = MemoryKeyStore::new();
        store.store("test", &[1, 2, 3], None).await.unwrap();

        let deleted = store.delete("test").await.unwrap();
        assert!(deleted);

        let deleted_again = store.delete("test").await.unwrap();
        assert!(!deleted_again);
    }

    #[tokio::test]
    async fn test_exists() {
        let store = MemoryKeyStore::new();

        assert!(!store.exists("test").await.unwrap());

        store.store("test", &[1, 2, 3], None).await.unwrap();
        assert!(store.exists("test").await.unwrap());
    }

    #[tokio::test]
    async fn test_list() {
        let store = MemoryKeyStore::new();

        store.store("key1", &[1], None).await.unwrap();
        store.store("key2", &[2], None).await.unwrap();
        store.store("key3", &[3], None).await.unwrap();

        let mut keys = store.list().await.unwrap();
        keys.sort();

        assert_eq!(keys, vec!["key1", "key2", "key3"]);
    }

    #[tokio::test]
    async fn test_clear() {
        let store = MemoryKeyStore::new();

        store.store("key1", &[1], None).await.unwrap();
        store.store("key2", &[2], None).await.unwrap();

        assert_eq!(store.count().await.unwrap(), 2);

        store.clear().await.unwrap();

        assert_eq!(store.count().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn test_metadata() {
        let store = MemoryKeyStore::new();
        let mut meta = KeyMetadata::new("AES-256-GCM");
        meta.set_description("Test key");

        store.store("test", &[1, 2, 3], Some(&meta)).await.unwrap();

        let retrieved_meta = store.get_metadata("test").await.unwrap().unwrap();
        assert_eq!(retrieved_meta.algorithm, "AES-256-GCM");
        assert_eq!(retrieved_meta.description, Some("Test key".to_string()));
    }

    #[tokio::test]
    async fn test_expired_key() {
        use chrono::{Duration, Utc};

        let store = MemoryKeyStore::new();
        let past = Utc::now() - Duration::hours(1);
        let meta = KeyMetadata::with_expiration("AES", past);

        store.store("expired", &[1, 2, 3], Some(&meta)).await.unwrap();

        let result = store.get("expired").await;
        assert!(matches!(result, Err(KeyStoreError::KeyExpired(_))));
    }

    #[tokio::test]
    async fn test_revoked_key() {
        let store = MemoryKeyStore::new();
        let mut meta = KeyMetadata::new("AES");
        meta.revoke(Some("Compromised".into()));

        store.store("revoked", &[1, 2, 3], Some(&meta)).await.unwrap();

        let result = store.get("revoked").await;
        assert!(matches!(result, Err(KeyStoreError::KeyRevoked(_))));
    }
}
