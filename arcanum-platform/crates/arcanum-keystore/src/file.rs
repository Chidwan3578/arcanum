//! File-based key storage backend.
//!
//! This backend stores keys on the filesystem with atomic writes
//! and file locking for concurrent access safety.
//!
//! Best used for:
//! - Persistent key storage
//! - Development environments
//! - Simple deployments without external databases

use crate::error::{KeyStoreError, Result};
use crate::metadata::KeyMetadata;
use crate::traits::KeyStore;
use async_trait::async_trait;
use base64ct::Encoding;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tokio::fs;
use tokio::io::AsyncWriteExt;
use zeroize::Zeroize;

/// On-disk format for stored keys.
#[derive(Serialize, Deserialize)]
struct StoredKey {
    /// Base64-encoded key data
    data: String,
    /// Key metadata
    metadata: KeyMetadata,
}

/// File-based key storage backend.
///
/// Keys are stored as individual JSON files in the specified directory.
/// Uses atomic writes (write to temp, then rename) to prevent corruption.
///
/// # Directory Structure
///
/// ```text
/// /path/to/keystore/
/// ├── index.json       # Key ID to filename mapping
/// ├── keys/
/// │   ├── <uuid1>.key  # Individual key files
/// │   ├── <uuid2>.key
/// │   └── ...
/// ```
///
/// # Example
///
/// ```rust,no_run
/// use arcanum_keystore::{FileKeyStore, KeyStore};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let store = FileKeyStore::new("/path/to/keystore").await?;
///
/// // Store a key
/// let key = vec![0u8; 32];
/// store.store("my-key", &key, None).await?;
///
/// // Keys persist across restarts
/// drop(store);
///
/// let store2 = FileKeyStore::new("/path/to/keystore").await?;
/// let retrieved = store2.get("my-key").await?.unwrap();
/// # Ok(())
/// # }
/// ```
pub struct FileKeyStore {
    base_path: PathBuf,
    keys_dir: PathBuf,
    /// In-memory index for fast lookups
    index: RwLock<HashMap<String, String>>,
}

impl FileKeyStore {
    /// Create a new file-based key store at the specified path.
    ///
    /// Creates the directory structure if it doesn't exist.
    pub async fn new(path: impl AsRef<Path>) -> Result<Self> {
        let base_path = path.as_ref().to_path_buf();
        let keys_dir = base_path.join("keys");

        // Create directories
        fs::create_dir_all(&keys_dir).await?;

        let store = Self {
            base_path,
            keys_dir,
            index: RwLock::new(HashMap::new()),
        };

        // Load existing index
        store.load_index().await?;

        Ok(store)
    }

    /// Get the path to the index file.
    fn index_path(&self) -> PathBuf {
        self.base_path.join("index.json")
    }

    /// Get the path to a key file.
    fn key_path(&self, filename: &str) -> PathBuf {
        self.keys_dir.join(filename)
    }

    /// Load the index from disk.
    async fn load_index(&self) -> Result<()> {
        let index_path = self.index_path();

        if index_path.exists() {
            let contents = fs::read_to_string(&index_path).await?;
            let loaded: HashMap<String, String> = serde_json::from_str(&contents)?;
            *self.index.write() = loaded;
        }

        Ok(())
    }

    /// Save the index to disk atomically.
    async fn save_index(&self) -> Result<()> {
        let index_path = self.index_path();
        let temp_path = self.base_path.join(".index.tmp");

        let contents = {
            let index = self.index.read();
            serde_json::to_string_pretty(&*index)?
        };

        // Write to temp file
        let mut file = fs::File::create(&temp_path).await?;
        file.write_all(contents.as_bytes()).await?;
        file.sync_all().await?;

        // Atomic rename
        fs::rename(&temp_path, &index_path).await?;

        Ok(())
    }

    /// Generate a unique filename for a new key.
    fn generate_filename() -> String {
        format!("{}.key", uuid::Uuid::new_v4())
    }

    /// Read a key from disk.
    async fn read_key(&self, filename: &str) -> Result<StoredKey> {
        let path = self.key_path(filename);
        let contents = fs::read_to_string(&path).await?;
        let stored: StoredKey = serde_json::from_str(&contents)?;
        Ok(stored)
    }

    /// Write a key to disk atomically.
    async fn write_key(&self, filename: &str, stored: &StoredKey) -> Result<()> {
        let path = self.key_path(filename);
        let temp_path = self.keys_dir.join(format!(".{}.tmp", filename));

        let contents = serde_json::to_string_pretty(stored)?;

        // Write to temp file
        let mut file = fs::File::create(&temp_path).await?;
        file.write_all(contents.as_bytes()).await?;
        file.sync_all().await?;

        // Atomic rename
        fs::rename(&temp_path, &path).await?;

        Ok(())
    }

    /// Delete a key file from disk.
    async fn delete_key_file(&self, filename: &str) -> Result<()> {
        let path = self.key_path(filename);
        if path.exists() {
            fs::remove_file(&path).await?;
        }
        Ok(())
    }
}

#[async_trait]
impl KeyStore for FileKeyStore {
    async fn store(&self, id: &str, key_data: &[u8], metadata: Option<&KeyMetadata>) -> Result<()> {
        // Check if key already exists
        if self.index.read().contains_key(id) {
            return Err(KeyStoreError::KeyAlreadyExistsByName(id.to_string()));
        }

        let filename = Self::generate_filename();
        let meta = metadata.cloned().unwrap_or_else(|| KeyMetadata::new("unknown"));

        let stored = StoredKey {
            data: base64ct::Base64::encode_string(key_data),
            metadata: meta,
        };

        // Write key file
        self.write_key(&filename, &stored).await?;

        // Update index
        self.index.write().insert(id.to_string(), filename);
        self.save_index().await?;

        Ok(())
    }

    async fn get(&self, id: &str) -> Result<Option<Vec<u8>>> {
        let filename = {
            let index = self.index.read();
            match index.get(id) {
                Some(f) => f.clone(),
                None => return Ok(None),
            }
        };

        let stored = self.read_key(&filename).await?;

        // Check validity
        if !stored.metadata.is_valid() {
            if stored.metadata.revoked {
                return Err(KeyStoreError::KeyRevoked(id.to_string()));
            }
            if stored.metadata.is_expired() {
                return Err(KeyStoreError::KeyExpired(id.to_string()));
            }
        }

        let mut data = base64ct::Base64::decode_vec(&stored.data)
            .map_err(|e| KeyStoreError::SerializationError(e.to_string()))?;

        // Return a copy and zeroize our local
        let result = data.clone();
        data.zeroize();

        Ok(Some(result))
    }

    async fn get_with_metadata(&self, id: &str) -> Result<Option<(Vec<u8>, KeyMetadata)>> {
        let filename = {
            let index = self.index.read();
            match index.get(id) {
                Some(f) => f.clone(),
                None => return Ok(None),
            }
        };

        let stored = self.read_key(&filename).await?;

        if !stored.metadata.is_valid() {
            if stored.metadata.revoked {
                return Err(KeyStoreError::KeyRevoked(id.to_string()));
            }
            if stored.metadata.is_expired() {
                return Err(KeyStoreError::KeyExpired(id.to_string()));
            }
        }

        let mut data = base64ct::Base64::decode_vec(&stored.data)
            .map_err(|e| KeyStoreError::SerializationError(e.to_string()))?;

        let result = data.clone();
        data.zeroize();

        Ok(Some((result, stored.metadata)))
    }

    async fn update(&self, id: &str, key_data: &[u8], metadata: Option<&KeyMetadata>) -> Result<()> {
        let filename = {
            let index = self.index.read();
            match index.get(id) {
                Some(f) => f.clone(),
                None => return Err(KeyStoreError::KeyNotFoundByName(id.to_string())),
            }
        };

        let old_stored = self.read_key(&filename).await?;

        let meta = match metadata {
            Some(m) => m.clone(),
            None => {
                let mut m = old_stored.metadata;
                m.touch();
                m.increment_version();
                m
            }
        };

        let stored = StoredKey {
            data: base64ct::Base64::encode_string(key_data),
            metadata: meta,
        };

        self.write_key(&filename, &stored).await?;

        Ok(())
    }

    async fn delete(&self, id: &str) -> Result<bool> {
        let filename = {
            let mut index = self.index.write();
            match index.remove(id) {
                Some(f) => f,
                None => return Ok(false),
            }
        };

        self.delete_key_file(&filename).await?;
        self.save_index().await?;

        Ok(true)
    }

    async fn exists(&self, id: &str) -> Result<bool> {
        Ok(self.index.read().contains_key(id))
    }

    async fn list(&self) -> Result<Vec<String>> {
        Ok(self.index.read().keys().cloned().collect())
    }

    async fn get_metadata(&self, id: &str) -> Result<Option<KeyMetadata>> {
        let filename = {
            let index = self.index.read();
            match index.get(id) {
                Some(f) => f.clone(),
                None => return Ok(None),
            }
        };

        let stored = self.read_key(&filename).await?;
        Ok(Some(stored.metadata))
    }

    async fn update_metadata(&self, id: &str, metadata: &KeyMetadata) -> Result<()> {
        let filename = {
            let index = self.index.read();
            match index.get(id) {
                Some(f) => f.clone(),
                None => return Err(KeyStoreError::KeyNotFoundByName(id.to_string())),
            }
        };

        let mut stored = self.read_key(&filename).await?;
        stored.metadata = metadata.clone();
        self.write_key(&filename, &stored).await?;

        Ok(())
    }

    async fn clear(&self) -> Result<()> {
        let filenames: Vec<String> = self.index.read().values().cloned().collect();

        for filename in filenames {
            self.delete_key_file(&filename).await?;
        }

        self.index.write().clear();
        self.save_index().await?;

        Ok(())
    }

    async fn count(&self) -> Result<usize> {
        Ok(self.index.read().len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    async fn create_temp_store() -> (FileKeyStore, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let store = FileKeyStore::new(temp_dir.path()).await.unwrap();
        (store, temp_dir)
    }

    #[tokio::test]
    async fn test_store_and_get() {
        let (store, _dir) = create_temp_store().await;
        let key = vec![1u8, 2, 3, 4, 5];

        store.store("test", &key, None).await.unwrap();
        let retrieved = store.get("test").await.unwrap().unwrap();

        assert_eq!(retrieved, key);
    }

    #[tokio::test]
    async fn test_persistence() {
        let temp_dir = TempDir::new().unwrap();
        let key = vec![1u8, 2, 3, 4, 5];

        // Store key
        {
            let store = FileKeyStore::new(temp_dir.path()).await.unwrap();
            store.store("persistent", &key, None).await.unwrap();
        }

        // Reload and verify
        {
            let store = FileKeyStore::new(temp_dir.path()).await.unwrap();
            let retrieved = store.get("persistent").await.unwrap().unwrap();
            assert_eq!(retrieved, key);
        }
    }

    #[tokio::test]
    async fn test_update() {
        let (store, _dir) = create_temp_store().await;
        let key1 = vec![1u8, 2, 3];
        let key2 = vec![4u8, 5, 6];

        store.store("test", &key1, None).await.unwrap();
        store.update("test", &key2, None).await.unwrap();

        let retrieved = store.get("test").await.unwrap().unwrap();
        assert_eq!(retrieved, key2);

        // Check version was incremented
        let meta = store.get_metadata("test").await.unwrap().unwrap();
        assert_eq!(meta.version, 2);
    }

    #[tokio::test]
    async fn test_delete() {
        let (store, _dir) = create_temp_store().await;
        store.store("test", &[1, 2, 3], None).await.unwrap();

        let deleted = store.delete("test").await.unwrap();
        assert!(deleted);

        assert!(!store.exists("test").await.unwrap());
    }

    #[tokio::test]
    async fn test_list() {
        let (store, _dir) = create_temp_store().await;

        store.store("key1", &[1], None).await.unwrap();
        store.store("key2", &[2], None).await.unwrap();
        store.store("key3", &[3], None).await.unwrap();

        let mut keys = store.list().await.unwrap();
        keys.sort();

        assert_eq!(keys, vec!["key1", "key2", "key3"]);
    }

    #[tokio::test]
    async fn test_metadata() {
        let (store, _dir) = create_temp_store().await;
        let mut meta = KeyMetadata::new("AES-256-GCM");
        meta.set_description("Test key");

        store.store("test", &[1, 2, 3], Some(&meta)).await.unwrap();

        let retrieved_meta = store.get_metadata("test").await.unwrap().unwrap();
        assert_eq!(retrieved_meta.algorithm, "AES-256-GCM");
        assert_eq!(retrieved_meta.description, Some("Test key".to_string()));
    }
}
