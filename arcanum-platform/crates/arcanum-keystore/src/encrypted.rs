//! Encrypted key storage backend.
//!
//! This backend wraps another keystore and encrypts all key data
//! before storage using AES-256-GCM.
//!
//! Best used for:
//! - Production deployments requiring encryption at rest
//! - Compliance requirements
//! - Sensitive key material

use crate::error::{KeyStoreError, Result};
use crate::metadata::KeyMetadata;
use crate::traits::KeyStore;
use arcanum_symmetric::prelude::*;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Master key for encrypting stored keys.
#[derive(Clone, ZeroizeOnDrop)]
pub struct MasterKey {
    key: Vec<u8>,
}

impl MasterKey {
    /// Create a master key from raw bytes.
    ///
    /// # Arguments
    ///
    /// * `key` - 32 bytes for AES-256-GCM
    ///
    /// # Errors
    ///
    /// Returns an error if the key is not exactly 32 bytes.
    pub fn from_bytes(key: &[u8]) -> Result<Self> {
        if key.len() != 32 {
            return Err(KeyStoreError::InvalidMetadata(format!(
                "master key must be 32 bytes, got {}",
                key.len()
            )));
        }
        Ok(Self { key: key.to_vec() })
    }

    /// Generate a random master key.
    pub fn generate() -> Self {
        Self {
            key: Aes256Gcm::generate_key(),
        }
    }

    /// Derive a master key from a password using Argon2id.
    ///
    /// # Arguments
    ///
    /// * `password` - The password to derive from
    /// * `salt` - A unique salt (at least 16 bytes recommended)
    pub fn from_password(password: &[u8], salt: &[u8]) -> Result<Self> {
        use arcanum_hash::{Argon2, Argon2Params, PasswordHash};

        let params = Argon2Params::default();
        let derived = Argon2::derive_key(password, salt, &params, 32)
            .map_err(|e| KeyStoreError::CryptoError(e))?;

        Ok(Self { key: derived })
    }

    /// Export the master key bytes.
    ///
    /// # Warning
    ///
    /// Handle with extreme care. This exposes the raw key material.
    pub fn expose(&self) -> &[u8] {
        &self.key
    }
}

/// Encrypted data format.
#[derive(Serialize, Deserialize)]
struct EncryptedBlob {
    /// Nonce used for encryption
    nonce: Vec<u8>,
    /// Encrypted ciphertext
    ciphertext: Vec<u8>,
}

/// Encrypted key storage backend.
///
/// Wraps any `KeyStore` implementation and encrypts all key data
/// before passing to the underlying store.
///
/// # Encryption
///
/// Uses AES-256-GCM with random nonces. Each key is encrypted
/// independently with a unique nonce.
///
/// # Example
///
/// ```rust,no_run
/// use arcanum_keystore::{EncryptedKeyStore, MemoryKeyStore, MasterKey, KeyStore};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Create backing store
/// let backing = MemoryKeyStore::new();
///
/// // Create or load master key
/// let master_key = MasterKey::generate();
///
/// // Create encrypted store
/// let store = EncryptedKeyStore::new(backing, master_key);
///
/// // Use like any other keystore
/// let secret = vec![0u8; 32];
/// store.store("my-key", &secret, None).await?;
///
/// let retrieved = store.get("my-key").await?.unwrap();
/// assert_eq!(retrieved, secret);
/// # Ok(())
/// # }
/// ```
///
/// ## With Password-Derived Key
///
/// ```rust,no_run
/// use arcanum_keystore::{EncryptedKeyStore, FileKeyStore, MasterKey, KeyStore};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let backing = FileKeyStore::new("/path/to/keystore").await?;
///
/// // Derive master key from password
/// let salt = b"unique-application-salt";
/// let master_key = MasterKey::from_password(b"user-password", salt)?;
///
/// let store = EncryptedKeyStore::new(backing, master_key);
/// # Ok(())
/// # }
/// ```
pub struct EncryptedKeyStore<S: KeyStore> {
    inner: Arc<S>,
    master_key: MasterKey,
}

impl<S: KeyStore> EncryptedKeyStore<S> {
    /// Create a new encrypted keystore wrapping the given backing store.
    ///
    /// # Arguments
    ///
    /// * `backing` - The underlying keystore to use for storage
    /// * `master_key` - The master key for encryption/decryption
    pub fn new(backing: S, master_key: MasterKey) -> Self {
        Self {
            inner: Arc::new(backing),
            master_key,
        }
    }

    /// Encrypt data using the master key.
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let nonce = Aes256Gcm::generate_nonce();

        let ciphertext = Aes256Gcm::encrypt(
            self.master_key.expose(),
            &nonce,
            plaintext,
            None,
        ).map_err(|e| KeyStoreError::EncryptionError(e.to_string()))?;

        let blob = EncryptedBlob { nonce, ciphertext };
        let serialized = bincode::serialize(&blob)
            .map_err(|e| KeyStoreError::SerializationError(e.to_string()))?;

        Ok(serialized)
    }

    /// Decrypt data using the master key.
    fn decrypt(&self, encrypted: &[u8]) -> Result<Vec<u8>> {
        let blob: EncryptedBlob = bincode::deserialize(encrypted)
            .map_err(|e| KeyStoreError::SerializationError(e.to_string()))?;

        let plaintext = Aes256Gcm::decrypt(
            self.master_key.expose(),
            &blob.nonce,
            &blob.ciphertext,
            None,
        ).map_err(|e| KeyStoreError::DecryptionError(e.to_string()))?;

        Ok(plaintext)
    }
}

#[async_trait]
impl<S: KeyStore + 'static> KeyStore for EncryptedKeyStore<S> {
    async fn store(&self, id: &str, key_data: &[u8], metadata: Option<&KeyMetadata>) -> Result<()> {
        let encrypted = self.encrypt(key_data)?;
        self.inner.store(id, &encrypted, metadata).await
    }

    async fn get(&self, id: &str) -> Result<Option<Vec<u8>>> {
        match self.inner.get(id).await? {
            Some(encrypted) => {
                let mut plaintext = self.decrypt(&encrypted)?;
                let result = plaintext.clone();
                plaintext.zeroize();
                Ok(Some(result))
            }
            None => Ok(None),
        }
    }

    async fn get_with_metadata(&self, id: &str) -> Result<Option<(Vec<u8>, KeyMetadata)>> {
        match self.inner.get_with_metadata(id).await? {
            Some((encrypted, metadata)) => {
                let mut plaintext = self.decrypt(&encrypted)?;
                let result = plaintext.clone();
                plaintext.zeroize();
                Ok(Some((result, metadata)))
            }
            None => Ok(None),
        }
    }

    async fn update(&self, id: &str, key_data: &[u8], metadata: Option<&KeyMetadata>) -> Result<()> {
        let encrypted = self.encrypt(key_data)?;
        self.inner.update(id, &encrypted, metadata).await
    }

    async fn delete(&self, id: &str) -> Result<bool> {
        self.inner.delete(id).await
    }

    async fn exists(&self, id: &str) -> Result<bool> {
        self.inner.exists(id).await
    }

    async fn list(&self) -> Result<Vec<String>> {
        self.inner.list().await
    }

    async fn get_metadata(&self, id: &str) -> Result<Option<KeyMetadata>> {
        self.inner.get_metadata(id).await
    }

    async fn update_metadata(&self, id: &str, metadata: &KeyMetadata) -> Result<()> {
        self.inner.update_metadata(id, metadata).await
    }

    async fn clear(&self) -> Result<()> {
        self.inner.clear().await
    }

    async fn count(&self) -> Result<usize> {
        self.inner.count().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MemoryKeyStore;

    #[tokio::test]
    async fn test_encrypt_decrypt() {
        let backing = MemoryKeyStore::new();
        let master_key = MasterKey::generate();
        let store = EncryptedKeyStore::new(backing, master_key);

        let key = vec![1u8, 2, 3, 4, 5, 6, 7, 8];

        store.store("test", &key, None).await.unwrap();
        let retrieved = store.get("test").await.unwrap().unwrap();

        assert_eq!(retrieved, key);
    }

    #[tokio::test]
    async fn test_data_is_encrypted() {
        let backing = MemoryKeyStore::new();
        let master_key = MasterKey::generate();
        let store = EncryptedKeyStore::new(backing, master_key);

        let key = vec![1u8, 2, 3, 4, 5];
        store.store("test", &key, None).await.unwrap();

        // Access the raw stored data through the backing store
        let raw = store.inner.get("test").await.unwrap().unwrap();

        // Raw data should NOT equal plaintext (it's encrypted)
        assert_ne!(raw, key);
        assert!(raw.len() > key.len()); // Encrypted data is larger
    }

    #[tokio::test]
    async fn test_wrong_key_fails() {
        let backing = MemoryKeyStore::new();
        let master_key = MasterKey::generate();
        let store = EncryptedKeyStore::new(backing, master_key);

        let key = vec![1u8, 2, 3, 4, 5];
        store.store("test", &key, None).await.unwrap();

        // Try to decrypt with different master key
        let wrong_key = MasterKey::generate();
        let store2 = EncryptedKeyStore {
            inner: store.inner.clone(),
            master_key: wrong_key,
        };

        let result = store2.get("test").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_password_derived_key() {
        let backing = MemoryKeyStore::new();
        let password = b"my-secure-password";
        let salt = b"unique-salt-12345678";

        let master_key = MasterKey::from_password(password, salt).unwrap();
        let store = EncryptedKeyStore::new(backing, master_key);

        let key = vec![42u8; 32];
        store.store("derived", &key, None).await.unwrap();

        // Derive same key from password and verify
        let master_key2 = MasterKey::from_password(password, salt).unwrap();
        let store2 = EncryptedKeyStore {
            inner: store.inner.clone(),
            master_key: master_key2,
        };

        let retrieved = store2.get("derived").await.unwrap().unwrap();
        assert_eq!(retrieved, key);
    }

    #[tokio::test]
    async fn test_metadata_preserved() {
        let backing = MemoryKeyStore::new();
        let master_key = MasterKey::generate();
        let store = EncryptedKeyStore::new(backing, master_key);

        let mut meta = KeyMetadata::new("AES-256-GCM");
        meta.set_description("Test encrypted key");

        store.store("test", &[1, 2, 3], Some(&meta)).await.unwrap();

        let retrieved_meta = store.get_metadata("test").await.unwrap().unwrap();
        assert_eq!(retrieved_meta.algorithm, "AES-256-GCM");
        assert_eq!(retrieved_meta.description, Some("Test encrypted key".to_string()));
    }

    #[tokio::test]
    async fn test_list_and_delete() {
        let backing = MemoryKeyStore::new();
        let master_key = MasterKey::generate();
        let store = EncryptedKeyStore::new(backing, master_key);

        store.store("key1", &[1], None).await.unwrap();
        store.store("key2", &[2], None).await.unwrap();

        assert_eq!(store.count().await.unwrap(), 2);

        let deleted = store.delete("key1").await.unwrap();
        assert!(deleted);

        assert_eq!(store.count().await.unwrap(), 1);
        assert!(!store.exists("key1").await.unwrap());
        assert!(store.exists("key2").await.unwrap());
    }

    #[tokio::test]
    async fn test_invalid_master_key_length() {
        let result = MasterKey::from_bytes(&[0u8; 16]); // Too short
        assert!(result.is_err());

        let result = MasterKey::from_bytes(&[0u8; 32]); // Correct
        assert!(result.is_ok());
    }
}
