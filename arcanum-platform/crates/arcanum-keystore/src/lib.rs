//! # Arcanum Keystore
//!
//! Secure key storage backends for the Arcanum cryptographic engine.
//!
//! This crate provides multiple storage backends for cryptographic keys:
//!
//! ## Storage Backends
//!
//! - **Memory**: In-memory storage for ephemeral keys (testing, short-lived sessions)
//! - **File**: File-based storage with atomic writes and locking
//! - **Encrypted**: Encrypted storage using Arcanum symmetric encryption
//!
//! ## Example
//!
//! ```rust,no_run
//! use arcanum_keystore::{MemoryKeyStore, KeyStore, KeyMetadata};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let store = MemoryKeyStore::new();
//!
//!     // Store a key
//!     let key_data = vec![0u8; 32]; // Your secret key
//!     let metadata = KeyMetadata::new("aes-256-gcm");
//!     store.store("my-key", &key_data, Some(&metadata)).await?;
//!
//!     // Retrieve the key
//!     let retrieved = store.get("my-key").await?;
//!     assert!(retrieved.is_some());
//!
//!     // List all keys
//!     let keys = store.list().await?;
//!     assert_eq!(keys.len(), 1);
//!
//!     // Delete the key
//!     store.delete("my-key").await?;
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Security Considerations
//!
//! - Memory keystore data is zeroized on drop
//! - File keystore uses atomic writes to prevent corruption
//! - Encrypted keystore provides encryption at rest
//! - All backends support key metadata for lifecycle management

#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

mod error;
mod traits;
mod metadata;

#[cfg(feature = "memory")]
mod memory;

#[cfg(feature = "file")]
mod file;

#[cfg(feature = "encrypted")]
mod encrypted;

pub use error::{KeyStoreError, Result};
pub use traits::KeyStore;
pub use metadata::KeyMetadata;

#[cfg(feature = "memory")]
pub use memory::MemoryKeyStore;

#[cfg(feature = "file")]
pub use file::FileKeyStore;

#[cfg(feature = "encrypted")]
pub use encrypted::{EncryptedKeyStore, MasterKey};

/// Prelude for convenient imports.
pub mod prelude {
    pub use crate::error::{KeyStoreError, Result};
    pub use crate::traits::KeyStore;
    pub use crate::metadata::KeyMetadata;

    #[cfg(feature = "memory")]
    pub use crate::memory::MemoryKeyStore;

    #[cfg(feature = "file")]
    pub use crate::file::FileKeyStore;

    #[cfg(feature = "encrypted")]
    pub use crate::encrypted::{EncryptedKeyStore, MasterKey};
}
