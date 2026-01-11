//! Storage backend trait and batch operations.
//!
//! ## Example
//! ```rust,ignore
//! use lib_storage::backend::{BatchOp, StorageBackend, StorageKey};
//!
//! async fn write_pair<B: StorageBackend>(backend: &B) -> anyhow::Result<()> {
//!     backend.put(b"key", b"value").await?;
//!     backend.write_batch(vec![
//!         BatchOp::Put { key: StorageKey::from(b"a".as_slice()), value: b"1".to_vec() },
//!         BatchOp::Delete { key: StorageKey::from(b"old".as_slice()) },
//!     ]).await?;
//!     backend.flush().await?;
//!     Ok(())
//! }
//! ```

use anyhow::Result;
use async_trait::async_trait;

/// Owned storage key for backend operations.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StorageKey(Vec<u8>);

impl StorageKey {
    /// Create a key from raw bytes.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Borrow key bytes.
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Convert into owned bytes.
    pub fn into_inner(self) -> Vec<u8> {
        self.0
    }
}

impl From<Vec<u8>> for StorageKey {
    fn from(bytes: Vec<u8>) -> Self {
        Self::new(bytes)
    }
}

impl From<&[u8]> for StorageKey {
    fn from(bytes: &[u8]) -> Self {
        Self::new(bytes.to_vec())
    }
}

impl AsRef<[u8]> for StorageKey {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

/// Batch operations for atomic writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BatchOp {
    /// Insert or overwrite a key-value pair.
    Put { key: StorageKey, value: Vec<u8> },
    /// Remove a key.
    Delete { key: StorageKey },
}

/// Optional backend stats for observability.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BackendStats {
    /// Total number of entries, if known.
    pub entries: Option<usize>,
    /// Total bytes stored, if known.
    pub bytes: Option<u64>,
    /// Last durable flush time as unix epoch seconds, if known.
    pub last_flush_unix: Option<u64>,
}

/// Async storage backend abstraction.
#[async_trait]
pub trait StorageBackend: Send + Sync {
    /// Store a key-value pair.
    async fn put(&self, key: &[u8], value: &[u8]) -> Result<()>;

    /// Retrieve a value by key.
    async fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>>;

    /// Delete a key.
    async fn delete(&self, key: &[u8]) -> Result<()>;

    /// Check if key exists.
    async fn contains(&self, key: &[u8]) -> Result<bool>;

    /// Iterate over keys with prefix.
    ///
    /// Implementations should return keys in lexicographic order and may impose
    /// internal limits; callers must not rely on unbounded result sizes.
    async fn scan_prefix(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>>;

    /// Batch write operations.
    ///
    /// Implementations must apply operations in order and atomically.
    async fn write_batch(&self, ops: Vec<BatchOp>) -> Result<()>;

    /// Flush to disk.
    ///
    /// Implementations must ensure durability guarantees consistent with the backend.
    async fn flush(&self) -> Result<()>;

    /// Number of entries, if supported.
    async fn len(&self) -> Result<usize>;

    /// Whether the backend is empty.
    async fn is_empty(&self) -> Result<bool> {
        Ok(self.len().await? == 0)
    }

    /// Backend stats for observability.
    async fn stats(&self) -> Result<BackendStats>;
}
