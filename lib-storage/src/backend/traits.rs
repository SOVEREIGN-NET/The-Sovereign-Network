//! Storage backend trait and batch operations.
//!
//! ## Example
//! ```rust,ignore
//! use lib_storage::backend::{BatchOp, StorageBackend};
//!
//! async fn write_pair<B: StorageBackend>(backend: &B) -> anyhow::Result<()> {
//!     backend.put(b"key", b"value").await?;
//!     backend.write_batch(vec![
//!         BatchOp::Put { key: b"a".to_vec(), value: b"1".to_vec() },
//!         BatchOp::Delete { key: b"old".to_vec() },
//!     ]).await?;
//!     backend.flush().await?;
//!     Ok(())
//! }
//! ```

use anyhow::Result;
use async_trait::async_trait;

/// Batch operations for atomic writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BatchOp {
    /// Insert or overwrite a key-value pair.
    Put { key: Vec<u8>, value: Vec<u8> },
    /// Remove a key.
    Delete { key: Vec<u8> },
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
    async fn scan_prefix(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>>;

    /// Batch write operations.
    async fn write_batch(&self, ops: Vec<BatchOp>) -> Result<()>;

    /// Flush to disk.
    async fn flush(&self) -> Result<()>;
}
