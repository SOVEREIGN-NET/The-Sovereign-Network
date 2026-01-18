//! Sled-based storage backend implementation
//!
//! Provides a production-ready key-value storage backend using sled,
//! an embedded database with automatic compression and crash safety.
//!
//! # Features
//!
//! - Async-compatible API using spawn_blocking for I/O operations
//! - Namespaced trees for logical data separation
//! - Batch operations for atomic writes
//! - Prefix scanning with configurable limits
//! - Compare-and-swap for atomic updates
//! - Automatic compression and crash recovery
//!
//! # Security
//!
//! - Key/value size limits prevent resource exhaustion
//! - Tree name validation prevents injection
//! - Bounded scan operations prevent OOM

use async_trait::async_trait;
use std::path::Path;
use thiserror::Error;
use tracing::{debug, info, warn, error};

// ============================================================================
// Error Types
// ============================================================================

/// Storage backend errors
#[derive(Debug, Error)]
pub enum StorageError {
    /// Database failed to open
    #[error("Database open failed: {0}")]
    OpenFailed(String),

    /// Write operation failed
    #[error("Write failed: {0}")]
    WriteFailed(String),

    /// Read operation failed
    #[error("Read failed: {0}")]
    ReadFailed(String),

    /// Delete operation failed
    #[error("Delete failed: {0}")]
    DeleteFailed(String),

    /// Batch operation failed
    #[error("Batch operation failed: {0}")]
    BatchFailed(String),

    /// Scan operation failed
    #[error("Scan failed: {0}")]
    ScanFailed(String),

    /// Flush operation failed
    #[error("Flush failed: {0}")]
    FlushFailed(String),

    /// Tree operation failed
    #[error("Tree operation failed: {0}")]
    TreeFailed(String),

    /// Compare-and-swap failed due to value mismatch
    #[error("Compare-and-swap conflict: value was modified")]
    CasConflict,

    /// Key exceeds maximum allowed size
    #[error("Key exceeds maximum size of {max} bytes (got {actual})")]
    KeyTooLarge { max: usize, actual: usize },

    /// Value exceeds maximum allowed size
    #[error("Value exceeds maximum size of {max} bytes (got {actual})")]
    ValueTooLarge { max: usize, actual: usize },

    /// Empty key not allowed
    #[error("Empty keys are not allowed")]
    EmptyKey,

    /// Invalid tree name
    #[error("Invalid tree name: {0}")]
    InvalidTreeName(String),

    /// Batch exceeds limits
    #[error("Batch exceeds limits: {0}")]
    BatchTooLarge(String),

    /// Task execution failed
    #[error("Task execution failed: {0}")]
    TaskFailed(String),
}

/// Result type for storage operations
pub type Result<T> = std::result::Result<T, StorageError>;

// ============================================================================
// Constants
// ============================================================================

/// Maximum key size (256 bytes - sufficient for 32-byte hashes with prefixes)
pub const MAX_KEY_SIZE: usize = 256;

/// Maximum value size (10 MB)
pub const MAX_VALUE_SIZE: usize = 10 * 1024 * 1024;

/// Maximum tree name length
pub const MAX_TREE_NAME_LENGTH: usize = 64;

/// Maximum operations per batch
pub const MAX_BATCH_OPS: usize = 10_000;

/// Maximum total batch size in bytes
pub const MAX_BATCH_SIZE: usize = 100 * 1024 * 1024; // 100 MB

/// Default scan limit
pub const DEFAULT_SCAN_LIMIT: usize = 10_000;

/// Default cache capacity (64 MB)
pub const DEFAULT_CACHE_CAPACITY: u64 = 64 * 1024 * 1024;

// ============================================================================
// Batch Operations
// ============================================================================

/// Batch operation for atomic writes
#[derive(Debug, Clone)]
pub enum BatchOp {
    /// Insert or update a key-value pair
    Put { key: Vec<u8>, value: Vec<u8> },
    /// Delete a key
    Delete { key: Vec<u8> },
}

impl BatchOp {
    /// Get the size of this operation in bytes
    fn size(&self) -> usize {
        match self {
            BatchOp::Put { key, value } => key.len() + value.len(),
            BatchOp::Delete { key } => key.len(),
        }
    }
}

// ============================================================================
// Storage Backend Trait
// ============================================================================

/// Core storage backend trait
///
/// Defines the interface for persistent key-value storage operations.
/// All methods are async and use spawn_blocking internally for I/O.
///
/// # Thread Safety
///
/// All implementations must be `Send + Sync` and safe for concurrent access.
///
/// # Error Handling
///
/// Operations return `StorageError` variants for specific failure modes.
#[async_trait]
pub trait StorageBackend: Send + Sync {
    /// Insert or update a key-value pair
    ///
    /// # Errors
    /// - `StorageError::EmptyKey` if key is empty
    /// - `StorageError::KeyTooLarge` if key exceeds MAX_KEY_SIZE
    /// - `StorageError::ValueTooLarge` if value exceeds MAX_VALUE_SIZE
    /// - `StorageError::WriteFailed` on database error
    async fn put(&self, key: &[u8], value: &[u8]) -> Result<()>;

    /// Get a value by key
    ///
    /// Returns `None` if the key does not exist.
    ///
    /// # Errors
    /// - `StorageError::EmptyKey` if key is empty
    /// - `StorageError::KeyTooLarge` if key exceeds MAX_KEY_SIZE
    /// - `StorageError::ReadFailed` on database error
    async fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>>;

    /// Delete a key
    ///
    /// No error is returned if the key does not exist.
    ///
    /// # Errors
    /// - `StorageError::EmptyKey` if key is empty
    /// - `StorageError::KeyTooLarge` if key exceeds MAX_KEY_SIZE
    /// - `StorageError::DeleteFailed` on database error
    async fn delete(&self, key: &[u8]) -> Result<()>;

    /// Check if a key exists
    ///
    /// # Errors
    /// - `StorageError::EmptyKey` if key is empty
    /// - `StorageError::KeyTooLarge` if key exceeds MAX_KEY_SIZE
    /// - `StorageError::ReadFailed` on database error
    async fn contains(&self, key: &[u8]) -> Result<bool>;

    /// Scan all keys with a given prefix, up to a limit
    ///
    /// # Arguments
    /// * `prefix` - Key prefix to match
    /// * `limit` - Maximum number of results (defaults to DEFAULT_SCAN_LIMIT)
    ///
    /// # Errors
    /// - `StorageError::ScanFailed` on database error
    async fn scan_prefix(&self, prefix: &[u8], limit: Option<usize>) -> Result<Vec<(Vec<u8>, Vec<u8>)>>;

    /// Execute a batch of operations atomically
    ///
    /// # Errors
    /// - `StorageError::BatchTooLarge` if batch exceeds limits
    /// - `StorageError::BatchFailed` on database error
    async fn write_batch(&self, ops: &[BatchOp]) -> Result<()>;

    /// Atomically compare and swap a value
    ///
    /// If the current value matches `expected`, replace it with `new`.
    /// Returns `Ok(())` if the swap succeeded, `Err(StorageError::CasConflict)` if
    /// the current value did not match expected.
    ///
    /// # Arguments
    /// * `key` - The key to update
    /// * `expected` - Expected current value (None means key should not exist)
    /// * `new` - New value to set (None means delete the key)
    ///
    /// # Errors
    /// - `StorageError::CasConflict` if current value doesn't match expected
    /// - `StorageError::WriteFailed` on database error
    async fn compare_and_swap(
        &self,
        key: &[u8],
        expected: Option<&[u8]>,
        new: Option<&[u8]>,
    ) -> Result<()>;

    /// Flush all pending writes to disk
    ///
    /// # Errors
    /// - `StorageError::FlushFailed` on database error
    async fn flush(&self) -> Result<()>;
}

// ============================================================================
// Key Validation
// ============================================================================

/// Validate a key
fn validate_key(key: &[u8]) -> Result<()> {
    if key.is_empty() {
        return Err(StorageError::EmptyKey);
    }
    if key.len() > MAX_KEY_SIZE {
        return Err(StorageError::KeyTooLarge {
            max: MAX_KEY_SIZE,
            actual: key.len(),
        });
    }
    Ok(())
}

/// Validate a value
fn validate_value(value: &[u8]) -> Result<()> {
    if value.len() > MAX_VALUE_SIZE {
        return Err(StorageError::ValueTooLarge {
            max: MAX_VALUE_SIZE,
            actual: value.len(),
        });
    }
    Ok(())
}

/// Validate a tree name
fn validate_tree_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(StorageError::InvalidTreeName(
            "Tree name cannot be empty".to_string(),
        ));
    }
    if name.len() > MAX_TREE_NAME_LENGTH {
        return Err(StorageError::InvalidTreeName(format!(
            "Tree name exceeds {} characters",
            MAX_TREE_NAME_LENGTH
        )));
    }
    if !name.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-') {
        return Err(StorageError::InvalidTreeName(
            "Tree name must contain only alphanumeric characters, underscores, or hyphens".to_string(),
        ));
    }
    Ok(())
}

/// Validate batch operations
fn validate_batch(ops: &[BatchOp]) -> Result<()> {
    if ops.len() > MAX_BATCH_OPS {
        return Err(StorageError::BatchTooLarge(format!(
            "Batch has {} operations, max is {}",
            ops.len(),
            MAX_BATCH_OPS
        )));
    }

    let total_size: usize = ops.iter().map(|op| op.size()).sum();
    if total_size > MAX_BATCH_SIZE {
        return Err(StorageError::BatchTooLarge(format!(
            "Batch size {} bytes exceeds max {} bytes",
            total_size, MAX_BATCH_SIZE
        )));
    }

    // Validate individual keys and values
    for op in ops {
        match op {
            BatchOp::Put { key, value } => {
                validate_key(key)?;
                validate_value(value)?;
            }
            BatchOp::Delete { key } => {
                validate_key(key)?;
            }
        }
    }

    Ok(())
}

// ============================================================================
// Sled Backend Implementation
// ============================================================================

/// Sled-based storage backend
///
/// Production-ready implementation using sled embedded database.
/// Supports multiple named trees for logical data separation.
///
/// # Example
///
/// ```ignore
/// let backend = SledBackend::open("./data/storage")?;
/// let dht_tree = backend.open_tree("dht")?;
/// dht_tree.put(b"key", b"value").await?;
/// ```
#[derive(Clone, Debug)]
pub struct SledBackend {
    db: sled::Db,
}

impl SledBackend {
    /// Open or create a sled database at the given path
    ///
    /// # Arguments
    ///
    /// * `path` - Directory path for the database files
    ///
    /// # Configuration
    ///
    /// Uses tuned settings for general-purpose storage:
    /// - 64 MB page cache
    /// - High throughput mode for write-heavy workloads
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        Self::open_with_config(path, DEFAULT_CACHE_CAPACITY)
    }

    /// Open or create a sled database with custom cache capacity
    ///
    /// # Arguments
    ///
    /// * `path` - Directory path for the database files
    /// * `cache_capacity` - Page cache size in bytes
    ///
    /// # Auto-Recovery
    ///
    /// If sled database is corrupted, automatically clears and recreates it.
    /// Data will be lost, but the node can restart. DHT data will be
    /// re-synchronized from peers.
    pub fn open_with_config<P: AsRef<Path>>(path: P, cache_capacity: u64) -> Result<Self> {
        let db = match sled::Config::default()
            .path(path.as_ref())
            .cache_capacity(cache_capacity)
            .mode(sled::Mode::HighThroughput)
            .open()
        {
            Ok(db) => db,
            Err(e) => {
                let err_str = e.to_string().to_lowercase();
                // Detect corruption indicators in error message
                if err_str.contains("corrupt") || err_str.contains("crc")
                   || err_str.contains("checksum") || err_str.contains("invalid") {
                    warn!(
                        "SLED CORRUPTION DETECTED at {:?}: {}. \
                         Auto-recovering by clearing corrupted database.",
                        path.as_ref(), e
                    );

                    // Clear the corrupted database
                    if let Err(rm_err) = std::fs::remove_dir_all(path.as_ref()) {
                        error!(
                            "Failed to remove corrupted sled database at {:?}: {}. \
                             Manual intervention required.",
                            path.as_ref(), rm_err
                        );
                        return Err(StorageError::OpenFailed(format!(
                            "Sled database corrupted and auto-recovery failed: {}. \
                             Original error: {}. Please manually delete {:?}",
                            rm_err, e, path.as_ref()
                        )));
                    }

                    info!(
                        "Cleared corrupted sled database at {:?}. Recreating fresh database.",
                        path.as_ref()
                    );

                    // Ensure parent directory exists for recreation
                    if let Some(parent) = path.as_ref().parent() {
                        let _ = std::fs::create_dir_all(parent);
                    }

                    // Retry opening
                    sled::Config::default()
                        .path(path.as_ref())
                        .cache_capacity(cache_capacity)
                        .mode(sled::Mode::HighThroughput)
                        .open()
                        .map_err(|e2| StorageError::OpenFailed(format!(
                            "Failed to recreate sled database after corruption recovery: {}",
                            e2
                        )))?
                } else {
                    // Non-corruption error - fail immediately
                    return Err(StorageError::OpenFailed(e.to_string()));
                }
            }
        };

        info!(
            "Opened sled database at {:?} with {}MB cache",
            path.as_ref(),
            cache_capacity / (1024 * 1024)
        );
        Ok(Self { db })
    }

    /// Open a named tree for namespaced storage
    ///
    /// Trees provide logical separation of data within the same database.
    /// Each tree has its own keyspace.
    ///
    /// # Arguments
    ///
    /// * `name` - Name of the tree (alphanumeric, underscore, hyphen only, max 64 chars)
    ///
    /// # Errors
    ///
    /// - `StorageError::InvalidTreeName` if name is invalid
    /// - `StorageError::TreeFailed` on database error
    pub fn open_tree(&self, name: &str) -> Result<SledTree> {
        validate_tree_name(name)?;

        let tree = self.db
            .open_tree(name)
            .map_err(|e| StorageError::TreeFailed(e.to_string()))?;

        debug!("Opened sled tree: {}", name);
        Ok(SledTree {
            tree,
            name: name.to_string(),
        })
    }

    /// Get database size on disk (approximate)
    pub fn size_on_disk(&self) -> Result<u64> {
        self.db
            .size_on_disk()
            .map_err(|e| StorageError::ReadFailed(e.to_string()))
    }

    /// Flush all pending writes to disk (synchronous)
    pub fn flush_sync(&self) -> Result<()> {
        self.db
            .flush()
            .map_err(|e| StorageError::FlushFailed(e.to_string()))?;
        Ok(())
    }
}

// ============================================================================
// Sled Tree Implementation
// ============================================================================

/// A namespaced tree within a sled database
///
/// Provides isolated storage within the same database file.
/// All operations are scoped to this tree's namespace.
#[derive(Clone, Debug)]
pub struct SledTree {
    tree: sled::Tree,
    name: String,
}

impl SledTree {
    /// Get the tree name
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the number of entries in this tree
    pub fn len(&self) -> usize {
        self.tree.len()
    }

    /// Check if the tree is empty
    pub fn is_empty(&self) -> bool {
        self.tree.is_empty()
    }

    /// Clear all entries in this tree
    pub fn clear(&self) -> Result<()> {
        self.tree
            .clear()
            .map_err(|e| StorageError::DeleteFailed(e.to_string()))?;
        debug!("Cleared tree: {}", self.name);
        Ok(())
    }
}

#[async_trait]
impl StorageBackend for SledTree {
    async fn put(&self, key: &[u8], value: &[u8]) -> Result<()> {
        validate_key(key)?;
        validate_value(value)?;

        let tree = self.tree.clone();
        let key = key.to_vec();
        let value = value.to_vec();

        tokio::task::spawn_blocking(move || {
            tree.insert(key, value)
                .map_err(|e| StorageError::WriteFailed(e.to_string()))
        })
        .await
        .map_err(|e| StorageError::TaskFailed(e.to_string()))??;

        Ok(())
    }

    async fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        validate_key(key)?;

        let tree = self.tree.clone();
        let key = key.to_vec();

        tokio::task::spawn_blocking(move || {
            tree.get(key)
                .map_err(|e| StorageError::ReadFailed(e.to_string()))
                .map(|opt| opt.map(|v| v.to_vec()))
        })
        .await
        .map_err(|e| StorageError::TaskFailed(e.to_string()))?
    }

    async fn delete(&self, key: &[u8]) -> Result<()> {
        validate_key(key)?;

        let tree = self.tree.clone();
        let key = key.to_vec();

        tokio::task::spawn_blocking(move || {
            tree.remove(key)
                .map_err(|e| StorageError::DeleteFailed(e.to_string()))
        })
        .await
        .map_err(|e| StorageError::TaskFailed(e.to_string()))??;

        Ok(())
    }

    async fn contains(&self, key: &[u8]) -> Result<bool> {
        validate_key(key)?;

        let tree = self.tree.clone();
        let key = key.to_vec();

        tokio::task::spawn_blocking(move || {
            tree.contains_key(key)
                .map_err(|e| StorageError::ReadFailed(e.to_string()))
        })
        .await
        .map_err(|e| StorageError::TaskFailed(e.to_string()))?
    }

    async fn scan_prefix(&self, prefix: &[u8], limit: Option<usize>) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let tree = self.tree.clone();
        let prefix = prefix.to_vec();
        let max = limit.unwrap_or(DEFAULT_SCAN_LIMIT);

        tokio::task::spawn_blocking(move || {
            let mut results = Vec::with_capacity(max.min(1000));
            for item in tree.scan_prefix(prefix).take(max) {
                let (k, v) = item.map_err(|e| StorageError::ScanFailed(e.to_string()))?;
                results.push((k.to_vec(), v.to_vec()));
            }
            Ok(results)
        })
        .await
        .map_err(|e| StorageError::TaskFailed(e.to_string()))?
    }

    async fn write_batch(&self, ops: &[BatchOp]) -> Result<()> {
        validate_batch(ops)?;

        let tree = self.tree.clone();
        let ops: Vec<BatchOp> = ops.to_vec();

        tokio::task::spawn_blocking(move || {
            let mut batch = sled::Batch::default();
            for op in ops {
                match op {
                    BatchOp::Put { key, value } => batch.insert(key, value),
                    BatchOp::Delete { key } => batch.remove(key),
                }
            }
            tree.apply_batch(batch)
                .map_err(|e| StorageError::BatchFailed(e.to_string()))
        })
        .await
        .map_err(|e| StorageError::TaskFailed(e.to_string()))?
    }

    async fn compare_and_swap(
        &self,
        key: &[u8],
        expected: Option<&[u8]>,
        new: Option<&[u8]>,
    ) -> Result<()> {
        validate_key(key)?;
        if let Some(v) = expected {
            validate_value(v)?;
        }
        if let Some(v) = new {
            validate_value(v)?;
        }

        let tree = self.tree.clone();
        let key = key.to_vec();
        let expected = expected.map(|v| v.to_vec());
        let new = new.map(|v| v.to_vec());

        tokio::task::spawn_blocking(move || {
            let result = tree
                .compare_and_swap(
                    key,
                    expected.as_deref(),
                    new.as_deref(),
                )
                .map_err(|e| StorageError::WriteFailed(e.to_string()))?;

            match result {
                Ok(()) => Ok(()),
                Err(_) => Err(StorageError::CasConflict),
            }
        })
        .await
        .map_err(|e| StorageError::TaskFailed(e.to_string()))?
    }

    async fn flush(&self) -> Result<()> {
        let tree = self.tree.clone();

        tokio::task::spawn_blocking(move || {
            tree.flush()
                .map_err(|e| StorageError::FlushFailed(e.to_string()))
        })
        .await
        .map_err(|e| StorageError::TaskFailed(e.to_string()))??;

        Ok(())
    }
}

// Also implement StorageBackend for the main database (default tree)
#[async_trait]
impl StorageBackend for SledBackend {
    async fn put(&self, key: &[u8], value: &[u8]) -> Result<()> {
        validate_key(key)?;
        validate_value(value)?;

        let db = self.db.clone();
        let key = key.to_vec();
        let value = value.to_vec();

        tokio::task::spawn_blocking(move || {
            db.insert(key, value)
                .map_err(|e| StorageError::WriteFailed(e.to_string()))
        })
        .await
        .map_err(|e| StorageError::TaskFailed(e.to_string()))??;

        Ok(())
    }

    async fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        validate_key(key)?;

        let db = self.db.clone();
        let key = key.to_vec();

        tokio::task::spawn_blocking(move || {
            db.get(key)
                .map_err(|e| StorageError::ReadFailed(e.to_string()))
                .map(|opt| opt.map(|v| v.to_vec()))
        })
        .await
        .map_err(|e| StorageError::TaskFailed(e.to_string()))?
    }

    async fn delete(&self, key: &[u8]) -> Result<()> {
        validate_key(key)?;

        let db = self.db.clone();
        let key = key.to_vec();

        tokio::task::spawn_blocking(move || {
            db.remove(key)
                .map_err(|e| StorageError::DeleteFailed(e.to_string()))
        })
        .await
        .map_err(|e| StorageError::TaskFailed(e.to_string()))??;

        Ok(())
    }

    async fn contains(&self, key: &[u8]) -> Result<bool> {
        validate_key(key)?;

        let db = self.db.clone();
        let key = key.to_vec();

        tokio::task::spawn_blocking(move || {
            db.contains_key(key)
                .map_err(|e| StorageError::ReadFailed(e.to_string()))
        })
        .await
        .map_err(|e| StorageError::TaskFailed(e.to_string()))?
    }

    async fn scan_prefix(&self, prefix: &[u8], limit: Option<usize>) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let db = self.db.clone();
        let prefix = prefix.to_vec();
        let max = limit.unwrap_or(DEFAULT_SCAN_LIMIT);

        tokio::task::spawn_blocking(move || {
            let mut results = Vec::with_capacity(max.min(1000));
            for item in db.scan_prefix(prefix).take(max) {
                let (k, v) = item.map_err(|e| StorageError::ScanFailed(e.to_string()))?;
                results.push((k.to_vec(), v.to_vec()));
            }
            Ok(results)
        })
        .await
        .map_err(|e| StorageError::TaskFailed(e.to_string()))?
    }

    async fn write_batch(&self, ops: &[BatchOp]) -> Result<()> {
        validate_batch(ops)?;

        let db = self.db.clone();
        let ops: Vec<BatchOp> = ops.to_vec();

        tokio::task::spawn_blocking(move || {
            let mut batch = sled::Batch::default();
            for op in ops {
                match op {
                    BatchOp::Put { key, value } => batch.insert(key, value),
                    BatchOp::Delete { key } => batch.remove(key),
                }
            }
            db.apply_batch(batch)
                .map_err(|e| StorageError::BatchFailed(e.to_string()))
        })
        .await
        .map_err(|e| StorageError::TaskFailed(e.to_string()))?
    }

    async fn compare_and_swap(
        &self,
        key: &[u8],
        expected: Option<&[u8]>,
        new: Option<&[u8]>,
    ) -> Result<()> {
        validate_key(key)?;
        if let Some(v) = expected {
            validate_value(v)?;
        }
        if let Some(v) = new {
            validate_value(v)?;
        }

        let db = self.db.clone();
        let key = key.to_vec();
        let expected = expected.map(|v| v.to_vec());
        let new = new.map(|v| v.to_vec());

        tokio::task::spawn_blocking(move || {
            let result = db
                .compare_and_swap(
                    key,
                    expected.as_deref(),
                    new.as_deref(),
                )
                .map_err(|e| StorageError::WriteFailed(e.to_string()))?;

            match result {
                Ok(()) => Ok(()),
                Err(_) => Err(StorageError::CasConflict),
            }
        })
        .await
        .map_err(|e| StorageError::TaskFailed(e.to_string()))?
    }

    async fn flush(&self) -> Result<()> {
        let db = self.db.clone();

        tokio::task::spawn_blocking(move || {
            db.flush()
                .map_err(|e| StorageError::FlushFailed(e.to_string()))
        })
        .await
        .map_err(|e| StorageError::TaskFailed(e.to_string()))??;

        Ok(())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    async fn create_test_backend() -> (SledBackend, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let backend = SledBackend::open(temp_dir.path()).unwrap();
        (backend, temp_dir)
    }

    #[tokio::test]
    async fn test_basic_put_get() {
        let (backend, _dir) = create_test_backend().await;

        backend.put(b"key1", b"value1").await.unwrap();
        let value = backend.get(b"key1").await.unwrap();

        assert_eq!(value, Some(b"value1".to_vec()));
    }

    #[tokio::test]
    async fn test_get_nonexistent() {
        let (backend, _dir) = create_test_backend().await;

        let value = backend.get(b"nonexistent").await.unwrap();
        assert_eq!(value, None);
    }

    #[tokio::test]
    async fn test_delete() {
        let (backend, _dir) = create_test_backend().await;

        backend.put(b"key1", b"value1").await.unwrap();
        assert!(backend.contains(b"key1").await.unwrap());

        backend.delete(b"key1").await.unwrap();
        assert!(!backend.contains(b"key1").await.unwrap());
    }

    #[tokio::test]
    async fn test_contains() {
        let (backend, _dir) = create_test_backend().await;

        assert!(!backend.contains(b"key1").await.unwrap());
        backend.put(b"key1", b"value1").await.unwrap();
        assert!(backend.contains(b"key1").await.unwrap());
    }

    #[tokio::test]
    async fn test_scan_prefix() {
        let (backend, _dir) = create_test_backend().await;

        backend.put(b"user:1", b"alice").await.unwrap();
        backend.put(b"user:2", b"bob").await.unwrap();
        backend.put(b"user:3", b"charlie").await.unwrap();
        backend.put(b"peer:1", b"peer_data").await.unwrap();

        let users = backend.scan_prefix(b"user:", None).await.unwrap();
        assert_eq!(users.len(), 3);

        let peers = backend.scan_prefix(b"peer:", None).await.unwrap();
        assert_eq!(peers.len(), 1);
    }

    #[tokio::test]
    async fn test_scan_prefix_with_limit() {
        let (backend, _dir) = create_test_backend().await;

        for i in 0..100 {
            let key = format!("item:{:03}", i);
            backend.put(key.as_bytes(), b"value").await.unwrap();
        }

        let limited = backend.scan_prefix(b"item:", Some(10)).await.unwrap();
        assert_eq!(limited.len(), 10);
    }

    #[tokio::test]
    async fn test_write_batch() {
        let (backend, _dir) = create_test_backend().await;

        let ops = vec![
            BatchOp::Put {
                key: b"batch:1".to_vec(),
                value: b"value1".to_vec(),
            },
            BatchOp::Put {
                key: b"batch:2".to_vec(),
                value: b"value2".to_vec(),
            },
            BatchOp::Put {
                key: b"batch:3".to_vec(),
                value: b"value3".to_vec(),
            },
        ];

        backend.write_batch(&ops).await.unwrap();

        assert_eq!(backend.get(b"batch:1").await.unwrap(), Some(b"value1".to_vec()));
        assert_eq!(backend.get(b"batch:2").await.unwrap(), Some(b"value2".to_vec()));
        assert_eq!(backend.get(b"batch:3").await.unwrap(), Some(b"value3".to_vec()));
    }

    #[tokio::test]
    async fn test_batch_mixed_operations() {
        let (backend, _dir) = create_test_backend().await;

        backend.put(b"to_delete", b"will_be_deleted").await.unwrap();

        let ops = vec![
            BatchOp::Put {
                key: b"new_key".to_vec(),
                value: b"new_value".to_vec(),
            },
            BatchOp::Delete {
                key: b"to_delete".to_vec(),
            },
        ];

        backend.write_batch(&ops).await.unwrap();

        assert_eq!(backend.get(b"new_key").await.unwrap(), Some(b"new_value".to_vec()));
        assert_eq!(backend.get(b"to_delete").await.unwrap(), None);
    }

    #[tokio::test]
    async fn test_compare_and_swap_success() {
        let (backend, _dir) = create_test_backend().await;

        // Insert initial value
        backend.put(b"cas_key", b"initial").await.unwrap();

        // CAS should succeed
        backend
            .compare_and_swap(b"cas_key", Some(b"initial"), Some(b"updated"))
            .await
            .unwrap();

        assert_eq!(backend.get(b"cas_key").await.unwrap(), Some(b"updated".to_vec()));
    }

    #[tokio::test]
    async fn test_compare_and_swap_conflict() {
        let (backend, _dir) = create_test_backend().await;

        backend.put(b"cas_key", b"actual").await.unwrap();

        // CAS should fail - expected value doesn't match
        let result = backend
            .compare_and_swap(b"cas_key", Some(b"wrong"), Some(b"updated"))
            .await;

        assert!(matches!(result, Err(StorageError::CasConflict)));
        assert_eq!(backend.get(b"cas_key").await.unwrap(), Some(b"actual".to_vec()));
    }

    #[tokio::test]
    async fn test_compare_and_swap_insert_if_absent() {
        let (backend, _dir) = create_test_backend().await;

        // Insert only if key doesn't exist
        backend
            .compare_and_swap(b"new_cas_key", None, Some(b"value"))
            .await
            .unwrap();

        assert_eq!(backend.get(b"new_cas_key").await.unwrap(), Some(b"value".to_vec()));

        // Second attempt should fail
        let result = backend
            .compare_and_swap(b"new_cas_key", None, Some(b"another"))
            .await;

        assert!(matches!(result, Err(StorageError::CasConflict)));
    }

    #[tokio::test]
    async fn test_named_trees() {
        let (backend, _dir) = create_test_backend().await;

        let dht_tree = backend.open_tree("dht").unwrap();
        let peer_tree = backend.open_tree("peers").unwrap();

        // Trees are isolated
        dht_tree.put(b"key1", b"dht_value").await.unwrap();
        peer_tree.put(b"key1", b"peer_value").await.unwrap();

        assert_eq!(dht_tree.get(b"key1").await.unwrap(), Some(b"dht_value".to_vec()));
        assert_eq!(peer_tree.get(b"key1").await.unwrap(), Some(b"peer_value".to_vec()));
    }

    #[tokio::test]
    async fn test_tree_clear() {
        let (backend, _dir) = create_test_backend().await;

        let tree = backend.open_tree("test_clear").unwrap();

        tree.put(b"key1", b"value1").await.unwrap();
        tree.put(b"key2", b"value2").await.unwrap();

        assert_eq!(tree.len(), 2);

        tree.clear().unwrap();

        assert_eq!(tree.len(), 0);
        assert!(tree.is_empty());
    }

    #[tokio::test]
    async fn test_flush() {
        let (backend, _dir) = create_test_backend().await;

        backend.put(b"key1", b"value1").await.unwrap();
        backend.flush().await.unwrap();

        let value = backend.get(b"key1").await.unwrap();
        assert_eq!(value, Some(b"value1".to_vec()));
    }

    #[tokio::test]
    async fn test_persistence_across_reopen() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().to_path_buf();

        {
            let backend = SledBackend::open(&path).unwrap();
            backend.put(b"persistent_key", b"persistent_value").await.unwrap();
            backend.flush().await.unwrap();
        }

        {
            let backend = SledBackend::open(&path).unwrap();
            let value = backend.get(b"persistent_key").await.unwrap();
            assert_eq!(value, Some(b"persistent_value".to_vec()));
        }
    }

    #[tokio::test]
    async fn test_large_values() {
        let (backend, _dir) = create_test_backend().await;

        let large_value = vec![0u8; 1024 * 1024]; // 1 MB
        backend.put(b"large_key", &large_value).await.unwrap();

        let retrieved = backend.get(b"large_key").await.unwrap();
        assert_eq!(retrieved, Some(large_value));
    }

    #[tokio::test]
    async fn test_binary_keys_and_values() {
        let (backend, _dir) = create_test_backend().await;

        let binary_key = vec![0x00, 0x01, 0xFF, 0xFE];
        let binary_value = vec![0xDE, 0xAD, 0xBE, 0xEF];

        backend.put(&binary_key, &binary_value).await.unwrap();

        let retrieved = backend.get(&binary_key).await.unwrap();
        assert_eq!(retrieved, Some(binary_value));
    }

    #[tokio::test]
    async fn test_overwrite_value() {
        let (backend, _dir) = create_test_backend().await;

        backend.put(b"key", b"value1").await.unwrap();
        assert_eq!(backend.get(b"key").await.unwrap(), Some(b"value1".to_vec()));

        backend.put(b"key", b"value2").await.unwrap();
        assert_eq!(backend.get(b"key").await.unwrap(), Some(b"value2".to_vec()));
    }

    // Security tests

    #[tokio::test]
    async fn test_empty_key_rejected() {
        let (backend, _dir) = create_test_backend().await;

        let result = backend.put(b"", b"value").await;
        assert!(matches!(result, Err(StorageError::EmptyKey)));
    }

    #[tokio::test]
    async fn test_key_too_large_rejected() {
        let (backend, _dir) = create_test_backend().await;

        let large_key = vec![0u8; MAX_KEY_SIZE + 1];
        let result = backend.put(&large_key, b"value").await;
        assert!(matches!(result, Err(StorageError::KeyTooLarge { .. })));
    }

    #[tokio::test]
    async fn test_value_too_large_rejected() {
        let (backend, _dir) = create_test_backend().await;

        let large_value = vec![0u8; MAX_VALUE_SIZE + 1];
        let result = backend.put(b"key", &large_value).await;
        assert!(matches!(result, Err(StorageError::ValueTooLarge { .. })));
    }

    #[tokio::test]
    async fn test_invalid_tree_name_rejected() {
        let (backend, _dir) = create_test_backend().await;

        // Empty name
        assert!(matches!(
            backend.open_tree(""),
            Err(StorageError::InvalidTreeName(_))
        ));

        // Special characters
        assert!(matches!(
            backend.open_tree("tree/name"),
            Err(StorageError::InvalidTreeName(_))
        ));

        // Too long
        let long_name = "a".repeat(MAX_TREE_NAME_LENGTH + 1);
        assert!(matches!(
            backend.open_tree(&long_name),
            Err(StorageError::InvalidTreeName(_))
        ));
    }

    #[tokio::test]
    async fn test_valid_tree_names() {
        let (backend, _dir) = create_test_backend().await;

        // Valid names
        assert!(backend.open_tree("dht").is_ok());
        assert!(backend.open_tree("peer_cache").is_ok());
        assert!(backend.open_tree("routing-table").is_ok());
        assert!(backend.open_tree("Tree123").is_ok());
    }

    #[tokio::test]
    async fn test_size_on_disk() {
        let (backend, _dir) = create_test_backend().await;

        for i in 0..100 {
            let key = format!("key_{}", i);
            let value = format!("value_{}", i);
            backend.put(key.as_bytes(), value.as_bytes()).await.unwrap();
        }

        backend.flush().await.unwrap();

        let size = backend.size_on_disk().unwrap();
        assert!(size > 0, "Database should have non-zero size");
    }
}
