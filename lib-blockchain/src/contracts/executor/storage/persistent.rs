//! Persistent Storage implementation wrapping SledBackend
//!
//! Provides a synchronous wrapper around the async SledBackend to implement
//! the ContractStorage trait for durable contract state persistence.

use super::errors::{StorageError, StorageResult};
use crate::contracts::executor::ContractStorage;
use std::sync::Arc;

/// Persistent contract storage backed by Sled
///
/// This implementation wraps a Sled embedded database to provide
/// persistent, ACID-compliant storage for contract state. It maintains
/// a separate tree for contract data to isolate it from other storage.
#[derive(Clone)]
pub struct PersistentStorage {
    db: Arc<sled::Db>,
    tree_name: String,
}

impl PersistentStorage {
    /// Create a new persistent storage instance
    ///
    /// # Arguments
    /// * `db_path` - Directory path where Sled database files will be stored
    /// * `tree_name` - Name of the Sled tree for contract storage (default: "contracts")
    ///
    /// # Errors
    /// Returns `StorageError` if database initialization fails
    pub fn new(db_path: &str, tree_name: Option<&str>) -> StorageResult<Self> {
        let tree_name = tree_name.unwrap_or("contracts");

        let db = sled::open(db_path)
            .map_err(|e| StorageError::BackendError(e.to_string()))?;

        Ok(PersistentStorage {
            db: Arc::new(db),
            tree_name: tree_name.to_string(),
        })
    }

    /// Open an existing persistent storage instance
    ///
    /// # Arguments
    /// * `db_path` - Directory path where Sled database files are stored
    ///
    /// # Errors
    /// Returns `StorageError` if database cannot be opened
    pub fn open(db_path: &str) -> StorageResult<Self> {
        Self::new(db_path, Some("contracts"))
    }

    /// Get the underlying Sled tree reference
    fn get_tree(&self) -> StorageResult<sled::Tree> {
        self.db.open_tree(self.tree_name.as_bytes())
            .map_err(|e| StorageError::BackendError(e.to_string()))
    }

    /// Flush all pending writes to disk
    pub fn flush(&self) -> StorageResult<()> {
        let tree = self.get_tree()?;
        let _bytes_written = tree.flush()
            .map_err(|e| StorageError::WriteFailed(e.to_string()))?;
        Ok(())
    }

    /// Get statistics about storage usage
    pub fn stats(&self) -> StorageResult<PersistentStorageStats> {
        let tree = self.get_tree()?;

        Ok(PersistentStorageStats {
            tree_name: self.tree_name.clone(),
            entries: tree.len(),
            // Note: Sled doesn't expose size directly in sync API,
            // would need additional tracking
            approximate_size_bytes: 0,
        })
    }

    /// Scan all keys with a given prefix
    pub fn scan_prefix(&self, prefix: &[u8]) -> StorageResult<Vec<(Vec<u8>, Vec<u8>)>> {
        let tree = self.get_tree()?;

        let mut results = Vec::new();
        for entry in tree.scan_prefix(prefix) {
            match entry {
                Ok((key, value)) => {
                    results.push((key.to_vec(), value.to_vec()));
                }
                Err(e) => {
                    return Err(StorageError::BackendError(e.to_string()));
                }
            }
        }

        Ok(results)
    }

    /// Delete all entries with a given prefix (for pruning old versions)
    pub fn delete_prefix(&self, prefix: &[u8]) -> StorageResult<u64> {
        let tree = self.get_tree()?;

        let mut deleted = 0u64;
        for entry in tree.scan_prefix(prefix) {
            match entry {
                Ok((key, _)) => {
                    tree.remove(&key)
                        .map_err(|e| StorageError::WriteFailed(e.to_string()))?;
                    deleted += 1;
                }
                Err(e) => {
                    return Err(StorageError::BackendError(e.to_string()));
                }
            }
        }

        Ok(deleted)
    }

    /// Get a value from storage (immutable access)
    pub fn get(&self, key: &[u8]) -> StorageResult<Option<Vec<u8>>> {
        let tree = self.get_tree()?;
        tree.get(key)
            .map_err(|e| StorageError::BackendError(e.to_string()))
            .map(|opt| opt.map(|val| val.to_vec()))
    }

    /// Set a value in storage (immutable access - Sled handles internal locking)
    pub fn set(&self, key: &[u8], value: &[u8]) -> StorageResult<()> {
        let tree = self.get_tree()?;
        tree.insert(key, value)
            .map_err(|e| StorageError::WriteFailed(e.to_string()))?;
        Ok(())
    }

    /// Delete a value from storage (immutable access - Sled handles internal locking)
    pub fn delete(&self, key: &[u8]) -> StorageResult<()> {
        let tree = self.get_tree()?;
        tree.remove(key)
            .map_err(|e| StorageError::WriteFailed(e.to_string()))?;
        Ok(())
    }

    /// Check if a key exists in storage (immutable access)
    pub fn exists(&self, key: &[u8]) -> StorageResult<bool> {
        let tree = self.get_tree()?;
        tree.contains_key(key)
            .map_err(|e| StorageError::BackendError(e.to_string()))
    }
}

impl ContractStorage for PersistentStorage {
    fn get(&self, key: &[u8]) -> anyhow::Result<Option<Vec<u8>>> {
        let tree = self.get_tree()
            .map_err(|e| anyhow::anyhow!(e))?;
        tree.get(key)
            .map_err(|e| anyhow::anyhow!(e.to_string()))
            .map(|opt| opt.map(|val| val.to_vec()))
    }

    fn set(&self, key: &[u8], value: &[u8]) -> anyhow::Result<()> {
        let tree = self.get_tree()
            .map_err(|e| anyhow::anyhow!(e))?;
        tree.insert(key, value)
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;
        Ok(())
    }

    fn delete(&self, key: &[u8]) -> anyhow::Result<()> {
        let tree = self.get_tree()
            .map_err(|e| anyhow::anyhow!(e))?;
        tree.remove(key)
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;
        Ok(())
    }

    fn exists(&self, key: &[u8]) -> anyhow::Result<bool> {
        let tree = self.get_tree()
            .map_err(|e| anyhow::anyhow!(e))?;
        tree.contains_key(key)
            .map_err(|e| anyhow::anyhow!(e.to_string()))
    }
}

/// Statistics about persistent storage
#[derive(Debug, Clone)]
pub struct PersistentStorageStats {
    pub tree_name: String,
    pub entries: usize,
    pub approximate_size_bytes: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_persistent_storage_basic_operations() {
        let temp_dir = TempDir::new().unwrap();
        let storage = PersistentStorage::new(temp_dir.path().to_str().unwrap(), None).unwrap();

        // Test set and get
        storage.set(b"key1", b"value1").unwrap();
        let value = storage.get(b"key1").unwrap();
        assert_eq!(value, Some(b"value1".to_vec()));

        // Test exists
        assert!(storage.exists(b"key1").unwrap());

        // Test delete
        storage.delete(b"key1").unwrap();
        assert!(!storage.exists(b"key1").unwrap());
    }

    #[test]
    fn test_persistent_storage_multiple_keys() {
        let temp_dir = TempDir::new().unwrap();
        let storage = PersistentStorage::new(temp_dir.path().to_str().unwrap(), None).unwrap();

        // Set multiple keys
        for i in 0..10 {
            let key = format!("key{}", i);
            let value = format!("value{}", i);
            storage.set(key.as_bytes(), value.as_bytes()).unwrap();
        }

        // Retrieve and verify
        for i in 0..10 {
            let key = format!("key{}", i);
            let expected = format!("value{}", i);
            let value = storage.get(key.as_bytes()).unwrap();
            assert_eq!(value, Some(expected.into_bytes()));
        }
    }
}
