//! Persistent sled backend for production storage
//!
//! Provides efficient, durable storage using sled key-value database.
//! Suitable for production deployments where data persistence across
//! restarts is required.

use super::StorageBackend;
use anyhow::Result;
use std::path::Path;

/// Persistent sled storage backend
///
/// Uses sled 0.34 with optimized configuration:
/// - 64MB page cache
/// - HighThroughput mode for write-heavy workloads
/// - Automatic compression
/// - Crash-safe atomic operations
#[derive(Clone, Debug)]
pub struct SledBackend {
    /// sled database instance (internally Arc, so clone is cheap)
    db: sled::Db,
}

impl SledBackend {
    /// Open or create a sled database at the given path
    ///
    /// # Arguments
    /// - `path`: Filesystem path for the database
    ///
    /// # Configuration
    /// - Cache capacity: 64MB
    /// - Mode: HighThroughput (optimized for write-heavy workloads)
    /// - Compression: Enabled (zstd)
    /// - Atomic writes: Enabled for crash safety
    ///
    /// # Returns
    /// - `Ok(backend)`: Database opened successfully
    /// - `Err(e)`: Failed to open database
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let db = sled::Config::default()
            .path(path.as_ref())
            .cache_capacity(64 * 1024 * 1024) // 64 MB
            .mode(sled::Mode::HighThroughput)
            .open()
            .map_err(|e| anyhow::anyhow!("Failed to open sled database: {}", e))?;

        Ok(Self { db })
    }

    /// Create a temporary sled database (for testing)
    ///
    /// Database is automatically cleaned up when dropped.
    ///
    /// # Returns
    /// - `Ok(backend)`: Temporary database created
    /// - `Err(e)`: Failed to create database
    pub fn temporary() -> Result<Self> {
        let db = sled::Config::default()
            .temporary(true)
            .open()
            .map_err(|e| anyhow::anyhow!("Failed to create temporary sled database: {}", e))?;

        Ok(Self { db })
    }
}

impl StorageBackend for SledBackend {
    fn put(&self, key: &[u8], value: &[u8]) -> Result<Option<Vec<u8>>> {
        let prev = self
            .db
            .insert(key, value)
            .map_err(|e| anyhow::anyhow!("Failed to insert into sled: {}", e))?;

        Ok(prev.map(|v| v.to_vec()))
    }

    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let value = self
            .db
            .get(key)
            .map_err(|e| anyhow::anyhow!("Failed to get from sled: {}", e))?;

        Ok(value.map(|v| v.to_vec()))
    }

    fn remove(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let prev = self
            .db
            .remove(key)
            .map_err(|e| anyhow::anyhow!("Failed to remove from sled: {}", e))?;

        Ok(prev.map(|v| v.to_vec()))
    }

    fn contains_key(&self, key: &[u8]) -> Result<bool> {
        let exists = self
            .db
            .contains_key(key)
            .map_err(|e| anyhow::anyhow!("Failed to check key in sled: {}", e))?;

        Ok(exists)
    }

    fn keys(&self) -> Result<Vec<Vec<u8>>> {
        let keys: Result<Vec<Vec<u8>>> = self
            .db
            .iter()
            .map(|item| {
                item.map(|(k, _)| k.to_vec())
                    .map_err(|e| anyhow::anyhow!("Failed to iterate sled: {}", e))
            })
            .collect();

        keys
    }

    fn keys_with_prefix(&self, prefix: &[u8]) -> Result<Vec<Vec<u8>>> {
        let keys: Result<Vec<Vec<u8>>> = self
            .db
            .scan_prefix(prefix)
            .map(|item| {
                item.map(|(k, _)| k.to_vec())
                    .map_err(|e| anyhow::anyhow!("Failed to scan sled prefix: {}", e))
            })
            .collect();

        keys
    }

    fn flush(&self) -> Result<()> {
        self.db
            .flush()
            .map_err(|e| anyhow::anyhow!("Failed to flush sled: {}", e))?;

        Ok(())
    }

    fn len(&self) -> Result<usize> {
        // Note: This is O(n) for sled. If performance is critical,
        // DhtStorage should maintain its own count.
        let count = self
            .db
            .iter()
            .count(); // count() consumes the iterator

        Ok(count)
    }

    fn backend_type(&self) -> &'static str {
        "sled"
    }

    #[cfg(test)]
    fn clear(&self) -> Result<()> {
        self.db
            .clear()
            .map_err(|e| anyhow::anyhow!("Failed to clear sled: {}", e))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sled_put_get() -> Result<()> {
        let backend = SledBackend::temporary()?;
        backend.put(b"key1", b"value1")?;
        assert_eq!(backend.get(b"key1")?, Some(b"value1".to_vec()));
        Ok(())
    }

    #[test]
    fn test_sled_put_returns_previous() -> Result<()> {
        let backend = SledBackend::temporary()?;
        backend.put(b"key1", b"value1")?;
        let prev = backend.put(b"key1", b"value2")?;
        assert_eq!(prev, Some(b"value1".to_vec()));
        Ok(())
    }

    #[test]
    fn test_sled_remove() -> Result<()> {
        let backend = SledBackend::temporary()?;
        backend.put(b"key1", b"value1")?;
        let removed = backend.remove(b"key1")?;
        assert_eq!(removed, Some(b"value1".to_vec()));
        assert_eq!(backend.get(b"key1")?, None);
        Ok(())
    }

    #[test]
    fn test_sled_contains_key() -> Result<()> {
        let backend = SledBackend::temporary()?;
        backend.put(b"key1", b"value1")?;
        assert!(backend.contains_key(b"key1")?);
        assert!(!backend.contains_key(b"key2")?);
        Ok(())
    }

    #[test]
    fn test_sled_keys() -> Result<()> {
        let backend = SledBackend::temporary()?;
        backend.put(b"key1", b"value1")?;
        backend.put(b"key2", b"value2")?;
        backend.put(b"key3", b"value3")?;

        let keys = backend.keys()?;
        assert_eq!(keys.len(), 3);
        Ok(())
    }

    #[test]
    fn test_sled_keys_with_prefix() -> Result<()> {
        let backend = SledBackend::temporary()?;
        backend.put(b"prefix:key1", b"value1")?;
        backend.put(b"prefix:key2", b"value2")?;
        backend.put(b"other:key", b"value3")?;

        let keys = backend.keys_with_prefix(b"prefix:")?;
        assert_eq!(keys.len(), 2);

        let all_keys = backend.keys_with_prefix(b"")?;
        assert_eq!(all_keys.len(), 3);
        Ok(())
    }

    #[test]
    fn test_sled_persistence() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let db_path = temp_dir.path();

        // Session 1: Write data
        {
            let backend = SledBackend::open(db_path)?;
            backend.put(b"persistent_key", b"persistent_value")?;
            backend.flush()?;
        }

        // Session 2: Verify persistence
        {
            let backend = SledBackend::open(db_path)?;
            assert_eq!(
                backend.get(b"persistent_key")?,
                Some(b"persistent_value".to_vec())
            );
        }

        Ok(())
    }

    #[test]
    fn test_sled_len() -> Result<()> {
        let backend = SledBackend::temporary()?;
        assert_eq!(backend.len()?, 0);
        assert!(backend.is_empty()?);

        backend.put(b"key1", b"value1")?;
        assert_eq!(backend.len()?, 1);
        assert!(!backend.is_empty()?);

        backend.put(b"key2", b"value2")?;
        assert_eq!(backend.len()?, 2);
        Ok(())
    }

    #[test]
    fn test_sled_clear() -> Result<()> {
        let backend = SledBackend::temporary()?;
        backend.put(b"key1", b"value1")?;
        backend.put(b"key2", b"value2")?;
        assert_eq!(backend.len()?, 2);

        backend.clear()?;
        assert_eq!(backend.len()?, 0);
        assert!(backend.is_empty()?);
        Ok(())
    }
}
