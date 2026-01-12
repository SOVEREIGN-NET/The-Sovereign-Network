//! In-memory HashMap backend for testing and development
//!
//! Provides a simple in-memory storage implementation suitable for:
//! - Unit tests
//! - Development
//! - Scenarios where data loss on restart is acceptable

use super::StorageBackend;
use anyhow::Result;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;

/// In-memory HashMap storage backend
///
/// Thread-safe HashMap wrapped in Arc<RwLock> for concurrent access.
/// All data is lost on process termination.
#[derive(Clone, Debug)]
pub struct HashMapBackend {
    /// In-memory storage using Arc<RwLock<>> for thread-safe sharing
    storage: Arc<RwLock<HashMap<Vec<u8>, Vec<u8>>>>,
}

impl HashMapBackend {
    /// Create a new in-memory backend
    pub fn new() -> Self {
        Self {
            storage: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create with pre-allocated capacity
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            storage: Arc::new(RwLock::new(HashMap::with_capacity(capacity))),
        }
    }
}

impl Default for HashMapBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl StorageBackend for HashMapBackend {
    fn put(&self, key: &[u8], value: &[u8]) -> Result<Option<Vec<u8>>> {
        let mut storage = self.storage.write();
        Ok(storage.insert(key.to_vec(), value.to_vec()))
    }

    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let storage = self.storage.read();
        Ok(storage.get(key).cloned())
    }

    fn remove(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let mut storage = self.storage.write();
        Ok(storage.remove(key))
    }

    fn contains_key(&self, key: &[u8]) -> Result<bool> {
        let storage = self.storage.read();
        Ok(storage.contains_key(key))
    }

    fn keys(&self) -> Result<Vec<Vec<u8>>> {
        let storage = self.storage.read();
        Ok(storage.keys().cloned().collect())
    }

    fn keys_with_prefix(&self, prefix: &[u8]) -> Result<Vec<Vec<u8>>> {
        let storage = self.storage.read();
        Ok(storage
            .keys()
            .filter(|k| k.starts_with(prefix))
            .cloned()
            .collect())
    }

    fn flush(&self) -> Result<()> {
        // No-op for in-memory storage
        Ok(())
    }

    fn len(&self) -> Result<usize> {
        let storage = self.storage.read();
        Ok(storage.len())
    }

    fn backend_type(&self) -> &'static str {
        "memory"
    }

    #[cfg(test)]
    fn clear(&self) -> Result<()> {
        let mut storage = self.storage.write();
        storage.clear();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_put_get() {
        let backend = HashMapBackend::new();
        backend.put(b"key1", b"value1").unwrap();
        assert_eq!(backend.get(b"key1").unwrap(), Some(b"value1".to_vec()));
    }

    #[test]
    fn test_put_returns_previous() {
        let backend = HashMapBackend::new();
        backend.put(b"key1", b"value1").unwrap();
        let prev = backend.put(b"key1", b"value2").unwrap();
        assert_eq!(prev, Some(b"value1".to_vec()));
    }

    #[test]
    fn test_remove() {
        let backend = HashMapBackend::new();
        backend.put(b"key1", b"value1").unwrap();
        let removed = backend.remove(b"key1").unwrap();
        assert_eq!(removed, Some(b"value1".to_vec()));
        assert_eq!(backend.get(b"key1").unwrap(), None);
    }

    #[test]
    fn test_contains_key() {
        let backend = HashMapBackend::new();
        backend.put(b"key1", b"value1").unwrap();
        assert!(backend.contains_key(b"key1").unwrap());
        assert!(!backend.contains_key(b"key2").unwrap());
    }

    #[test]
    fn test_keys() {
        let backend = HashMapBackend::new();
        backend.put(b"key1", b"value1").unwrap();
        backend.put(b"key2", b"value2").unwrap();
        backend.put(b"key3", b"value3").unwrap();

        let keys = backend.keys().unwrap();
        assert_eq!(keys.len(), 3);
    }

    #[test]
    fn test_keys_with_prefix() {
        let backend = HashMapBackend::new();
        backend.put(b"prefix:key1", b"value1").unwrap();
        backend.put(b"prefix:key2", b"value2").unwrap();
        backend.put(b"other:key", b"value3").unwrap();

        let keys = backend.keys_with_prefix(b"prefix:").unwrap();
        assert_eq!(keys.len(), 2);

        let all_keys = backend.keys_with_prefix(b"").unwrap();
        assert_eq!(all_keys.len(), 3);
    }

    #[test]
    fn test_len() {
        let backend = HashMapBackend::new();
        assert_eq!(backend.len().unwrap(), 0);
        assert!(backend.is_empty().unwrap());

        backend.put(b"key1", b"value1").unwrap();
        assert_eq!(backend.len().unwrap(), 1);
        assert!(!backend.is_empty().unwrap());

        backend.put(b"key2", b"value2").unwrap();
        assert_eq!(backend.len().unwrap(), 2);
    }

    #[test]
    fn test_clear() {
        let backend = HashMapBackend::new();
        backend.put(b"key1", b"value1").unwrap();
        backend.put(b"key2", b"value2").unwrap();
        assert_eq!(backend.len().unwrap(), 2);

        backend.clear().unwrap();
        assert_eq!(backend.len().unwrap(), 0);
        assert!(backend.is_empty().unwrap());
    }
}
