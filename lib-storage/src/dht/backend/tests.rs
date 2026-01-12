//! Backend trait compliance tests
//!
//! These tests verify that all backends implement the StorageBackend trait correctly.
//! Each backend should pass the same test suite to ensure compatibility.

#[cfg(test)]
mod backend_tests {
    use crate::dht::backend::{HashMapBackend, SledBackend, StorageBackend};
    use anyhow::Result;

    /// Test backend compliance for basic CRUD operations
    fn test_backend_crud<B: StorageBackend>(backend: B) -> Result<()> {
        // Test put/get
        assert_eq!(backend.get(b"key1")?, None, "Key should not exist initially");
        backend.put(b"key1", b"value1")?;
        assert_eq!(
            backend.get(b"key1")?,
            Some(b"value1".to_vec()),
            "Should retrieve inserted value"
        );

        // Test put returns previous value
        let prev = backend.put(b"key1", b"value2")?;
        assert_eq!(prev, Some(b"value1".to_vec()), "Should return previous value");
        assert_eq!(backend.get(b"key1")?, Some(b"value2".to_vec()));

        // Test remove
        let removed = backend.remove(b"key1")?;
        assert_eq!(removed, Some(b"value2".to_vec()), "Should return removed value");
        assert_eq!(backend.get(b"key1")?, None, "Key should not exist after removal");

        Ok(())
    }

    /// Test backend compliance for contains_key
    fn test_backend_contains<B: StorageBackend>(backend: B) -> Result<()> {
        assert!(!backend.contains_key(b"key1")?);

        backend.put(b"key1", b"value1")?;
        assert!(backend.contains_key(b"key1")?);

        backend.remove(b"key1")?;
        assert!(!backend.contains_key(b"key1")?);

        Ok(())
    }

    /// Test backend compliance for keys listing
    fn test_backend_keys<B: StorageBackend>(backend: B) -> Result<()> {
        assert_eq!(backend.keys()?, Vec::<Vec<u8>>::new(), "Should be empty initially");

        backend.put(b"key1", b"value1")?;
        backend.put(b"key2", b"value2")?;
        backend.put(b"key3", b"value3")?;

        let keys = backend.keys()?;
        assert_eq!(keys.len(), 3);
        assert!(keys.contains(&b"key1".to_vec()));
        assert!(keys.contains(&b"key2".to_vec()));
        assert!(keys.contains(&b"key3".to_vec()));

        Ok(())
    }

    /// Test backend compliance for prefix iteration
    fn test_backend_prefix<B: StorageBackend>(backend: B) -> Result<()> {
        backend.put(b"prefix:key1", b"value1")?;
        backend.put(b"prefix:key2", b"value2")?;
        backend.put(b"other:key", b"value3")?;

        let prefixed = backend.keys_with_prefix(b"prefix:")?;
        assert_eq!(prefixed.len(), 2, "Should match keys with prefix");
        assert!(prefixed.contains(&b"prefix:key1".to_vec()));
        assert!(prefixed.contains(&b"prefix:key2".to_vec()));
        assert!(!prefixed.contains(&b"other:key".to_vec()));

        // Empty prefix should return all
        let all = backend.keys_with_prefix(b"")?;
        assert_eq!(all.len(), 3);

        Ok(())
    }

    /// Test backend compliance for len and is_empty
    fn test_backend_len<B: StorageBackend>(backend: B) -> Result<()> {
        assert_eq!(backend.len()?, 0);
        assert!(backend.is_empty()?);

        backend.put(b"key1", b"value1")?;
        assert_eq!(backend.len()?, 1);
        assert!(!backend.is_empty()?);

        backend.put(b"key2", b"value2")?;
        assert_eq!(backend.len()?, 2);

        backend.remove(b"key1")?;
        assert_eq!(backend.len()?, 1);

        backend.remove(b"key2")?;
        assert_eq!(backend.len()?, 0);
        assert!(backend.is_empty()?);

        Ok(())
    }

    /// Test backend compliance for flush (may be no-op)
    fn test_backend_flush<B: StorageBackend>(backend: B) -> Result<()> {
        backend.put(b"key1", b"value1")?;
        backend.flush()?; // Should not error

        // Data should still be retrievable
        assert_eq!(backend.get(b"key1")?, Some(b"value1".to_vec()));

        Ok(())
    }

    /// Test backend compliance for clear
    fn test_backend_clear<B: StorageBackend>(backend: B) -> Result<()> {
        backend.put(b"key1", b"value1")?;
        backend.put(b"key2", b"value2")?;
        backend.put(b"key3", b"value3")?;
        assert_eq!(backend.len()?, 3);

        backend.clear()?;
        assert_eq!(backend.len()?, 0);
        assert!(backend.is_empty()?);
        assert_eq!(backend.get(b"key1")?, None);
        assert_eq!(backend.get(b"key2")?, None);
        assert_eq!(backend.get(b"key3")?, None);

        Ok(())
    }

    /// Test backend compliance for empty operations
    fn test_backend_empty_ops<B: StorageBackend>(backend: B) -> Result<()> {
        // Get non-existent key
        assert_eq!(backend.get(b"nonexistent")?, None);

        // Remove non-existent key
        let removed = backend.remove(b"nonexistent")?;
        assert_eq!(removed, None);

        // Contains for non-existent key
        assert!(!backend.contains_key(b"nonexistent")?);

        Ok(())
    }

    /// Run all backend compliance tests
    fn run_all_tests<B: StorageBackend>(backend: B) -> Result<()> {
        test_backend_crud(backend.clone())?;
        backend.clear()?;

        test_backend_contains(backend.clone())?;
        backend.clear()?;

        test_backend_keys(backend.clone())?;
        backend.clear()?;

        test_backend_prefix(backend.clone())?;
        backend.clear()?;

        test_backend_len(backend.clone())?;
        backend.clear()?;

        test_backend_flush(backend.clone())?;
        backend.clear()?;

        test_backend_clear(backend.clone())?;
        backend.clear()?;

        test_backend_empty_ops(backend)?;

        Ok(())
    }

    #[test]
    fn test_hashmap_backend_compliance() -> Result<()> {
        let backend = HashMapBackend::new();
        run_all_tests(backend)?;
        Ok(())
    }

    #[test]
    fn test_sled_backend_compliance() -> Result<()> {
        let backend = SledBackend::temporary()?;
        run_all_tests(backend)?;
        Ok(())
    }

    #[test]
    fn test_hashmap_with_unicode_keys() -> Result<()> {
        let backend = HashMapBackend::new();

        let key = "こんにちは".as_bytes();
        let value = "世界".as_bytes();

        backend.put(key, value)?;
        assert_eq!(backend.get(key)?, Some(value.to_vec()));

        Ok(())
    }

    #[test]
    fn test_sled_with_unicode_keys() -> Result<()> {
        let backend = SledBackend::temporary()?;

        let key = "مرحبا".as_bytes();
        let value = "عالم".as_bytes();

        backend.put(key, value)?;
        assert_eq!(backend.get(key)?, Some(value.to_vec()));

        Ok(())
    }

    #[test]
    fn test_hashmap_large_values() -> Result<()> {
        let backend = HashMapBackend::new();

        let large_value = vec![0u8; 1_000_000]; // 1 MB
        backend.put(b"large", &large_value)?;
        assert_eq!(backend.get(b"large")?, Some(large_value));

        Ok(())
    }

    #[test]
    fn test_sled_large_values() -> Result<()> {
        let backend = SledBackend::temporary()?;

        let large_value = vec![0u8; 1_000_000]; // 1 MB
        backend.put(b"large", &large_value)?;
        assert_eq!(backend.get(b"large")?, Some(large_value));

        Ok(())
    }

    #[test]
    fn test_hashmap_backend_type() {
        let backend = HashMapBackend::new();
        assert_eq!(backend.backend_type(), "memory");
    }

    #[test]
    fn test_sled_backend_type() -> Result<()> {
        let backend = SledBackend::temporary()?;
        assert_eq!(backend.backend_type(), "sled");
        Ok(())
    }
}
