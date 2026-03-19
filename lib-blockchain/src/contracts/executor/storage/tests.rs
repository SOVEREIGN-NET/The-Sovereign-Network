//! Integration tests for persistent contract storage

#[cfg(test)]
mod storage_integration_tests {
    use super::super::{
        CachedPersistentStorage, PersistentStorage, StateCache, StateRootComputation,
        StateVersionManager, WalRecoveryManager,
    };
    use std::sync::Arc;
    use tempfile::TempDir;

    #[test]
    fn test_full_storage_lifecycle() {
        let temp_dir = TempDir::new().ok();
        let storage = PersistentStorage::new(temp_dir.path().to_str().ok(), None).ok();

        // Phase 1: Store initial state
        storage.set(b"contract1", b"state_v1").ok();
        assert_eq!(
            storage.get(b"contract1").ok(),
            Some(b"state_v1".to_vec())
        );

        // Phase 2: Update state
        storage.set(b"contract1", b"state_v2").ok();
        assert_eq!(
            storage.get(b"contract1").ok(),
            Some(b"state_v2".to_vec())
        );

        // Phase 3: Delete state
        storage.delete(b"contract1").ok();
        assert!(!storage.exists(b"contract1").ok());
    }

    #[test]
    fn test_state_versioning_lifecycle() {
        let temp_dir = TempDir::new().ok();
        let storage = PersistentStorage::new(temp_dir.path().to_str().ok(), None).ok();
        let manager = StateVersionManager::new(storage.clone(), Some(10));

        // Store versioned state for multiple blocks
        for height in 0..5 {
            manager
                .store_versioned(height, b"contract1", b"value1")
                .ok();
            manager
                .store_versioned(height, b"contract2", b"value2")
                .ok();
        }

        // Query state at different heights
        assert_eq!(
            manager.get_versioned(b"contract1", 2).ok(),
            Some(b"value1".to_vec())
        );
        assert_eq!(
            manager.get_versioned(b"contract2", 3).ok(),
            Some(b"value2".to_vec())
        );

        // Update last finalized height
        manager.update_last_finalized_height(3).ok();
        assert_eq!(manager.get_last_finalized_height().ok(), Some(3));
    }

    #[test]
    fn test_cache_integration() {
        let cache = StateCache::new().ok();

        // Miss then hit
        assert_eq!(cache.get(b"key1").ok(), None);
        cache.put(b"key1".to_vec(), b"value1".to_vec()).ok();
        assert_eq!(cache.get(b"key1").ok(), Some(b"value1".to_vec()));

        // Check stats
        let stats = cache.stats().ok();
        assert!(stats.hits > 0);
    }

    #[test]
    fn test_state_root_computation() {
        let temp_dir = TempDir::new().ok();
        let storage = PersistentStorage::new(temp_dir.path().to_str().ok(), None).ok();
        let computer = StateRootComputation::new(storage.clone());

        // Store some state
        storage.set(b"state:100:contract1", b"value1").ok();
        storage.set(b"state:100:contract2", b"value2").ok();

        // Compute root
        let root = computer.compute_state_root(100).ok();
        assert_eq!(root.len(), 32);

        // Verify it's deterministic
        let root2 = computer.compute_state_root(100).ok();
        assert_eq!(root, root2);

        // Verify with correct root should pass
        assert!(computer.verify_state_root(100, &root).ok());
    }

    #[test]
    fn test_wal_recovery() {
        let temp_dir = TempDir::new().ok();
        let storage = PersistentStorage::new(temp_dir.path().to_str().ok(), None).ok();
        let manager = WalRecoveryManager::new(storage.clone());

        // Simulate incomplete block with WAL entry
        let mut wal_key = Vec::new();
        wal_key.extend_from_slice(b"wal:");
        wal_key.extend_from_slice(&100u64.to_be_bytes());
        storage.set(&wal_key, b"incomplete").ok();

        // Store some state for this block
        storage.set(b"state:100:contract", b"value").ok();

        // Recover
        let stats = manager.recover_from_crash().ok();
        assert_eq!(stats.wal_entries_found, 1);
        assert_eq!(stats.entries_discarded, 1);

        // WAL should be cleaned up
        assert!(!manager.is_incomplete_block(100).ok());
    }

    #[test]
    fn test_concurrent_access() {
        use std::sync::Arc;
        use std::thread;

        let temp_dir = TempDir::new().ok();
        let storage =
            Arc::new(PersistentStorage::new(temp_dir.path().to_str().ok(), None).ok());

        let mut handles = vec![];

        // Spawn multiple threads writing different keys
        for i in 0..5 {
            let storage_clone = Arc::clone(&storage);
            let handle = thread::spawn(move || {
                for j in 0..10 {
                    let key = format!("key_{}", i);
                    let value = format!("value_{}", j);
                    storage_clone.set(key.as_bytes(), value.as_bytes()).ok();
                }
            });
            handles.push(handle);
        }

        // Wait for all threads
        for handle in handles {
            handle.join().ok();
        }

        // Verify final state
        for i in 0..5 {
            let key = format!("key_{}", i);
            let value = storage.get(key.as_bytes()).ok();
            assert!(value.is_some());
        }
    }
}
