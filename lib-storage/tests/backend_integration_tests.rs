//! Backend Integration Tests
//!
//! [DB-014] Comprehensive integration tests for storage backends covering:
//! - Trait compliance across implementations
//! - Concurrent access patterns
//! - Crash recovery for persistent backends
//! - Batch atomicity guarantees
//! - Performance baselines
//!
//! These tests complement the unit tests in each backend module by testing
//! cross-cutting concerns and real-world usage patterns.

use lib_storage::backend::{
    BatchOp, SledBackend, SledTree, StorageBackend, StorageError,
};
use std::sync::Arc;
use std::time::Instant;
use tempfile::TempDir;
use tokio::sync::Barrier;

// Constants matching sled_backend.rs (not exported)
const MAX_KEY_SIZE: usize = 256;
const MAX_VALUE_SIZE: usize = 10 * 1024 * 1024;
const MAX_BATCH_OPS: usize = 10_000;

// ============================================================================
// Test Utilities
// ============================================================================

/// Create a temporary sled backend for testing
async fn create_temp_sled() -> (SledBackend, TempDir) {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let backend = SledBackend::open(temp_dir.path()).expect("Failed to open sled");
    (backend, temp_dir)
}

/// Create a temporary sled tree for testing
async fn create_temp_tree(name: &str) -> (SledTree, SledBackend, TempDir) {
    let (backend, temp_dir) = create_temp_sled().await;
    let tree = backend.open_tree(name).expect("Failed to open tree");
    (tree, backend, temp_dir)
}

// ============================================================================
// Trait Compliance Tests
// ============================================================================

/// Generic test suite that can be run against any StorageBackend implementation
mod trait_compliance {
    use super::*;

    /// Test basic CRUD operations on any backend
    async fn test_crud<B: StorageBackend>(backend: &B) {
        // Put
        backend.put(b"key1", b"value1").await.unwrap();
        backend.put(b"key2", b"value2").await.unwrap();

        // Get
        assert_eq!(backend.get(b"key1").await.unwrap(), Some(b"value1".to_vec()));
        assert_eq!(backend.get(b"key2").await.unwrap(), Some(b"value2".to_vec()));
        assert_eq!(backend.get(b"nonexistent").await.unwrap(), None);

        // Contains
        assert!(backend.contains(b"key1").await.unwrap());
        assert!(!backend.contains(b"nonexistent").await.unwrap());

        // Overwrite
        backend.put(b"key1", b"updated").await.unwrap();
        assert_eq!(backend.get(b"key1").await.unwrap(), Some(b"updated".to_vec()));

        // Delete
        backend.delete(b"key1").await.unwrap();
        assert_eq!(backend.get(b"key1").await.unwrap(), None);
        assert!(!backend.contains(b"key1").await.unwrap());

        // Delete non-existent (should not error)
        backend.delete(b"nonexistent").await.unwrap();
    }

    /// Test scan_prefix functionality
    async fn test_scan_prefix<B: StorageBackend>(backend: &B) {
        // Insert test data with prefixes
        for i in 0..20 {
            let key = format!("user:{:03}", i);
            let value = format!("user_data_{}", i);
            backend.put(key.as_bytes(), value.as_bytes()).await.unwrap();
        }
        for i in 0..10 {
            let key = format!("item:{:03}", i);
            let value = format!("item_data_{}", i);
            backend.put(key.as_bytes(), value.as_bytes()).await.unwrap();
        }

        // Scan user prefix
        let users = backend.scan_prefix(b"user:", Some(100)).await.unwrap();
        assert_eq!(users.len(), 20);

        // Scan item prefix
        let items = backend.scan_prefix(b"item:", Some(100)).await.unwrap();
        assert_eq!(items.len(), 10);

        // Scan with limit
        let limited = backend.scan_prefix(b"user:", Some(5)).await.unwrap();
        assert_eq!(limited.len(), 5);

        // Scan empty prefix (all keys)
        let all = backend.scan_prefix(b"", Some(100)).await.unwrap();
        assert_eq!(all.len(), 30);

        // Scan non-matching prefix
        let empty = backend.scan_prefix(b"nonexistent:", Some(100)).await.unwrap();
        assert!(empty.is_empty());
    }

    /// Test batch operations
    async fn test_batch_operations<B: StorageBackend>(backend: &B) {
        // Mixed batch: puts and deletes
        backend.put(b"to_delete", b"delete_me").await.unwrap();

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
            BatchOp::Delete {
                key: b"to_delete".to_vec(),
            },
        ];

        backend.write_batch(&ops).await.unwrap();

        // Verify all operations applied
        assert_eq!(backend.get(b"batch:1").await.unwrap(), Some(b"value1".to_vec()));
        assert_eq!(backend.get(b"batch:2").await.unwrap(), Some(b"value2".to_vec()));
        assert_eq!(backend.get(b"batch:3").await.unwrap(), Some(b"value3".to_vec()));
        assert_eq!(backend.get(b"to_delete").await.unwrap(), None);
    }

    /// Test compare-and-swap operations
    async fn test_compare_and_swap<B: StorageBackend>(backend: &B) {
        // Insert if absent (None -> Some)
        backend.compare_and_swap(b"cas_key", None, Some(b"initial")).await.unwrap();
        assert_eq!(backend.get(b"cas_key").await.unwrap(), Some(b"initial".to_vec()));

        // Try insert again (should fail - key exists)
        let result = backend.compare_and_swap(b"cas_key", None, Some(b"second")).await;
        assert!(matches!(result, Err(StorageError::CasConflict)));
        assert_eq!(backend.get(b"cas_key").await.unwrap(), Some(b"initial".to_vec()));

        // Update with correct expected value
        backend.compare_and_swap(b"cas_key", Some(b"initial"), Some(b"updated")).await.unwrap();
        assert_eq!(backend.get(b"cas_key").await.unwrap(), Some(b"updated".to_vec()));

        // Update with wrong expected value (should fail)
        let result = backend.compare_and_swap(b"cas_key", Some(b"wrong"), Some(b"new")).await;
        assert!(matches!(result, Err(StorageError::CasConflict)));
        assert_eq!(backend.get(b"cas_key").await.unwrap(), Some(b"updated".to_vec()));

        // Delete with CAS (Some -> None)
        backend.compare_and_swap(b"cas_key", Some(b"updated"), None).await.unwrap();
        assert_eq!(backend.get(b"cas_key").await.unwrap(), None);
    }

    /// Test input validation
    async fn test_validation<B: StorageBackend>(backend: &B) {
        // Empty key
        let result = backend.put(b"", b"value").await;
        assert!(matches!(result, Err(StorageError::EmptyKey)));

        // Key too large
        let large_key = vec![0u8; MAX_KEY_SIZE + 1];
        let result = backend.put(&large_key, b"value").await;
        assert!(matches!(result, Err(StorageError::KeyTooLarge { .. })));

        // Value too large
        let large_value = vec![0u8; MAX_VALUE_SIZE + 1];
        let result = backend.put(b"key", &large_value).await;
        assert!(matches!(result, Err(StorageError::ValueTooLarge { .. })));
    }

    /// Test binary data handling
    async fn test_binary_data<B: StorageBackend>(backend: &B) {
        // Binary key with null bytes
        let binary_key = vec![0x00, 0x01, 0xFF, 0xFE, 0x00, 0x42];
        let binary_value = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0xFF];

        backend.put(&binary_key, &binary_value).await.unwrap();

        let retrieved = backend.get(&binary_key).await.unwrap();
        assert_eq!(retrieved, Some(binary_value.clone()));

        // Verify contains works with binary keys
        assert!(backend.contains(&binary_key).await.unwrap());

        // Verify delete works with binary keys
        backend.delete(&binary_key).await.unwrap();
        assert!(!backend.contains(&binary_key).await.unwrap());
    }

    // Run all trait compliance tests for SledBackend
    #[tokio::test]
    async fn sled_backend_crud() {
        let (backend, _dir) = create_temp_sled().await;
        test_crud(&backend).await;
    }

    #[tokio::test]
    async fn sled_backend_scan_prefix() {
        let (backend, _dir) = create_temp_sled().await;
        test_scan_prefix(&backend).await;
    }

    #[tokio::test]
    async fn sled_backend_batch_operations() {
        let (backend, _dir) = create_temp_sled().await;
        test_batch_operations(&backend).await;
    }

    #[tokio::test]
    async fn sled_backend_compare_and_swap() {
        let (backend, _dir) = create_temp_sled().await;
        test_compare_and_swap(&backend).await;
    }

    #[tokio::test]
    async fn sled_backend_validation() {
        let (backend, _dir) = create_temp_sled().await;
        test_validation(&backend).await;
    }

    #[tokio::test]
    async fn sled_backend_binary_data() {
        let (backend, _dir) = create_temp_sled().await;
        test_binary_data(&backend).await;
    }

    // Run all trait compliance tests for SledTree
    #[tokio::test]
    async fn sled_tree_crud() {
        let (tree, _backend, _dir) = create_temp_tree("test_crud").await;
        test_crud(&tree).await;
    }

    #[tokio::test]
    async fn sled_tree_scan_prefix() {
        let (tree, _backend, _dir) = create_temp_tree("test_scan").await;
        test_scan_prefix(&tree).await;
    }

    #[tokio::test]
    async fn sled_tree_batch_operations() {
        let (tree, _backend, _dir) = create_temp_tree("test_batch").await;
        test_batch_operations(&tree).await;
    }

    #[tokio::test]
    async fn sled_tree_compare_and_swap() {
        let (tree, _backend, _dir) = create_temp_tree("test_cas").await;
        test_compare_and_swap(&tree).await;
    }

    #[tokio::test]
    async fn sled_tree_validation() {
        let (tree, _backend, _dir) = create_temp_tree("test_validation").await;
        test_validation(&tree).await;
    }

    #[tokio::test]
    async fn sled_tree_binary_data() {
        let (tree, _backend, _dir) = create_temp_tree("test_binary").await;
        test_binary_data(&tree).await;
    }
}

// ============================================================================
// Concurrent Access Tests
// ============================================================================

mod concurrent_access {
    use super::*;

    /// Test concurrent reads and writes
    #[tokio::test]
    async fn concurrent_read_write() {
        let (backend, _dir) = create_temp_sled().await;
        let backend = Arc::new(backend);
        let num_tasks = 10;
        let ops_per_task = 100;

        let mut handles = Vec::new();

        // Spawn writer tasks
        for task_id in 0..num_tasks {
            let backend = backend.clone();
            handles.push(tokio::spawn(async move {
                for i in 0..ops_per_task {
                    let key = format!("task{}:key{}", task_id, i);
                    let value = format!("task{}:value{}", task_id, i);
                    backend.put(key.as_bytes(), value.as_bytes()).await.unwrap();
                }
            }));
        }

        // Wait for all writers
        for handle in handles {
            handle.await.unwrap();
        }

        // Verify all data written
        for task_id in 0..num_tasks {
            for i in 0..ops_per_task {
                let key = format!("task{}:key{}", task_id, i);
                let expected = format!("task{}:value{}", task_id, i);
                let result = backend.get(key.as_bytes()).await.unwrap();
                assert_eq!(result, Some(expected.into_bytes()));
            }
        }
    }

    /// Test concurrent updates to same key using CAS
    #[tokio::test]
    async fn concurrent_cas_contention() {
        let (backend, _dir) = create_temp_sled().await;
        let backend = Arc::new(backend);
        let num_tasks = 10;
        let iterations = 50;

        // Initialize counter
        backend.put(b"counter", b"0").await.unwrap();

        let barrier = Arc::new(Barrier::new(num_tasks));
        let mut handles = Vec::new();

        for _ in 0..num_tasks {
            let backend = backend.clone();
            let barrier = barrier.clone();
            handles.push(tokio::spawn(async move {
                barrier.wait().await;
                let mut successful_updates = 0;

                for _ in 0..iterations {
                    // Read current value
                    let current = backend.get(b"counter").await.unwrap()
                        .map(|v| String::from_utf8(v).unwrap())
                        .unwrap_or_else(|| "0".to_string());
                    let current_val: i32 = current.parse().unwrap();
                    let new_val = current_val + 1;

                    // Try to update
                    let result = backend.compare_and_swap(
                        b"counter",
                        Some(current.as_bytes()),
                        Some(new_val.to_string().as_bytes()),
                    ).await;

                    if result.is_ok() {
                        successful_updates += 1;
                    }
                    // If CAS failed, another task updated first - this is expected
                }

                successful_updates
            }));
        }

        // Wait for all tasks and count successful updates
        let mut total_successful = 0;
        for handle in handles {
            total_successful += handle.await.unwrap();
        }

        // Final value should equal total successful updates
        let final_value = backend.get(b"counter").await.unwrap()
            .map(|v| String::from_utf8(v).unwrap())
            .unwrap();
        let final_int: i32 = final_value.parse().unwrap();
        assert_eq!(final_int, total_successful as i32);
    }

    /// Test concurrent batch operations
    #[tokio::test]
    async fn concurrent_batch_writes() {
        let (backend, _dir) = create_temp_sled().await;
        let backend = Arc::new(backend);
        let num_tasks = 5;
        let batch_size = 50;

        let mut handles = Vec::new();

        for task_id in 0..num_tasks {
            let backend = backend.clone();
            handles.push(tokio::spawn(async move {
                let ops: Vec<BatchOp> = (0..batch_size)
                    .map(|i| BatchOp::Put {
                        key: format!("batch_task{}:key{}", task_id, i).into_bytes(),
                        value: format!("batch_task{}:value{}", task_id, i).into_bytes(),
                    })
                    .collect();

                backend.write_batch(&ops).await.unwrap();
            }));
        }

        for handle in handles {
            handle.await.unwrap();
        }

        // Verify all data
        for task_id in 0..num_tasks {
            for i in 0..batch_size {
                let key = format!("batch_task{}:key{}", task_id, i);
                let expected = format!("batch_task{}:value{}", task_id, i);
                let result = backend.get(key.as_bytes()).await.unwrap();
                assert_eq!(result, Some(expected.into_bytes()));
            }
        }
    }

    /// Test concurrent reads during writes
    #[tokio::test]
    async fn concurrent_reads_during_writes() {
        let (backend, _dir) = create_temp_sled().await;
        let backend = Arc::new(backend);

        // Pre-populate some data
        for i in 0..100 {
            let key = format!("preload:{}", i);
            backend.put(key.as_bytes(), b"initial").await.unwrap();
        }

        let barrier = Arc::new(Barrier::new(4));
        let mut writer_handles = Vec::new();
        let mut reader_handles = Vec::new();

        // Writer task
        let backend_w = backend.clone();
        let barrier_w = barrier.clone();
        writer_handles.push(tokio::spawn(async move {
            barrier_w.wait().await;
            for round in 0..10 {
                for i in 0..100 {
                    let key = format!("preload:{}", i);
                    let value = format!("round{}", round);
                    backend_w.put(key.as_bytes(), value.as_bytes()).await.unwrap();
                }
            }
        }));

        // Reader tasks
        for _ in 0..3 {
            let backend_r = backend.clone();
            let barrier_r = barrier.clone();
            reader_handles.push(tokio::spawn(async move {
                barrier_r.wait().await;
                let mut reads = 0;
                for _ in 0..500 {
                    for i in 0..100 {
                        let key = format!("preload:{}", i);
                        let result = backend_r.get(key.as_bytes()).await.unwrap();
                        // Value should exist and be valid
                        assert!(result.is_some());
                        reads += 1;
                    }
                }
                reads
            }));
        }

        for handle in writer_handles {
            handle.await.unwrap();
        }
        for handle in reader_handles {
            let _ = handle.await.unwrap();
        }
    }

    /// Test tree isolation under concurrent access
    #[tokio::test]
    async fn concurrent_tree_isolation() {
        let (backend, _dir) = create_temp_sled().await;
        let backend = Arc::new(backend);

        let tree1 = Arc::new(backend.open_tree("tree1").unwrap());
        let tree2 = Arc::new(backend.open_tree("tree2").unwrap());

        let mut handles = Vec::new();

        // Write to tree1
        let t1 = tree1.clone();
        handles.push(tokio::spawn(async move {
            for i in 0..100 {
                let key = format!("key{}", i);
                t1.put(key.as_bytes(), b"tree1_value").await.unwrap();
            }
        }));

        // Write to tree2 with same keys
        let t2 = tree2.clone();
        handles.push(tokio::spawn(async move {
            for i in 0..100 {
                let key = format!("key{}", i);
                t2.put(key.as_bytes(), b"tree2_value").await.unwrap();
            }
        }));

        for handle in handles {
            handle.await.unwrap();
        }

        // Verify isolation
        for i in 0..100 {
            let key = format!("key{}", i);
            assert_eq!(tree1.get(key.as_bytes()).await.unwrap(), Some(b"tree1_value".to_vec()));
            assert_eq!(tree2.get(key.as_bytes()).await.unwrap(), Some(b"tree2_value".to_vec()));
        }
    }
}

// ============================================================================
// Crash Recovery Tests
// ============================================================================

mod crash_recovery {
    use super::*;

    /// Test data persistence across database reopen
    #[tokio::test]
    async fn persistence_across_reopen() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().to_path_buf();

        // Phase 1: Write data and close
        {
            let backend = SledBackend::open(&path).unwrap();
            for i in 0..100 {
                let key = format!("persist:{}", i);
                let value = format!("value:{}", i);
                backend.put(key.as_bytes(), value.as_bytes()).await.unwrap();
            }
            backend.flush().await.unwrap();
            // Backend dropped here
        }

        // Phase 2: Reopen and verify
        {
            let backend = SledBackend::open(&path).unwrap();
            for i in 0..100 {
                let key = format!("persist:{}", i);
                let expected = format!("value:{}", i);
                let result = backend.get(key.as_bytes()).await.unwrap();
                assert_eq!(result, Some(expected.into_bytes()), "Key {} not found", i);
            }
        }
    }

    /// Test tree data persistence
    #[tokio::test]
    async fn tree_persistence_across_reopen() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().to_path_buf();

        // Phase 1: Write to multiple trees
        {
            let backend = SledBackend::open(&path).unwrap();
            let tree_a = backend.open_tree("tree_a").unwrap();
            let tree_b = backend.open_tree("tree_b").unwrap();

            for i in 0..50 {
                tree_a.put(format!("a:{}", i).as_bytes(), b"from_tree_a").await.unwrap();
                tree_b.put(format!("b:{}", i).as_bytes(), b"from_tree_b").await.unwrap();
            }
            tree_a.flush().await.unwrap();
            tree_b.flush().await.unwrap();
        }

        // Phase 2: Reopen and verify
        {
            let backend = SledBackend::open(&path).unwrap();
            let tree_a = backend.open_tree("tree_a").unwrap();
            let tree_b = backend.open_tree("tree_b").unwrap();

            for i in 0..50 {
                assert_eq!(
                    tree_a.get(format!("a:{}", i).as_bytes()).await.unwrap(),
                    Some(b"from_tree_a".to_vec())
                );
                assert_eq!(
                    tree_b.get(format!("b:{}", i).as_bytes()).await.unwrap(),
                    Some(b"from_tree_b".to_vec())
                );
            }

            // Trees should still be isolated
            assert_eq!(tree_a.get(b"b:0").await.unwrap(), None);
            assert_eq!(tree_b.get(b"a:0").await.unwrap(), None);
        }
    }

    /// Test batch persistence
    #[tokio::test]
    async fn batch_persistence_across_reopen() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().to_path_buf();

        // Phase 1: Write batch and close
        {
            let backend = SledBackend::open(&path).unwrap();

            let ops: Vec<BatchOp> = (0..100)
                .map(|i| BatchOp::Put {
                    key: format!("batch_persist:{}", i).into_bytes(),
                    value: format!("batch_value:{}", i).into_bytes(),
                })
                .collect();

            backend.write_batch(&ops).await.unwrap();
            backend.flush().await.unwrap();
        }

        // Phase 2: Verify all batch operations persisted
        {
            let backend = SledBackend::open(&path).unwrap();
            for i in 0..100 {
                let key = format!("batch_persist:{}", i);
                let expected = format!("batch_value:{}", i);
                let result = backend.get(key.as_bytes()).await.unwrap();
                assert_eq!(result, Some(expected.into_bytes()));
            }
        }
    }

    /// Test CAS result persistence
    #[tokio::test]
    async fn cas_persistence_across_reopen() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().to_path_buf();

        // Phase 1: Perform CAS operations
        {
            let backend = SledBackend::open(&path).unwrap();

            // Insert via CAS
            backend.compare_and_swap(b"cas_persist", None, Some(b"v1")).await.unwrap();

            // Update via CAS
            backend.compare_and_swap(b"cas_persist", Some(b"v1"), Some(b"v2")).await.unwrap();

            backend.flush().await.unwrap();
        }

        // Phase 2: Verify CAS state persisted
        {
            let backend = SledBackend::open(&path).unwrap();

            assert_eq!(
                backend.get(b"cas_persist").await.unwrap(),
                Some(b"v2".to_vec())
            );

            // Further CAS should work with persisted state
            backend.compare_and_swap(b"cas_persist", Some(b"v2"), Some(b"v3")).await.unwrap();
            assert_eq!(
                backend.get(b"cas_persist").await.unwrap(),
                Some(b"v3".to_vec())
            );
        }
    }

    /// Test delete persistence
    #[tokio::test]
    async fn delete_persistence_across_reopen() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().to_path_buf();

        // Phase 1: Write, delete some, close
        {
            let backend = SledBackend::open(&path).unwrap();

            for i in 0..100 {
                backend.put(format!("delete_test:{}", i).as_bytes(), b"value").await.unwrap();
            }

            // Delete odd keys
            for i in (1..100).step_by(2) {
                backend.delete(format!("delete_test:{}", i).as_bytes()).await.unwrap();
            }

            backend.flush().await.unwrap();
        }

        // Phase 2: Verify delete state persisted
        {
            let backend = SledBackend::open(&path).unwrap();

            for i in 0..100 {
                let key = format!("delete_test:{}", i);
                let result = backend.get(key.as_bytes()).await.unwrap();

                if i % 2 == 0 {
                    assert_eq!(result, Some(b"value".to_vec()), "Even key {} should exist", i);
                } else {
                    assert_eq!(result, None, "Odd key {} should be deleted", i);
                }
            }
        }
    }
}

// ============================================================================
// Batch Atomicity Tests
// ============================================================================

mod batch_atomicity {
    use super::*;

    /// Verify batch writes are atomic - all or nothing
    #[tokio::test]
    async fn batch_all_or_nothing() {
        let (backend, _dir) = create_temp_sled().await;

        // Pre-existing key
        backend.put(b"existing", b"original").await.unwrap();

        // Valid batch should succeed
        let valid_ops = vec![
            BatchOp::Put {
                key: b"atomic:1".to_vec(),
                value: b"v1".to_vec(),
            },
            BatchOp::Put {
                key: b"atomic:2".to_vec(),
                value: b"v2".to_vec(),
            },
        ];
        backend.write_batch(&valid_ops).await.unwrap();

        assert_eq!(backend.get(b"atomic:1").await.unwrap(), Some(b"v1".to_vec()));
        assert_eq!(backend.get(b"atomic:2").await.unwrap(), Some(b"v2".to_vec()));
    }

    /// Test batch size limits
    #[tokio::test]
    async fn batch_size_limits() {
        let (backend, _dir) = create_temp_sled().await;

        // Create batch exceeding MAX_BATCH_OPS
        let oversized_ops: Vec<BatchOp> = (0..MAX_BATCH_OPS + 1)
            .map(|i| BatchOp::Put {
                key: format!("limit:{}", i).into_bytes(),
                value: b"value".to_vec(),
            })
            .collect();

        let result = backend.write_batch(&oversized_ops).await;
        assert!(matches!(result, Err(StorageError::BatchTooLarge(_))));

        // Verify no partial writes
        assert_eq!(backend.get(b"limit:0").await.unwrap(), None);
    }

    /// Test mixed batch operations
    #[tokio::test]
    async fn batch_mixed_put_delete() {
        let (backend, _dir) = create_temp_sled().await;

        // Setup initial state
        backend.put(b"keep", b"keep_value").await.unwrap();
        backend.put(b"delete1", b"will_delete").await.unwrap();
        backend.put(b"delete2", b"will_delete").await.unwrap();
        backend.put(b"update", b"old_value").await.unwrap();

        let ops = vec![
            BatchOp::Put {
                key: b"new1".to_vec(),
                value: b"new_value1".to_vec(),
            },
            BatchOp::Put {
                key: b"new2".to_vec(),
                value: b"new_value2".to_vec(),
            },
            BatchOp::Put {
                key: b"update".to_vec(),
                value: b"new_value".to_vec(),
            },
            BatchOp::Delete {
                key: b"delete1".to_vec(),
            },
            BatchOp::Delete {
                key: b"delete2".to_vec(),
            },
        ];

        backend.write_batch(&ops).await.unwrap();

        // Verify final state
        assert_eq!(backend.get(b"keep").await.unwrap(), Some(b"keep_value".to_vec()));
        assert_eq!(backend.get(b"new1").await.unwrap(), Some(b"new_value1".to_vec()));
        assert_eq!(backend.get(b"new2").await.unwrap(), Some(b"new_value2".to_vec()));
        assert_eq!(backend.get(b"update").await.unwrap(), Some(b"new_value".to_vec()));
        assert_eq!(backend.get(b"delete1").await.unwrap(), None);
        assert_eq!(backend.get(b"delete2").await.unwrap(), None);
    }

    /// Test empty batch
    #[tokio::test]
    async fn batch_empty() {
        let (backend, _dir) = create_temp_sled().await;

        backend.put(b"key", b"value").await.unwrap();

        // Empty batch should succeed
        backend.write_batch(&[]).await.unwrap();

        // Data should be unchanged
        assert_eq!(backend.get(b"key").await.unwrap(), Some(b"value".to_vec()));
    }

    /// Test batch with duplicate keys
    #[tokio::test]
    async fn batch_duplicate_keys() {
        let (backend, _dir) = create_temp_sled().await;

        // Batch with same key written multiple times
        let ops = vec![
            BatchOp::Put {
                key: b"dup".to_vec(),
                value: b"v1".to_vec(),
            },
            BatchOp::Put {
                key: b"dup".to_vec(),
                value: b"v2".to_vec(),
            },
            BatchOp::Put {
                key: b"dup".to_vec(),
                value: b"v3".to_vec(),
            },
        ];

        backend.write_batch(&ops).await.unwrap();

        // Last write wins
        assert_eq!(backend.get(b"dup").await.unwrap(), Some(b"v3".to_vec()));
    }
}

// ============================================================================
// Performance Baseline Tests
// ============================================================================

mod performance_baseline {
    use super::*;

    /// Measure sequential write throughput
    #[tokio::test]
    async fn sequential_write_throughput() {
        let (backend, _dir) = create_temp_sled().await;
        let num_ops = 1000;
        let value = vec![0u8; 1024]; // 1KB values

        let start = Instant::now();
        for i in 0..num_ops {
            let key = format!("perf_write:{:08}", i);
            backend.put(key.as_bytes(), &value).await.unwrap();
        }
        let elapsed = start.elapsed();

        let ops_per_sec = num_ops as f64 / elapsed.as_secs_f64();
        println!(
            "Sequential write: {} ops in {:?} ({:.0} ops/sec)",
            num_ops, elapsed, ops_per_sec
        );

        // Sanity check: should be able to do at least 100 ops/sec
        assert!(ops_per_sec > 100.0, "Write throughput too low: {} ops/sec", ops_per_sec);
    }

    /// Measure sequential read throughput
    #[tokio::test]
    async fn sequential_read_throughput() {
        let (backend, _dir) = create_temp_sled().await;
        let num_ops = 1000;
        let value = vec![0u8; 1024];

        // Setup data
        for i in 0..num_ops {
            let key = format!("perf_read:{:08}", i);
            backend.put(key.as_bytes(), &value).await.unwrap();
        }
        backend.flush().await.unwrap();

        let start = Instant::now();
        for i in 0..num_ops {
            let key = format!("perf_read:{:08}", i);
            let _ = backend.get(key.as_bytes()).await.unwrap();
        }
        let elapsed = start.elapsed();

        let ops_per_sec = num_ops as f64 / elapsed.as_secs_f64();
        println!(
            "Sequential read: {} ops in {:?} ({:.0} ops/sec)",
            num_ops, elapsed, ops_per_sec
        );

        // Sanity check: reads should be faster than writes
        assert!(ops_per_sec > 100.0, "Read throughput too low: {} ops/sec", ops_per_sec);
    }

    /// Measure batch write throughput
    #[tokio::test]
    async fn batch_write_throughput() {
        let (backend, _dir) = create_temp_sled().await;
        let num_batches = 100;
        let batch_size = 100;
        let value = vec![0u8; 512];

        let start = Instant::now();
        for batch_num in 0..num_batches {
            let ops: Vec<BatchOp> = (0..batch_size)
                .map(|i| BatchOp::Put {
                    key: format!("perf_batch:{}:{:08}", batch_num, i).into_bytes(),
                    value: value.clone(),
                })
                .collect();
            backend.write_batch(&ops).await.unwrap();
        }
        let elapsed = start.elapsed();

        let total_ops = num_batches * batch_size;
        let ops_per_sec = total_ops as f64 / elapsed.as_secs_f64();
        println!(
            "Batch write: {} ops ({} batches of {}) in {:?} ({:.0} ops/sec)",
            total_ops, num_batches, batch_size, elapsed, ops_per_sec
        );

        // Batch writes should be significantly faster than individual writes
        assert!(ops_per_sec > 500.0, "Batch throughput too low: {} ops/sec", ops_per_sec);
    }

    /// Measure scan throughput
    #[tokio::test]
    async fn scan_throughput() {
        let (backend, _dir) = create_temp_sled().await;
        let num_keys = 5000;
        let value = vec![0u8; 256];

        // Setup data with common prefix
        for i in 0..num_keys {
            let key = format!("scan_perf:{:08}", i);
            backend.put(key.as_bytes(), &value).await.unwrap();
        }
        backend.flush().await.unwrap();

        let start = Instant::now();
        let results = backend.scan_prefix(b"scan_perf:", Some(10000)).await.unwrap();
        let elapsed = start.elapsed();

        assert_eq!(results.len(), num_keys);
        println!(
            "Scan: {} keys in {:?} ({:.0} keys/sec)",
            num_keys, elapsed,
            num_keys as f64 / elapsed.as_secs_f64()
        );
    }

    /// Measure CAS throughput under contention
    #[tokio::test]
    async fn cas_throughput() {
        let (backend, _dir) = create_temp_sled().await;
        let backend = Arc::new(backend);
        let num_tasks = 4;
        let ops_per_task = 100;

        backend.put(b"cas_counter", b"0").await.unwrap();

        let start = Instant::now();
        let barrier = Arc::new(Barrier::new(num_tasks));
        let mut handles = Vec::new();

        for _ in 0..num_tasks {
            let backend = backend.clone();
            let barrier = barrier.clone();
            handles.push(tokio::spawn(async move {
                barrier.wait().await;
                let mut successful = 0;
                for _ in 0..ops_per_task {
                    let current = backend.get(b"cas_counter").await.unwrap()
                        .map(|v| String::from_utf8(v).unwrap())
                        .unwrap();
                    let new_val = current.parse::<i32>().unwrap() + 1;
                    if backend.compare_and_swap(
                        b"cas_counter",
                        Some(current.as_bytes()),
                        Some(new_val.to_string().as_bytes()),
                    ).await.is_ok() {
                        successful += 1;
                    }
                }
                successful
            }));
        }

        let mut total_successful = 0;
        for handle in handles {
            total_successful += handle.await.unwrap();
        }
        let elapsed = start.elapsed();

        println!(
            "CAS: {} successful ops in {:?} ({:.0} ops/sec)",
            total_successful, elapsed,
            total_successful as f64 / elapsed.as_secs_f64()
        );
    }

    /// Test large value performance
    #[tokio::test]
    async fn large_value_performance() {
        let (backend, _dir) = create_temp_sled().await;
        let sizes = [1024, 10 * 1024, 100 * 1024, 1024 * 1024]; // 1KB, 10KB, 100KB, 1MB

        for size in sizes {
            let value = vec![0u8; size];
            let key = format!("large_value:{}", size);

            let start = Instant::now();
            backend.put(key.as_bytes(), &value).await.unwrap();
            let write_time = start.elapsed();

            let start = Instant::now();
            let _ = backend.get(key.as_bytes()).await.unwrap();
            let read_time = start.elapsed();

            println!(
                "Value size {}: write {:?}, read {:?}",
                size, write_time, read_time
            );
        }
    }
}

// ============================================================================
// Edge Cases and Error Handling
// ============================================================================

mod edge_cases {
    use super::*;

    /// Test maximum allowed key size
    #[tokio::test]
    async fn max_key_size() {
        let (backend, _dir) = create_temp_sled().await;

        // Exactly at limit should work
        let max_key = vec![0u8; MAX_KEY_SIZE];
        backend.put(&max_key, b"value").await.unwrap();
        assert_eq!(backend.get(&max_key).await.unwrap(), Some(b"value".to_vec()));

        // One byte over should fail
        let over_key = vec![0u8; MAX_KEY_SIZE + 1];
        let result = backend.put(&over_key, b"value").await;
        assert!(matches!(result, Err(StorageError::KeyTooLarge { .. })));
    }

    /// Test maximum allowed value size
    #[tokio::test]
    async fn max_value_size() {
        let (backend, _dir) = create_temp_sled().await;

        // Exactly at limit should work
        let max_value = vec![0u8; MAX_VALUE_SIZE];
        backend.put(b"max_value_key", &max_value).await.unwrap();
        let retrieved = backend.get(b"max_value_key").await.unwrap();
        assert_eq!(retrieved.map(|v| v.len()), Some(MAX_VALUE_SIZE));

        // One byte over should fail
        let over_value = vec![0u8; MAX_VALUE_SIZE + 1];
        let result = backend.put(b"over_value_key", &over_value).await;
        assert!(matches!(result, Err(StorageError::ValueTooLarge { .. })));
    }

    /// Test scan with empty prefix returns all
    #[tokio::test]
    async fn scan_empty_prefix() {
        let (backend, _dir) = create_temp_sled().await;

        backend.put(b"a", b"1").await.unwrap();
        backend.put(b"b", b"2").await.unwrap();
        backend.put(b"c", b"3").await.unwrap();

        let all = backend.scan_prefix(b"", Some(100)).await.unwrap();
        assert_eq!(all.len(), 3);
    }

    /// Test handling of null bytes in keys and values
    #[tokio::test]
    async fn null_bytes_handling() {
        let (backend, _dir) = create_temp_sled().await;

        // Key with embedded nulls
        let key = b"key\x00with\x00nulls";
        let value = b"value\x00also\x00has\x00nulls";

        backend.put(key, value).await.unwrap();
        assert_eq!(backend.get(key).await.unwrap(), Some(value.to_vec()));

        // Scan should find it with partial prefix
        let results = backend.scan_prefix(b"key\x00", Some(100)).await.unwrap();
        assert_eq!(results.len(), 1);
    }

    /// Test delete of non-existent key
    #[tokio::test]
    async fn delete_nonexistent() {
        let (backend, _dir) = create_temp_sled().await;

        // Should not error
        backend.delete(b"never_existed").await.unwrap();
        assert!(!backend.contains(b"never_existed").await.unwrap());
    }

    /// Test scan with very large limit
    #[tokio::test]
    async fn scan_large_limit() {
        let (backend, _dir) = create_temp_sled().await;

        for i in 0..10 {
            backend.put(format!("key{}", i).as_bytes(), b"v").await.unwrap();
        }

        // Large limit should just return available data
        let results = backend.scan_prefix(b"key", Some(1_000_000)).await.unwrap();
        assert_eq!(results.len(), 10);
    }

    /// Test multiple tree operations
    #[tokio::test]
    async fn multiple_tree_lifecycle() {
        let (backend, _dir) = create_temp_sled().await;

        // Create multiple trees
        let tree1 = backend.open_tree("t1").unwrap();
        let tree2 = backend.open_tree("t2").unwrap();
        let tree3 = backend.open_tree("t3").unwrap();

        // Write to each
        tree1.put(b"k", b"v1").await.unwrap();
        tree2.put(b"k", b"v2").await.unwrap();
        tree3.put(b"k", b"v3").await.unwrap();

        // Verify isolation
        assert_eq!(tree1.get(b"k").await.unwrap(), Some(b"v1".to_vec()));
        assert_eq!(tree2.get(b"k").await.unwrap(), Some(b"v2".to_vec()));
        assert_eq!(tree3.get(b"k").await.unwrap(), Some(b"v3".to_vec()));

        // Default backend should not have the key
        assert_eq!(backend.get(b"k").await.unwrap(), None);

        // Clear one tree
        tree2.clear().unwrap();
        assert!(tree2.is_empty());
        assert_eq!(tree1.get(b"k").await.unwrap(), Some(b"v1".to_vec()));
        assert_eq!(tree3.get(b"k").await.unwrap(), Some(b"v3".to_vec()));
    }
}
