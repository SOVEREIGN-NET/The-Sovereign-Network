//! Performance benchmarks for persistent contract storage
//!
//! Run benchmarks with:
//! ```bash
//! cargo test --lib --release --features persistent-contracts -- --ignored bench_ --nocapture
//! ```

#[cfg(all(test, feature = "persistent-contracts"))]
mod benchmarks {
    use super::super::{
        CachedPersistentStorage, PersistentStorage, StateCache, StateRootComputation,
        StateVersionManager, WalRecoveryManager,
    };
    use crate::contracts::executor::ContractStorage;
    use std::time::Instant;
    use tempfile::TempDir;

    struct BenchResult {
        operation: String,
        num_operations: u64,
        duration_ms: f64,
        ops_per_sec: f64,
        latency_us: f64,
    }

    impl BenchResult {
        fn new(
            operation: &str,
            num_operations: u64,
            duration_ms: f64,
        ) -> Self {
            let ops_per_sec = num_operations as f64 / (duration_ms / 1000.0);
            let latency_us = (duration_ms * 1000.0) / num_operations as f64;

            Self {
                operation: operation.to_string(),
                num_operations,
                duration_ms,
                ops_per_sec,
                latency_us,
            }
        }

        fn print(&self) {
            println!(
                "{:<30} | {:>10} ops | {:>8.2} ms | {:>10.0} ops/s | {:>8.2} μs/op",
                self.operation,
                self.num_operations,
                self.duration_ms,
                self.ops_per_sec,
                self.latency_us
            );
        }
    }

    /// Benchmark cache hit performance
    #[test]
    #[ignore]
    fn bench_cache_hits() {
        let temp_dir = TempDir::new().unwrap();
        let storage = PersistentStorage::new(temp_dir.path().to_str().unwrap(), None).unwrap();
        let cached = CachedPersistentStorage::new(storage).unwrap();

        // Populate cache with 1000 entries
        for i in 0..1000 {
            let key = format!("key_{}", i).into_bytes();
            let value = format!("value_{}", i).into_bytes();
            let mut cached_mut = cached.clone();
            cached_mut.set(&key, &value).unwrap();
        }

        // Warm up JIT
        for _ in 0..100 {
            let _ = cached.get(b"key_0").unwrap();
        }

        // Benchmark repeated access
        let num_ops = 1_000_000;
        let start = Instant::now();

        for i in 0..num_ops {
            let key = format!("key_{}", i % 1000).into_bytes();
            let _ = cached.get(&key).unwrap();
        }

        let elapsed = start.elapsed();
        let result = BenchResult::new("Cache Hit (1M ops)", num_ops, elapsed.as_secs_f64() * 1000.0);

        println!("\n=== Cache Hit Benchmark ===");
        result.print();

        let stats = cached.cache_stats().unwrap();
        println!(
            "Cache stats: hits={}, misses={}, hit_rate={:.1}%\n",
            stats.hits,
            stats.misses,
            stats.hit_rate()
        );

        assert!(result.ops_per_sec > 500_000.0, "Cache hit throughput too low");
    }

    /// Benchmark cache miss performance (disk reads)
    #[test]
    #[ignore]
    fn bench_cache_misses() {
        let temp_dir = TempDir::new().unwrap();
        let storage = PersistentStorage::new(temp_dir.path().to_str().unwrap(), None).unwrap();
        let cached = CachedPersistentStorage::new(storage).unwrap();

        // Populate storage with 10k entries (but not in cache)
        for i in 0..10_000 {
            let key = format!("key_{}", i).into_bytes();
            let value = format!("value_{}", i).into_bytes();
            let mut cached_mut = cached.clone();
            cached_mut.set(&key, &value).unwrap();
        }

        // Clear cache to force misses
        cached.clear_cache().unwrap();

        // Benchmark cache misses (cold reads)
        let num_ops = 10_000;
        let start = Instant::now();

        for i in 0..num_ops {
            let key = format!("key_{}", i % 1000).into_bytes();
            let _ = cached.get(&key).unwrap();
        }

        let elapsed = start.elapsed();
        let result = BenchResult::new("Cache Miss (10k ops)", num_ops as u64, elapsed.as_secs_f64() * 1000.0);

        println!("\n=== Cache Miss Benchmark ===");
        result.print();

        let stats = cached.cache_stats().unwrap();
        println!(
            "Cache stats after cold reads: hits={}, misses={}, hit_rate={:.1}%\n",
            stats.hits,
            stats.misses,
            stats.hit_rate()
        );
    }

    /// Benchmark write performance
    #[test]
    #[ignore]
    fn bench_writes() {
        let temp_dir = TempDir::new().unwrap();
        let storage = PersistentStorage::new(temp_dir.path().to_str().unwrap(), None).unwrap();
        let mut cached = CachedPersistentStorage::new(storage).unwrap();

        let num_ops = 100_000;
        let start = Instant::now();

        for i in 0..num_ops {
            let key = format!("key_{}", i).into_bytes();
            let value = format!("value_data_{}", i).into_bytes();
            cached.set(&key, &value).unwrap();
        }

        let elapsed = start.elapsed();
        let result = BenchResult::new("Writes (100k ops)", num_ops as u64, elapsed.as_secs_f64() * 1000.0);

        println!("\n=== Write Performance Benchmark ===");
        result.print();
    }

    /// Benchmark delete performance
    #[test]
    #[ignore]
    fn bench_deletes() {
        let temp_dir = TempDir::new().unwrap();
        let storage = PersistentStorage::new(temp_dir.path().to_str().unwrap(), None).unwrap();
        let mut cached = CachedPersistentStorage::new(storage).unwrap();

        // Pre-populate
        for i in 0..50_000 {
            let key = format!("key_{}", i).into_bytes();
            let value = format!("value_{}", i).into_bytes();
            cached.set(&key, &value).unwrap();
        }

        let num_ops = 50_000;
        let start = Instant::now();

        for i in 0..num_ops {
            let key = format!("key_{}", i).into_bytes();
            cached.delete(&key).unwrap();
        }

        let elapsed = start.elapsed();
        let result = BenchResult::new("Deletes (50k ops)", num_ops as u64, elapsed.as_secs_f64() * 1000.0);

        println!("\n=== Delete Performance Benchmark ===");
        result.print();
    }

    /// Benchmark state root computation
    #[test]
    #[ignore]
    fn bench_state_root_computation() {
        let temp_dir = TempDir::new().unwrap();
        let storage = PersistentStorage::new(temp_dir.path().to_str().unwrap(), None).unwrap();

        // Add state entries at various scales
        let test_sizes = vec![1_000, 10_000, 100_000];

        println!("\n=== State Root Computation Benchmark ===");
        println!("{:<20} | {:<15} | {:<15}", "State Size", "Time (ms)", "Per 1k entries");

        for size in test_sizes {
            // Add entries
            for i in 0..size {
                let key = format!("state:100:contract_{}", i).into_bytes();
                let value = format!("state_value_{}", i).into_bytes();
                storage.set(&key, &value).unwrap();
            }

            let computer = StateRootComputation::new(storage.clone());

            let start = Instant::now();
            let _root = computer.compute_state_root(100).unwrap();
            let elapsed = start.elapsed();

            let per_1k = (elapsed.as_secs_f64() * 1000.0) / (size as f64 / 1000.0);

            println!(
                "{:<20} | {:>15.2} | {:>15.2}",
                format!("{} entries", size),
                elapsed.as_secs_f64() * 1000.0,
                per_1k
            );
        }

        println!();
    }

    /// Benchmark WAL recovery
    #[test]
    #[ignore]
    fn bench_wal_recovery() {
        let temp_dir = TempDir::new().unwrap();
        let storage = PersistentStorage::new(temp_dir.path().to_str().unwrap(), None).unwrap();

        // Create WAL entries at various scales
        let test_sizes = vec![100, 1_000, 10_000];

        println!("\n=== WAL Recovery Benchmark ===");
        println!("{:<20} | {:<15} | {:<15}", "WAL Entries", "Time (ms)", "Per entry (μs)");

        for size in test_sizes {
            // Create fresh storage for each test
            let temp_dir = TempDir::new().unwrap();
            let storage = PersistentStorage::new(temp_dir.path().to_str().unwrap(), None).unwrap();

            // Create WAL entries
            for height in 0..size {
                let key = format!("wal:{}", height).into_bytes();
                let value = b"incomplete_block".to_vec();
                storage.set(&key, &value).unwrap();
            }

            let recovery = WalRecoveryManager::new(storage.clone());

            let start = Instant::now();
            let stats = recovery.recover_from_crash().unwrap();
            let elapsed = start.elapsed();

            let per_entry = (elapsed.as_secs_f64() * 1_000_000.0) / size as f64;

            println!(
                "{:<20} | {:>15.2} | {:>15.2}",
                format!("{} entries", size),
                elapsed.as_secs_f64() * 1000.0,
                per_entry
            );

            println!("  -> Recovered: {}, Discarded: {}", stats.entries_recovered, stats.entries_discarded);
        }

        println!();
    }

    /// Benchmark version manager operations
    #[test]
    #[ignore]
    fn bench_versioning() {
        let temp_dir = TempDir::new().unwrap();
        let storage = PersistentStorage::new(temp_dir.path().to_str().unwrap(), None).unwrap();
        let version_mgr = StateVersionManager::new(storage.clone(), Some(1000));

        println!("\n=== Version Manager Benchmark ===");

        // Benchmark store_versioned
        let num_writes = 10_000;
        let start = Instant::now();

        for height in 0..100 {
            for i in 0..100 {
                let key = format!("contract:balance:user_{}", i).into_bytes();
                let value = format!("balance_{}", height * 100 + i).into_bytes();
                version_mgr.store_versioned(height, &key, &value).unwrap();
            }
        }

        let elapsed = start.elapsed();
        let result = BenchResult::new("Versioned Writes (10k ops)", num_writes, elapsed.as_secs_f64() * 1000.0);
        result.print();

        // Benchmark get_versioned
        let num_reads = 10_000;
        let start = Instant::now();

        for _ in 0..1000 {
            for i in 0..10 {
                let key = format!("contract:balance:user_{}", i).into_bytes();
                let _val = version_mgr.get_versioned(&key, 50).unwrap();
            }
        }

        let elapsed = start.elapsed();
        let result = BenchResult::new("Versioned Reads (10k ops)", num_reads as u64, elapsed.as_secs_f64() * 1000.0);
        result.print();

        println!();
    }

    /// Benchmark cache size impact on hit rate
    #[test]
    #[ignore]
    fn bench_cache_size_impact() {
        println!("\n=== Cache Size Impact on Hit Rate ===");
        println!(
            "{:<15} | {:<12} | {:<12} | {:<12}",
            "Cache Size (MB)", "Hit Rate (%)", "Entries", "Evictions"
        );

        let cache_sizes = vec![4, 16, 64, 128];

        for cache_size_mb in cache_sizes {
            let temp_dir = TempDir::new().unwrap();
            let storage = PersistentStorage::new(temp_dir.path().to_str().unwrap(), None).unwrap();

            let cache_config = super::super::CacheConfig {
                max_size_bytes: cache_size_mb * 1024 * 1024,
                track_stats: true,
            };

            let cached = CachedPersistentStorage::with_cache_config(storage, cache_config).unwrap();

            // Populate with varied key distribution
            for i in 0..10_000 {
                let key = format!("key_{}", i).into_bytes();
                let value = format!("value_{}", i % 100).into_bytes();
                let mut cached_mut = cached.clone();
                cached_mut.set(&key, &value).unwrap();
            }

            // Simulate workload with temporal locality
            for i in 0..50_000 {
                let key = format!("key_{}", i % 1000).into_bytes();
                let _ = cached.get(&key).unwrap();
            }

            let stats = cached.cache_stats().unwrap();
            println!(
                "{:<15} | {:>12.1} | {:>12} | {:>12}",
                cache_size_mb,
                stats.hit_rate(),
                stats.entry_count,
                stats.evictions
            );
        }

        println!();
    }

    /// Benchmark concurrent access
    #[test]
    #[ignore]
    fn bench_concurrent_access() {
        use std::sync::Arc;
        use std::thread;

        let temp_dir = Arc::new(TempDir::new().unwrap());
        let storage = Arc::new(
            PersistentStorage::new(temp_dir.path().to_str().unwrap(), None).unwrap(),
        );
        let mut cached = CachedPersistentStorage::new((*storage).clone()).unwrap();

        // Pre-populate
        for i in 0..1_000 {
            let key = format!("key_{}", i).into_bytes();
            let value = format!("value_{}", i).into_bytes();
            cached.set(&key, &value).unwrap();
        }

        // Wrap in Arc for concurrent access
        let cached = Arc::new(cached);

        println!("\n=== Concurrent Access Benchmark ===");

        for num_threads in [2, 4, 8, 16] {
            let start = Instant::now();
            let ops_per_thread = 100_000;
            let mut handles = vec![];

            for thread_id in 0..num_threads {
                let cached_clone = Arc::clone(&cached);
                let handle = thread::spawn(move || {
                    for i in 0..ops_per_thread {
                        let key = format!("key_{}", (thread_id * ops_per_thread + i) % 1000).into_bytes();
                        let _ = cached_clone.get(&key).unwrap();
                    }
                });
                handles.push(handle);
            }

            for handle in handles {
                handle.join().unwrap();
            }

            let elapsed = start.elapsed();
            let total_ops = num_threads * ops_per_thread;
            let ops_per_sec = total_ops as f64 / elapsed.as_secs_f64();

            println!(
                "Threads: {:>2} | Total ops: {:>10} | Time: {:>8.2}ms | Throughput: {:>10.0} ops/s",
                num_threads,
                total_ops,
                elapsed.as_secs_f64() * 1000.0,
                ops_per_sec
            );
        }

        println!();
    }

    /// Comprehensive performance suite
    #[test]
    #[ignore]
    fn bench_comprehensive_suite() {
        println!("\n╔════════════════════════════════════════════════════════════════╗");
        println!("║      Persistent Contract Storage Performance Benchmark         ║");
        println!("╚════════════════════════════════════════════════════════════════╝");

        bench_cache_hits();
        bench_cache_misses();
        bench_writes();
        bench_deletes();
        bench_state_root_computation();
        bench_wal_recovery();
        bench_versioning();
        bench_cache_size_impact();
        bench_concurrent_access();

        println!("╔════════════════════════════════════════════════════════════════╗");
        println!("║                   Benchmark Suite Complete                     ║");
        println!("╚════════════════════════════════════════════════════════════════╝\n");
    }
}
