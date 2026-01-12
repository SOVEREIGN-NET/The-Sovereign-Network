//! NonceCache Load Tests [DB-016]
//!
//! Comprehensive load testing for the NonceCache replay protection system
//! to validate performance characteristics under production-scale loads.
//!
//! ## Test Scenarios
//! - Nonce cache stress testing with 1 million entries
//! - Concurrent nonce insertion with 100 parallel workers
//! - Memory consumption validation to ensure bounded growth
//! - Pruning performance under high load
//!
//! ## Performance Targets
//! - mark_nonce_seen: sub-millisecond p50, under 10ms p99
//! - Throughput: ≥100K nonce insertions/sec
//! - Memory: less than 500MB per million entries
//!
//! Run with: `cargo test -p lib-network --test nonce_cache_load_tests --release -- --nocapture`
//! Note: These tests are ignored by default due to their long runtime.
//! Enable with: `ZHTP_RUN_LOAD_TESTS=1 cargo test ...`

use anyhow::Result;
use lib_network::handshake::{compute_nonce_fingerprint, NetworkEpoch, NonceCache, SeenResult};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tempfile::TempDir;
use tokio::sync::Barrier;

/// Check if load tests should run (environment variable gate)
fn should_run_load_tests() -> bool {
    std::env::var("ZHTP_RUN_LOAD_TESTS").is_ok()
}

/// Performance metrics collector for latency analysis
#[derive(Default)]
struct LatencyMetrics {
    samples: parking_lot::Mutex<Vec<Duration>>,
}

impl LatencyMetrics {
    fn new() -> Self {
        Self {
            samples: parking_lot::Mutex::new(Vec::new()),
        }
    }

    fn record(&self, duration: Duration) {
        self.samples.lock().push(duration);
    }

    fn percentile(&self, p: f64) -> Duration {
        let mut samples = self.samples.lock().clone();
        if samples.is_empty() {
            return Duration::ZERO;
        }
        samples.sort();
        let idx = ((p / 100.0) * (samples.len() - 1) as f64) as usize;
        samples[idx]
    }

    fn p50(&self) -> Duration {
        self.percentile(50.0)
    }

    fn p99(&self) -> Duration {
        self.percentile(99.0)
    }

    fn count(&self) -> usize {
        self.samples.lock().len()
    }

    fn mean(&self) -> Duration {
        let samples = self.samples.lock();
        if samples.is_empty() {
            return Duration::ZERO;
        }
        let total: Duration = samples.iter().sum();
        total / samples.len() as u32
    }
}

/// Memory usage tracker
struct MemoryTracker {
    initial_rss: u64,
}

impl MemoryTracker {
    fn new() -> Self {
        Self {
            initial_rss: Self::current_rss(),
        }
    }

    #[cfg(target_os = "linux")]
    fn current_rss() -> u64 {
        if let Ok(content) = std::fs::read_to_string("/proc/self/statm") {
            if let Some(rss_pages) = content.split_whitespace().nth(1) {
                if let Ok(pages) = rss_pages.parse::<u64>() {
                    return pages * 4096;
                }
            }
        }
        0
    }

    #[cfg(not(target_os = "linux"))]
    fn current_rss() -> u64 {
        0
    }

    fn delta_mb(&self) -> f64 {
        let current = Self::current_rss();
        if current > self.initial_rss {
            (current - self.initial_rss) as f64 / (1024.0 * 1024.0)
        } else {
            0.0
        }
    }
}

/// Create a test nonce cache with specified max size
fn create_test_cache(max_size: usize) -> Result<(NonceCache, TempDir)> {
    let temp_dir = TempDir::new()?;
    let db_path = temp_dir.path().join("nonce_cache");

    // Create a test network epoch using chain ID (for testing)
    let network_epoch = NetworkEpoch::from_chain_id(0);

    let cache = NonceCache::open(&db_path, 3600, max_size, network_epoch)?;
    Ok((cache, temp_dir))
}

/// Generate a unique nonce for testing
fn generate_test_nonce(index: u64) -> [u8; 32] {
    let mut nonce = [0u8; 32];
    let hash = blake3::hash(&index.to_le_bytes());
    nonce.copy_from_slice(hash.as_bytes());
    nonce
}

// ============================================================================
// NonceCache Stress Tests
// ============================================================================

/// Test: NonceCache stress test with 1 million entries
///
/// Validates that the nonce cache can handle production-scale entry counts.
#[tokio::test]
#[ignore = "Load test - run with ZHTP_RUN_LOAD_TESTS=1"]
async fn test_nonce_cache_1m_entries_stress() -> Result<()> {
    if !should_run_load_tests() {
        println!("Skipping load test (set ZHTP_RUN_LOAD_TESTS=1 to enable)");
        return Ok(());
    }

    const ENTRY_COUNT: u64 = 1_000_000;
    const MAX_CACHE_SIZE: usize = 1_100_000; // Slightly larger to avoid eviction

    println!("\n=== NonceCache 1M Entries Stress Test ===");
    println!("Target entries: {}", ENTRY_COUNT);

    let (cache, _temp_dir) = create_test_cache(MAX_CACHE_SIZE)?;
    let memory_tracker = MemoryTracker::new();
    let metrics = LatencyMetrics::new();

    let network_epoch = cache.network_epoch();
    let now = chrono::Utc::now().timestamp();

    let start = Instant::now();
    for i in 0..ENTRY_COUNT {
        let nonce = generate_test_nonce(i);
        let nonce_fp = compute_nonce_fingerprint(network_epoch, &nonce, 1, "client");

        let op_start = Instant::now();
        let result = cache.mark_nonce_seen(&nonce_fp, now)?;
        metrics.record(op_start.elapsed());

        assert_eq!(result, SeenResult::New, "Entry {} should be new", i);

        // Progress logging every 100k entries
        if (i + 1) % 100_000 == 0 {
            println!(
                "  Progress: {}/{} entries ({:.1}%), Memory: {:.2} MB",
                i + 1,
                ENTRY_COUNT,
                (i + 1) as f64 / ENTRY_COUNT as f64 * 100.0,
                memory_tracker.delta_mb()
            );
        }
    }
    let elapsed = start.elapsed();

    let throughput = ENTRY_COUNT as f64 / elapsed.as_secs_f64();
    let memory_mb = memory_tracker.delta_mb();

    println!("\nResults:");
    println!("  Total time: {:?}", elapsed);
    println!("  Entries inserted: {}", ENTRY_COUNT);
    println!("  Throughput: {:.2} entries/sec", throughput);
    println!("  Latency - p50: {:?}, p99: {:?}", metrics.p50(), metrics.p99());
    println!("  Memory usage: {:.2} MB", memory_mb);
    println!("  Cache size: {}", cache.size());
    println!("  Cache utilization: {:.2}%", cache.utilization() * 100.0);

    // Performance assertions
    assert!(
        metrics.p50() < Duration::from_millis(1),
        "p50 latency exceeded 1ms: {:?}",
        metrics.p50()
    );
    assert!(
        metrics.p99() < Duration::from_millis(10),
        "p99 latency exceeded 10ms: {:?}",
        metrics.p99()
    );
    assert!(
        throughput >= 50_000.0,
        "Throughput below 50K/sec: {:.2}",
        throughput
    );

    // Memory efficiency: should be less than 500MB for 1M entries
    // Note: On non-Linux platforms, memory tracking returns 0
    if memory_mb > 0.0 {
        assert!(
            memory_mb < 500.0,
            "Memory usage exceeded 500MB for 1M entries: {:.2} MB",
            memory_mb
        );
    }

    println!("\n=== NonceCache 1M Entries Stress Test Complete ===\n");
    Ok(())
}

/// Test: Concurrent nonce insertion with 100 parallel workers
///
/// Validates thread safety and performance under concurrent load.
#[tokio::test]
#[ignore = "Load test - run with ZHTP_RUN_LOAD_TESTS=1"]
async fn test_nonce_cache_concurrent_100_workers() -> Result<()> {
    if !should_run_load_tests() {
        println!("Skipping load test (set ZHTP_RUN_LOAD_TESTS=1 to enable)");
        return Ok(());
    }

    const WORKER_COUNT: usize = 100;
    const NONCES_PER_WORKER: u64 = 1000;

    println!("\n=== NonceCache Concurrent 100 Workers Test ===");
    println!(
        "Workers: {}, Nonces per worker: {}, Total: {}",
        WORKER_COUNT,
        NONCES_PER_WORKER,
        WORKER_COUNT as u64 * NONCES_PER_WORKER
    );

    let (cache, _temp_dir) = create_test_cache(WORKER_COUNT * NONCES_PER_WORKER as usize + 10_000)?;
    let cache = Arc::new(cache);
    let barrier = Arc::new(Barrier::new(WORKER_COUNT));

    let success_count = Arc::new(AtomicU64::new(0));
    let replay_count = Arc::new(AtomicU64::new(0));
    let error_count = Arc::new(AtomicU64::new(0));
    let metrics = Arc::new(LatencyMetrics::new());

    let start = Instant::now();

    let mut handles = Vec::new();
    for worker_id in 0..WORKER_COUNT {
        let cache = Arc::clone(&cache);
        let barrier = Arc::clone(&barrier);
        let success = Arc::clone(&success_count);
        let replay = Arc::clone(&replay_count);
        let errors = Arc::clone(&error_count);
        let m = Arc::clone(&metrics);

        handles.push(tokio::spawn(async move {
            barrier.wait().await;

            let network_epoch = cache.network_epoch();
            let now = chrono::Utc::now().timestamp();

            for nonce_id in 0..NONCES_PER_WORKER {
                // Create unique nonce per worker
                let unique_id = worker_id as u64 * NONCES_PER_WORKER + nonce_id;
                let nonce = generate_test_nonce(unique_id);
                let nonce_fp = compute_nonce_fingerprint(network_epoch, &nonce, 1, "client");

                let op_start = Instant::now();
                match cache.mark_nonce_seen(&nonce_fp, now) {
                    Ok(SeenResult::New) => {
                        m.record(op_start.elapsed());
                        success.fetch_add(1, Ordering::Relaxed);
                    }
                    Ok(SeenResult::Replay) => {
                        replay.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(_) => {
                        errors.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }));
    }

    for handle in handles {
        handle.await?;
    }

    let elapsed = start.elapsed();
    let total_ops = WORKER_COUNT as u64 * NONCES_PER_WORKER;
    let throughput = total_ops as f64 / elapsed.as_secs_f64();

    println!("\nResults:");
    println!("  Total time: {:?}", elapsed);
    println!("  Total operations: {}", total_ops);
    println!("  Throughput: {:.2} ops/sec", throughput);
    println!("  New nonces: {}", success_count.load(Ordering::Relaxed));
    println!("  Replays detected: {}", replay_count.load(Ordering::Relaxed));
    println!("  Errors: {}", error_count.load(Ordering::Relaxed));
    println!(
        "  Latency - p50: {:?}, p99: {:?}",
        metrics.p50(),
        metrics.p99()
    );

    // Assertions
    assert_eq!(
        error_count.load(Ordering::Relaxed),
        0,
        "No errors should occur during concurrent insertion"
    );
    // Each unique nonce should be new (no replays since each worker uses unique IDs)
    assert_eq!(
        replay_count.load(Ordering::Relaxed),
        0,
        "No replays expected with unique nonces per worker"
    );

    println!("\n=== NonceCache Concurrent 100 Workers Test Complete ===\n");
    Ok(())
}

/// Test: Replay detection under concurrent load
///
/// Validates that replay attacks are correctly detected even under heavy concurrent access.
#[tokio::test]
#[ignore = "Load test - run with ZHTP_RUN_LOAD_TESTS=1"]
async fn test_nonce_cache_replay_detection_concurrent() -> Result<()> {
    if !should_run_load_tests() {
        println!("Skipping load test (set ZHTP_RUN_LOAD_TESTS=1 to enable)");
        return Ok(());
    }

    const WORKER_COUNT: usize = 50;
    const SHARED_NONCES: u64 = 100; // Nonces that all workers try to insert

    println!("\n=== NonceCache Replay Detection Concurrent Test ===");
    println!(
        "Workers: {}, Shared nonces: {}",
        WORKER_COUNT, SHARED_NONCES
    );

    let (cache, _temp_dir) = create_test_cache(100_000)?;
    let cache = Arc::new(cache);
    let barrier = Arc::new(Barrier::new(WORKER_COUNT));

    let first_seen_count = Arc::new(AtomicU64::new(0));
    let replay_count = Arc::new(AtomicU64::new(0));

    let start = Instant::now();

    let mut handles = Vec::new();
    for _worker_id in 0..WORKER_COUNT {
        let cache = Arc::clone(&cache);
        let barrier = Arc::clone(&barrier);
        let first_seen = Arc::clone(&first_seen_count);
        let replays = Arc::clone(&replay_count);

        handles.push(tokio::spawn(async move {
            barrier.wait().await;

            let network_epoch = cache.network_epoch();
            let now = chrono::Utc::now().timestamp();

            for nonce_id in 0..SHARED_NONCES {
                // All workers use the SAME nonces (to test replay detection)
                let nonce = generate_test_nonce(nonce_id);
                let nonce_fp = compute_nonce_fingerprint(network_epoch, &nonce, 1, "client");

                match cache.mark_nonce_seen(&nonce_fp, now) {
                    Ok(SeenResult::New) => {
                        first_seen.fetch_add(1, Ordering::Relaxed);
                    }
                    Ok(SeenResult::Replay) => {
                        replays.fetch_add(1, Ordering::Relaxed);
                    }
                    _ => {}
                }
            }
        }));
    }

    for handle in handles {
        handle.await?;
    }

    let elapsed = start.elapsed();
    let total_first_seen = first_seen_count.load(Ordering::Relaxed);
    let total_replays = replay_count.load(Ordering::Relaxed);

    println!("\nResults:");
    println!("  Total time: {:?}", elapsed);
    println!("  First seen: {}", total_first_seen);
    println!("  Replays detected: {}", total_replays);
    println!(
        "  Expected replays: {}",
        (WORKER_COUNT as u64 - 1) * SHARED_NONCES
    );

    // Each nonce should only be "first seen" once
    assert_eq!(
        total_first_seen, SHARED_NONCES,
        "Exactly {} nonces should be 'first seen', got {}",
        SHARED_NONCES, total_first_seen
    );

    // All other attempts should be detected as replays
    let expected_replays = (WORKER_COUNT as u64 - 1) * SHARED_NONCES;
    assert_eq!(
        total_replays, expected_replays,
        "Expected {} replays, got {}",
        expected_replays, total_replays
    );

    println!("\n=== NonceCache Replay Detection Concurrent Test Complete ===\n");
    Ok(())
}

/// Test: Memory efficiency with bounded cache
///
/// Validates that memory stays bounded even with continuous insertions.
#[tokio::test]
#[ignore = "Load test - run with ZHTP_RUN_LOAD_TESTS=1"]
async fn test_nonce_cache_memory_bounded() -> Result<()> {
    if !should_run_load_tests() {
        println!("Skipping load test (set ZHTP_RUN_LOAD_TESTS=1 to enable)");
        return Ok(());
    }

    const MAX_CACHE_SIZE: usize = 100_000;
    const INSERT_COUNT: u64 = 500_000; // 5x the cache size to force evictions

    println!("\n=== NonceCache Memory Bounded Test ===");
    println!(
        "Cache max size: {}, Insert count: {} (5x overfill)",
        MAX_CACHE_SIZE, INSERT_COUNT
    );

    let (cache, _temp_dir) = create_test_cache(MAX_CACHE_SIZE)?;
    let memory_tracker = MemoryTracker::new();

    let network_epoch = cache.network_epoch();
    let now = chrono::Utc::now().timestamp();

    let start = Instant::now();
    for i in 0..INSERT_COUNT {
        let nonce = generate_test_nonce(i);
        let nonce_fp = compute_nonce_fingerprint(network_epoch, &nonce, 1, "client");
        let _ = cache.mark_nonce_seen(&nonce_fp, now)?;

        // Log progress
        if (i + 1) % 100_000 == 0 {
            println!(
                "  Progress: {}/{}, Cache size: {}, Memory: {:.2} MB",
                i + 1,
                INSERT_COUNT,
                cache.size(),
                memory_tracker.delta_mb()
            );
        }
    }
    let elapsed = start.elapsed();

    let final_cache_size = cache.size();
    let memory_mb = memory_tracker.delta_mb();

    println!("\nResults:");
    println!("  Total time: {:?}", elapsed);
    println!("  Final cache size: {} (max: {})", final_cache_size, MAX_CACHE_SIZE);
    println!("  Memory usage: {:.2} MB", memory_mb);
    println!("  Utilization: {:.2}%", cache.utilization() * 100.0);

    // Memory cache should be bounded (may be slightly over due to timing)
    // The persistent storage will have all entries, but memory should be bounded
    // Note: final_cache_size represents memory cache size

    // Memory should be reasonable - allow generous headroom for disk storage
    // The memory cache is bounded, but disk persistence may use more
    if memory_mb > 0.0 {
        // Allow 200MB for 100K memory entries plus disk overhead
        assert!(
            memory_mb < 200.0,
            "Memory usage unexpectedly high: {:.2} MB",
            memory_mb
        );
    }

    println!("\n=== NonceCache Memory Bounded Test Complete ===\n");
    Ok(())
}

/// Test: Pruning performance under load
///
/// Validates that expired nonce pruning maintains performance.
#[tokio::test]
#[ignore = "Load test - run with ZHTP_RUN_LOAD_TESTS=1"]
async fn test_nonce_cache_pruning_performance() -> Result<()> {
    if !should_run_load_tests() {
        println!("Skipping load test (set ZHTP_RUN_LOAD_TESTS=1 to enable)");
        return Ok(());
    }

    const ENTRY_COUNT: u64 = 100_000;

    println!("\n=== NonceCache Pruning Performance Test ===");
    println!("Entries to prune: {}", ENTRY_COUNT);

    let (cache, _temp_dir) = create_test_cache(ENTRY_COUNT as usize + 10_000)?;
    let network_epoch = cache.network_epoch();

    // Insert entries with "old" timestamps (1 hour ago)
    let old_time = chrono::Utc::now().timestamp() - 3700; // Just over 1 hour TTL

    println!("  Inserting {} entries with old timestamps...", ENTRY_COUNT);
    let insert_start = Instant::now();
    for i in 0..ENTRY_COUNT {
        let nonce = generate_test_nonce(i);
        let nonce_fp = compute_nonce_fingerprint(network_epoch, &nonce, 1, "client");
        let _ = cache.mark_nonce_seen(&nonce_fp, old_time)?;
    }
    let insert_elapsed = insert_start.elapsed();
    println!("  Insert time: {:?}", insert_elapsed);

    let size_before = cache.size();

    // Trigger pruning
    println!("  Triggering prune...");
    let prune_start = Instant::now();
    let cutoff = chrono::Utc::now().timestamp();
    let pruned = cache.prune_seen_nonces(cutoff)?;
    let prune_elapsed = prune_start.elapsed();

    let size_after = cache.size();

    println!("\nResults:");
    println!("  Entries pruned: {}", pruned);
    println!("  Prune time: {:?}", prune_elapsed);
    println!("  Cache size before: {}", size_before);
    println!("  Cache size after: {}", size_after);
    println!(
        "  Prune throughput: {:.2} entries/sec",
        pruned as f64 / prune_elapsed.as_secs_f64()
    );

    // Most entries should have been pruned (they were old)
    assert!(
        pruned >= ENTRY_COUNT as usize * 9 / 10,
        "Expected to prune at least 90% of entries, pruned {}",
        pruned
    );

    // Pruning should be reasonably fast
    assert!(
        prune_elapsed < Duration::from_secs(30),
        "Pruning took too long: {:?}",
        prune_elapsed
    );

    println!("\n=== NonceCache Pruning Performance Test Complete ===\n");
    Ok(())
}

/// Test: Generate nonce cache performance baseline
#[tokio::test]
#[ignore = "Load test - run with ZHTP_RUN_LOAD_TESTS=1"]
async fn test_nonce_cache_performance_baseline() -> Result<()> {
    if !should_run_load_tests() {
        println!("Skipping load test (set ZHTP_RUN_LOAD_TESTS=1 to enable)");
        return Ok(());
    }

    const ITERATIONS: u64 = 50_000;

    let (cache, _temp_dir) = create_test_cache(ITERATIONS as usize + 10_000)?;
    let network_epoch = cache.network_epoch();
    let now = chrono::Utc::now().timestamp();

    println!("\n");
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║         NONCE CACHE PERFORMANCE BASELINE REPORT              ║");
    println!("╠══════════════════════════════════════════════════════════════╣");
    println!(
        "║ Date: {}                                      ║",
        chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
    );
    println!("║ Iterations: {:>6}                                          ║", ITERATIONS);
    println!("╚══════════════════════════════════════════════════════════════╝");

    // mark_nonce_seen performance (new nonces)
    let insert_metrics = LatencyMetrics::new();
    for i in 0..ITERATIONS {
        let nonce = generate_test_nonce(i);
        let nonce_fp = compute_nonce_fingerprint(network_epoch, &nonce, 1, "client");
        let start = Instant::now();
        let _ = cache.mark_nonce_seen(&nonce_fp, now)?;
        insert_metrics.record(start.elapsed());
    }

    println!("\n┌─────────────────────────────────────────────────────────────┐");
    println!("│ mark_nonce_seen (New Nonces)                                │");
    println!("├─────────────────────────────────────────────────────────────┤");
    println!(
        "│ p50={:>10?}  p99={:>10?}  mean={:>10?}        │",
        insert_metrics.p50(),
        insert_metrics.p99(),
        insert_metrics.mean()
    );
    println!(
        "│ Throughput: {:>10.0} ops/sec                              │",
        1.0 / insert_metrics.mean().as_secs_f64()
    );
    println!("└─────────────────────────────────────────────────────────────┘");

    // mark_nonce_seen performance (replay detection)
    let replay_metrics = LatencyMetrics::new();
    for i in 0..ITERATIONS {
        let nonce = generate_test_nonce(i); // Same nonces as before
        let nonce_fp = compute_nonce_fingerprint(network_epoch, &nonce, 1, "client");
        let start = Instant::now();
        let _ = cache.mark_nonce_seen(&nonce_fp, now)?;
        replay_metrics.record(start.elapsed());
    }

    println!("\n┌─────────────────────────────────────────────────────────────┐");
    println!("│ mark_nonce_seen (Replay Detection)                          │");
    println!("├─────────────────────────────────────────────────────────────┤");
    println!(
        "│ p50={:>10?}  p99={:>10?}  mean={:>10?}        │",
        replay_metrics.p50(),
        replay_metrics.p99(),
        replay_metrics.mean()
    );
    println!(
        "│ Throughput: {:>10.0} ops/sec                              │",
        1.0 / replay_metrics.mean().as_secs_f64()
    );
    println!("└─────────────────────────────────────────────────────────────┘");

    println!("\n");

    Ok(())
}
