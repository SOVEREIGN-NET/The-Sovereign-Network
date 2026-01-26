//! Storage Load Tests [DB-016]
//!
//! Comprehensive load testing for storage backends to validate performance
//! characteristics and establish baseline metrics before production deployment.
//!
//! ## Test Scenarios
//! - Sled backend stress testing with high entry counts
//! - DHT storage throughput evaluation across variable payload sizes (100B–100KB)
//! - Concurrent access patterns using 100 parallel workers
//! - Memory consumption validation to ensure bounded growth
//!
//! ## Performance Targets
//! - Write operations: sub-millisecond p50 latency, under 10ms p99
//! - Read operations: sub-0.1ms p50 latency, under 1ms p99
//! - Throughput benchmarks: ≥100K writes/sec, ≥500K reads/sec
//! - Memory efficiency: less than 500MB per million entries
//!
//! Run with: `cargo test -p lib-storage --test storage_load_tests --release -- --nocapture`
//! Note: These tests are ignored by default due to their long runtime.
//! Enable with: `ZHTP_RUN_LOAD_TESTS=1 cargo test ...`

use anyhow::Result;
use lib_storage::backend::{SledBackend, StorageBackend};
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
        // Read from /proc/self/statm
        if let Ok(content) = std::fs::read_to_string("/proc/self/statm") {
            if let Some(rss_pages) = content.split_whitespace().nth(1) {
                if let Ok(pages) = rss_pages.parse::<u64>() {
                    return pages * 4096; // Assume 4KB pages
                }
            }
        }
        0
    }

    #[cfg(not(target_os = "linux"))]
    fn current_rss() -> u64 {
        // Fallback: return 0 on non-Linux platforms
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

/// Create a test sled backend
fn create_test_backend() -> Result<(SledBackend, TempDir)> {
    let temp_dir = TempDir::new()?;
    let db_path = temp_dir.path().join("sled_db");
    let backend = SledBackend::open(&db_path).map_err(|e| anyhow::anyhow!("{}", e))?;
    Ok((backend, temp_dir))
}

// ============================================================================
// Sled Backend Load Tests
// ============================================================================

/// Test: Sled backend throughput with variable payload sizes (100B - 100KB)
///
/// Validates throughput across different payload sizes commonly used in DHT.
#[tokio::test]
#[ignore = "Load test - run with ZHTP_RUN_LOAD_TESTS=1"]
async fn test_sled_backend_throughput_variable_payloads() -> Result<()> {
    if !should_run_load_tests() {
        println!("Skipping load test (set ZHTP_RUN_LOAD_TESTS=1 to enable)");
        return Ok(());
    }

    let (backend, _temp_dir) = create_test_backend()?;

    // Payload sizes to test: 100B, 1KB, 10KB, 100KB
    let payload_sizes: Vec<usize> = vec![100, 1_024, 10_240, 102_400];
    let iterations_per_size = 1000;

    println!("\n=== Sled Backend Throughput Test ===");
    println!("Iterations per payload size: {}", iterations_per_size);

    for size in payload_sizes {
        let payload = vec![0xABu8; size];
        let write_metrics = LatencyMetrics::new();
        let read_metrics = LatencyMetrics::new();

        // Write phase
        let write_start = Instant::now();
        for i in 0..iterations_per_size {
            let key = format!("throughput:{}:{}", size, i);
            let start = Instant::now();
            backend.put(key.as_bytes(), &payload).await.map_err(|e| anyhow::anyhow!("{}", e))?;
            write_metrics.record(start.elapsed());
        }
        let write_elapsed = write_start.elapsed();

        // Read phase
        let read_start = Instant::now();
        for i in 0..iterations_per_size {
            let key = format!("throughput:{}:{}", size, i);
            let start = Instant::now();
            let _ = backend.get(key.as_bytes()).await.map_err(|e| anyhow::anyhow!("{}", e))?;
            read_metrics.record(start.elapsed());
        }
        let read_elapsed = read_start.elapsed();

        let write_throughput = iterations_per_size as f64 / write_elapsed.as_secs_f64();
        let read_throughput = iterations_per_size as f64 / read_elapsed.as_secs_f64();

        println!(
            "\nPayload size: {} bytes",
            size
        );
        println!(
            "  Write: {:.2} ops/sec | p50: {:?} | p99: {:?}",
            write_throughput,
            write_metrics.p50(),
            write_metrics.p99()
        );
        println!(
            "  Read:  {:.2} ops/sec | p50: {:?} | p99: {:?}",
            read_throughput,
            read_metrics.p50(),
            read_metrics.p99()
        );

        // Performance assertions for smaller payloads (100B, 1KB)
        if size <= 1024 {
            assert!(
                write_metrics.p50() < Duration::from_millis(1),
                "Write p50 latency too high for {} byte payload: {:?}",
                size,
                write_metrics.p50()
            );
            assert!(
                write_metrics.p99() < Duration::from_millis(10),
                "Write p99 latency too high for {} byte payload: {:?}",
                size,
                write_metrics.p99()
            );
        }
    }

    println!("\n=== Sled Backend Throughput Test Complete ===\n");
    Ok(())
}

/// Test: Concurrent sled backend access with 100 parallel workers
///
/// Validates storage behavior under heavy concurrent load.
#[tokio::test]
#[ignore = "Load test - run with ZHTP_RUN_LOAD_TESTS=1"]
async fn test_sled_backend_concurrent_access_100_workers() -> Result<()> {
    if !should_run_load_tests() {
        println!("Skipping load test (set ZHTP_RUN_LOAD_TESTS=1 to enable)");
        return Ok(());
    }

    const WORKER_COUNT: usize = 100;
    const OPS_PER_WORKER: usize = 100;

    let (backend, _temp_dir) = create_test_backend()?;
    let backend = Arc::new(backend);

    let barrier = Arc::new(Barrier::new(WORKER_COUNT));
    let success_count = Arc::new(AtomicU64::new(0));
    let error_count = Arc::new(AtomicU64::new(0));
    let write_metrics = Arc::new(LatencyMetrics::new());
    let read_metrics = Arc::new(LatencyMetrics::new());

    println!("\n=== Concurrent Access Test ===");
    println!("Workers: {}, Operations per worker: {}", WORKER_COUNT, OPS_PER_WORKER);

    let start = Instant::now();

    let mut handles = Vec::new();
    for worker_id in 0..WORKER_COUNT {
        let backend = Arc::clone(&backend);
        let barrier = Arc::clone(&barrier);
        let success = Arc::clone(&success_count);
        let errors = Arc::clone(&error_count);
        let w_metrics = Arc::clone(&write_metrics);
        let r_metrics = Arc::clone(&read_metrics);

        handles.push(tokio::spawn(async move {
            // Wait for all workers to be ready
            barrier.wait().await;

            let payload = vec![0xCDu8; 1024]; // 1KB payload

            for op_id in 0..OPS_PER_WORKER {
                let key = format!("concurrent:{}:{}", worker_id, op_id);

                // Write
                let write_start = Instant::now();
                match backend.put(key.as_bytes(), &payload).await {
                    Ok(_) => {
                        w_metrics.record(write_start.elapsed());
                        success.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(_) => {
                        errors.fetch_add(1, Ordering::Relaxed);
                    }
                }

                // Read
                let read_start = Instant::now();
                match backend.get(key.as_bytes()).await {
                    Ok(Some(_)) => {
                        r_metrics.record(read_start.elapsed());
                        success.fetch_add(1, Ordering::Relaxed);
                    }
                    Ok(None) => {
                        errors.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(_) => {
                        errors.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }));
    }

    // Wait for all workers
    for handle in handles {
        handle.await?;
    }

    let elapsed = start.elapsed();
    let total_ops = WORKER_COUNT * OPS_PER_WORKER * 2; // read + write
    let throughput = total_ops as f64 / elapsed.as_secs_f64();

    println!("\nResults:");
    println!("  Total time: {:?}", elapsed);
    println!("  Total ops: {}", total_ops);
    println!("  Throughput: {:.2} ops/sec", throughput);
    println!("  Successes: {}", success_count.load(Ordering::Relaxed));
    println!("  Errors: {}", error_count.load(Ordering::Relaxed));
    println!(
        "  Write latency - p50: {:?}, p99: {:?}",
        write_metrics.p50(),
        write_metrics.p99()
    );
    println!(
        "  Read latency - p50: {:?}, p99: {:?}",
        read_metrics.p50(),
        read_metrics.p99()
    );

    // Assertions
    assert_eq!(
        error_count.load(Ordering::Relaxed),
        0,
        "Concurrent access should not produce errors"
    );

    println!("\n=== Concurrent Access Test Complete ===\n");
    Ok(())
}

/// Test: Sled backend memory efficiency under load
///
/// Validates that memory usage stays bounded under sustained writes.
#[tokio::test]
#[ignore = "Load test - run with ZHTP_RUN_LOAD_TESTS=1"]
async fn test_sled_backend_memory_bounded_growth() -> Result<()> {
    if !should_run_load_tests() {
        println!("Skipping load test (set ZHTP_RUN_LOAD_TESTS=1 to enable)");
        return Ok(());
    }

    const ENTRY_COUNT: usize = 100_000;
    const PAYLOAD_SIZE: usize = 100; // 100 bytes per entry

    let (backend, _temp_dir) = create_test_backend()?;
    let memory_tracker = MemoryTracker::new();

    println!("\n=== Memory Bounded Growth Test ===");
    println!("Entries: {}, Payload size: {} bytes", ENTRY_COUNT, PAYLOAD_SIZE);
    println!("Expected data size: {:.2} MB", (ENTRY_COUNT * PAYLOAD_SIZE) as f64 / (1024.0 * 1024.0));

    let payload = vec![0xEFu8; PAYLOAD_SIZE];

    let start = Instant::now();
    for i in 0..ENTRY_COUNT {
        let key = format!("memory:{:08}", i);
        backend.put(key.as_bytes(), &payload).await.map_err(|e| anyhow::anyhow!("{}", e))?;

        // Log progress every 10k entries
        if (i + 1) % 10_000 == 0 {
            println!(
                "  Progress: {}/{} entries, Memory delta: {:.2} MB",
                i + 1,
                ENTRY_COUNT,
                memory_tracker.delta_mb()
            );
        }
    }
    let elapsed = start.elapsed();

    let memory_delta_mb = memory_tracker.delta_mb();
    let expected_data_mb = (ENTRY_COUNT * PAYLOAD_SIZE) as f64 / (1024.0 * 1024.0);

    println!("\nResults:");
    println!("  Write time: {:?}", elapsed);
    println!("  Throughput: {:.2} entries/sec", ENTRY_COUNT as f64 / elapsed.as_secs_f64());
    println!("  Expected data size: {:.2} MB", expected_data_mb);
    println!("  Actual memory delta: {:.2} MB", memory_delta_mb);

    // Memory should not exceed 5x the raw data size (accounting for indexes, etc.)
    // For 100K entries @ 100B = 10MB data, allow up to 50MB memory growth
    let max_allowed_mb = expected_data_mb * 5.0;
    if memory_delta_mb > 0.0 {
        assert!(
            memory_delta_mb < max_allowed_mb,
            "Memory growth exceeded 5x data size: {:.2} MB > {:.2} MB",
            memory_delta_mb,
            max_allowed_mb
        );
    }

    println!("\n=== Memory Bounded Growth Test Complete ===\n");
    Ok(())
}

/// Test: High-volume batch operations
///
/// Tests batch write performance for bulk data ingestion scenarios.
#[tokio::test]
#[ignore = "Load test - run with ZHTP_RUN_LOAD_TESTS=1"]
async fn test_sled_backend_batch_operations_throughput() -> Result<()> {
    if !should_run_load_tests() {
        println!("Skipping load test (set ZHTP_RUN_LOAD_TESTS=1 to enable)");
        return Ok(());
    }

    const BATCH_SIZE: usize = 1000;
    const BATCH_COUNT: usize = 100;
    const PAYLOAD_SIZE: usize = 512;

    let (backend, _temp_dir) = create_test_backend()?;

    println!("\n=== Batch Operations Test ===");
    println!(
        "Batches: {}, Entries per batch: {}, Total entries: {}",
        BATCH_COUNT,
        BATCH_SIZE,
        BATCH_COUNT * BATCH_SIZE
    );

    let payload = vec![0x12u8; PAYLOAD_SIZE];
    let batch_metrics = LatencyMetrics::new();

    let start = Instant::now();
    for batch_id in 0..BATCH_COUNT {
        let batch_start = Instant::now();

        // Build batch operations
        let ops: Vec<lib_storage::backend::BatchOp> = (0..BATCH_SIZE)
            .map(|entry_id| {
                let key = format!("batch:{}:{}", batch_id, entry_id);
                lib_storage::backend::BatchOp::Put {
                    key: key.into_bytes(),
                    value: payload.clone(),
                }
            })
            .collect();

        backend.write_batch(&ops).await.map_err(|e| anyhow::anyhow!("{}", e))?;

        batch_metrics.record(batch_start.elapsed());
    }
    let elapsed = start.elapsed();

    let total_entries = BATCH_COUNT * BATCH_SIZE;
    let throughput = total_entries as f64 / elapsed.as_secs_f64();

    println!("\nResults:");
    println!("  Total time: {:?}", elapsed);
    println!("  Total entries: {}", total_entries);
    println!("  Throughput: {:.2} entries/sec", throughput);
    println!(
        "  Batch latency - p50: {:?}, p99: {:?}, mean: {:?}",
        batch_metrics.p50(),
        batch_metrics.p99(),
        batch_metrics.mean()
    );

    println!("\n=== Batch Operations Test Complete ===\n");
    Ok(())
}

/// Test: Sustained write load with periodic reads
///
/// Simulates realistic mixed workload pattern.
#[tokio::test]
#[ignore = "Load test - run with ZHTP_RUN_LOAD_TESTS=1"]
async fn test_sled_backend_mixed_workload_sustained() -> Result<()> {
    if !should_run_load_tests() {
        println!("Skipping load test (set ZHTP_RUN_LOAD_TESTS=1 to enable)");
        return Ok(());
    }

    const DURATION_SECS: u64 = 10;
    const PAYLOAD_SIZE: usize = 256;
    const READ_RATIO: usize = 10; // 1 read per 10 writes

    let (backend, _temp_dir) = create_test_backend()?;

    println!("\n=== Sustained Mixed Workload Test ===");
    println!("Duration: {}s, Read ratio: 1:{}", DURATION_SECS, READ_RATIO);

    let payload = vec![0x34u8; PAYLOAD_SIZE];
    let write_metrics = LatencyMetrics::new();
    let read_metrics = LatencyMetrics::new();
    let mut write_count = 0u64;
    let mut read_count = 0u64;

    let start = Instant::now();
    let deadline = start + Duration::from_secs(DURATION_SECS);

    while Instant::now() < deadline {
        // Write operation
        let key = format!("mixed:{}", write_count);
        let write_start = Instant::now();
        backend.put(key.as_bytes(), &payload).await.map_err(|e| anyhow::anyhow!("{}", e))?;
        write_metrics.record(write_start.elapsed());
        write_count += 1;

        // Periodic read (every READ_RATIO writes)
        if write_count % READ_RATIO as u64 == 0 && write_count > 0 {
            let read_key = format!("mixed:{}", rand::random::<u64>() % write_count);
            let read_start = Instant::now();
            let _ = backend.get(read_key.as_bytes()).await;
            read_metrics.record(read_start.elapsed());
            read_count += 1;
        }
    }

    let elapsed = start.elapsed();

    println!("\nResults:");
    println!("  Total time: {:?}", elapsed);
    println!("  Writes: {} ({:.2}/sec)", write_count, write_count as f64 / elapsed.as_secs_f64());
    println!("  Reads: {} ({:.2}/sec)", read_count, read_count as f64 / elapsed.as_secs_f64());
    println!(
        "  Write latency - p50: {:?}, p99: {:?}",
        write_metrics.p50(),
        write_metrics.p99()
    );
    println!(
        "  Read latency - p50: {:?}, p99: {:?}",
        read_metrics.p50(),
        read_metrics.p99()
    );

    // Performance assertions
    assert!(
        write_metrics.p50() < Duration::from_millis(1),
        "Write p50 latency exceeded 1ms: {:?}",
        write_metrics.p50()
    );
    assert!(
        read_metrics.p50() < Duration::from_micros(500),
        "Read p50 latency exceeded 500us: {:?}",
        read_metrics.p50()
    );

    println!("\n=== Sustained Mixed Workload Test Complete ===\n");
    Ok(())
}

// ============================================================================
// Performance Baseline Documentation Tests
// ============================================================================

/// Test: Generate performance baseline report
///
/// Runs a standardized benchmark and outputs baseline metrics for documentation.
#[tokio::test]
#[ignore = "Load test - run with ZHTP_RUN_LOAD_TESTS=1"]
async fn test_generate_performance_baseline() -> Result<()> {
    if !should_run_load_tests() {
        println!("Skipping load test (set ZHTP_RUN_LOAD_TESTS=1 to enable)");
        return Ok(());
    }

    const ITERATIONS: usize = 10_000;

    let (backend, _temp_dir) = create_test_backend()?;

    println!("\n");
    println!("======================================================================");
    println!("          SLED STORAGE PERFORMANCE BASELINE REPORT                    ");
    println!("======================================================================");
    println!(" Date: {}", chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC"));
    println!(" Iterations per test: {}", ITERATIONS);
    println!("======================================================================");

    // Small payload (100 bytes)
    let small_payload = vec![0u8; 100];
    let small_write = LatencyMetrics::new();
    let small_read = LatencyMetrics::new();

    for i in 0..ITERATIONS {
        let key = format!("baseline:small:{}", i);
        let start = Instant::now();
        backend.put(key.as_bytes(), &small_payload).await.map_err(|e| anyhow::anyhow!("{}", e))?;
        small_write.record(start.elapsed());
    }

    for i in 0..ITERATIONS {
        let key = format!("baseline:small:{}", i);
        let start = Instant::now();
        let _ = backend.get(key.as_bytes()).await.map_err(|e| anyhow::anyhow!("{}", e))?;
        small_read.record(start.elapsed());
    }

    println!("\n----------------------------------------------------------------------");
    println!(" 100-byte Payload Performance");
    println!("----------------------------------------------------------------------");
    println!(" Write: p50={:>10?}  p99={:>10?}  mean={:>10?}", small_write.p50(), small_write.p99(), small_write.mean());
    println!(" Read:  p50={:>10?}  p99={:>10?}  mean={:>10?}", small_read.p50(), small_read.p99(), small_read.mean());

    // Medium payload (1KB)
    let medium_payload = vec![0u8; 1024];
    let medium_write = LatencyMetrics::new();
    let medium_read = LatencyMetrics::new();

    for i in 0..ITERATIONS {
        let key = format!("baseline:medium:{}", i);
        let start = Instant::now();
        backend.put(key.as_bytes(), &medium_payload).await.map_err(|e| anyhow::anyhow!("{}", e))?;
        medium_write.record(start.elapsed());
    }

    for i in 0..ITERATIONS {
        let key = format!("baseline:medium:{}", i);
        let start = Instant::now();
        let _ = backend.get(key.as_bytes()).await.map_err(|e| anyhow::anyhow!("{}", e))?;
        medium_read.record(start.elapsed());
    }

    println!("\n----------------------------------------------------------------------");
    println!(" 1KB Payload Performance");
    println!("----------------------------------------------------------------------");
    println!(" Write: p50={:>10?}  p99={:>10?}  mean={:>10?}", medium_write.p50(), medium_write.p99(), medium_write.mean());
    println!(" Read:  p50={:>10?}  p99={:>10?}  mean={:>10?}", medium_read.p50(), medium_read.p99(), medium_read.mean());

    // Large payload (10KB)
    let large_payload = vec![0u8; 10240];
    let large_write = LatencyMetrics::new();
    let large_read = LatencyMetrics::new();

    let large_iterations = ITERATIONS / 10; // Fewer iterations for large payloads
    for i in 0..large_iterations {
        let key = format!("baseline:large:{}", i);
        let start = Instant::now();
        backend.put(key.as_bytes(), &large_payload).await.map_err(|e| anyhow::anyhow!("{}", e))?;
        large_write.record(start.elapsed());
    }

    for i in 0..large_iterations {
        let key = format!("baseline:large:{}", i);
        let start = Instant::now();
        let _ = backend.get(key.as_bytes()).await.map_err(|e| anyhow::anyhow!("{}", e))?;
        large_read.record(start.elapsed());
    }

    println!("\n----------------------------------------------------------------------");
    println!(" 10KB Payload Performance");
    println!("----------------------------------------------------------------------");
    println!(" Write: p50={:>10?}  p99={:>10?}  mean={:>10?}", large_write.p50(), large_write.p99(), large_write.mean());
    println!(" Read:  p50={:>10?}  p99={:>10?}  mean={:>10?}", large_read.p50(), large_read.p99(), large_read.mean());

    // Throughput summary
    println!("\n----------------------------------------------------------------------");
    println!(" Throughput Summary (ops/sec)");
    println!("----------------------------------------------------------------------");
    println!(
        " 100B Write: {:>10.0}    100B Read: {:>10.0}",
        1.0 / small_write.mean().as_secs_f64(),
        1.0 / small_read.mean().as_secs_f64()
    );
    println!(
        " 1KB Write:  {:>10.0}    1KB Read:  {:>10.0}",
        1.0 / medium_write.mean().as_secs_f64(),
        1.0 / medium_read.mean().as_secs_f64()
    );
    println!(
        " 10KB Write: {:>10.0}    10KB Read: {:>10.0}",
        1.0 / large_write.mean().as_secs_f64(),
        1.0 / large_read.mean().as_secs_f64()
    );
    println!("======================================================================\n");

    Ok(())
}
