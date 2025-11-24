<<<<<<< HEAD
# ZHTP Storage Performance Optimization Guide

This guide provides detailed strategies for optimizing the performance of the ZHTP Unified Storage System across different scenarios and deployment environments.

##  Performance Overview

The ZHTP Storage System is designed for high-performance distributed storage with multiple optimization layers:

- **Network Layer**: DHT routing, connection pooling, message batching
- **Storage Layer**: Erasure coding, compression, caching
- **Economic Layer**: Optimized contract processing, payment batching
- **Application Layer**: Async operations, parallel processing

##  Network Performance Optimization

### DHT Network Tuning

```rust
// Optimized DHT configuration for high-performance scenarios
let optimized_dht_config = DhtConfig {
    // Increase routing table size for faster lookups
    routing_table_size: 256, // Default: 160
    
    // Reduce lookup timeout for faster responses
    lookup_timeout: Duration::from_millis(3000), // Default: 5000ms
    
    // Increase concurrent lookups
    max_concurrent_lookups: 10, // Default: 3
    
    // Enable aggressive caching
    enable_routing_cache: true,
    routing_cache_size: 10000, // Cache 10K entries
    routing_cache_ttl: Duration::from_secs(300), // 5 minutes
    
    // Optimize message handling
    message_batch_size: 50, // Process messages in batches
    message_queue_size: 1000,
    
    // Network quality settings
    preferred_node_count: 20, // Maintain connections to top nodes
    min_node_quality: 0.8, // Only use high-quality nodes
    
    // Heartbeat optimization
    heartbeat_interval: Duration::from_secs(30), // Default: 60s
    node_timeout: Duration::from_secs(120), // Default: 300s
};

let config = UnifiedStorageConfig {
    dht_config: optimized_dht_config,
    ..Default::default()
};
```

### Connection Pool Optimization

```rust
// High-performance network configuration
let network_config = NetworkConfig {
    // Connection management
    max_connections_per_node: 8, // Multiple connections per node
    connection_pool_size: 200, // Large connection pool
    connection_timeout: Duration::from_secs(10),
    connection_keepalive: Duration::from_secs(30),
    
    // I/O optimization
    tcp_nodelay: true, // Disable Nagle's algorithm
    tcp_send_buffer_size: 1024 * 1024, // 1MB send buffer
    tcp_recv_buffer_size: 1024 * 1024, // 1MB receive buffer
    
    // Parallel processing
    max_concurrent_requests: 100,
    request_timeout: Duration::from_secs(30),
    
    // Message compression
    enable_message_compression: true,
    compression_threshold: 1024, // Compress messages > 1KB
    
    // Bandwidth management
    max_bandwidth_mbps: 100, // Limit to 100 Mbps
    enable_traffic_shaping: true,
};
```

### Network Monitoring and Adaptive Optimization

```rust
use std::collections::VecDeque;
use std::time::{Duration, Instant};

pub struct NetworkPerformanceMonitor {
    latency_samples: VecDeque<Duration>,
    throughput_samples: VecDeque<f64>,
    error_rate_samples: VecDeque<f64>,
    sample_window: usize,
}

impl NetworkPerformanceMonitor {
    pub fn new(sample_window: usize) -> Self {
        Self {
            latency_samples: VecDeque::with_capacity(sample_window),
            throughput_samples: VecDeque::with_capacity(sample_window),
            error_rate_samples: VecDeque::with_capacity(sample_window),
            sample_window,
        }
    }
    
    pub fn record_request(&mut self, latency: Duration, bytes_transferred: u64, success: bool) {
        // Record latency
        if self.latency_samples.len() >= self.sample_window {
            self.latency_samples.pop_front();
        }
        self.latency_samples.push_back(latency);
        
        // Record throughput (MB/s)
        let throughput = (bytes_transferred as f64) / (1024.0 * 1024.0) / latency.as_secs_f64();
        if self.throughput_samples.len() >= self.sample_window {
            self.throughput_samples.pop_front();
        }
        self.throughput_samples.push_back(throughput);
        
        // Record error rate
        let error_rate = if success { 0.0 } else { 1.0 };
        if self.error_rate_samples.len() >= self.sample_window {
            self.error_rate_samples.pop_front();
        }
        self.error_rate_samples.push_back(error_rate);
    }
    
    pub fn get_adaptive_config(&self) -> NetworkConfig {
        let avg_latency = self.average_latency();
        let avg_throughput = self.average_throughput();
        let avg_error_rate = self.average_error_rate();
        
        let mut config = NetworkConfig::default();
        
        // Adapt timeouts based on latency
        if avg_latency > Duration::from_millis(1000) {
            config.connection_timeout = avg_latency * 5;
            config.request_timeout = avg_latency * 10;
        }
        
        // Adapt concurrency based on throughput and error rate
        if avg_throughput > 50.0 && avg_error_rate < 0.01 {
            config.max_concurrent_requests = 200; // High performance
        } else if avg_error_rate > 0.1 {
            config.max_concurrent_requests = 20; // Conservative
        }
        
        // Adapt buffer sizes based on throughput
        let buffer_size = if avg_throughput > 100.0 {
            2 * 1024 * 1024 // 2MB for high throughput
        } else if avg_throughput > 10.0 {
            1024 * 1024 // 1MB for medium throughput
        } else {
            256 * 1024 // 256KB for low throughput
        };
        
        config.tcp_send_buffer_size = buffer_size;
        config.tcp_recv_buffer_size = buffer_size;
        
        config
    }
    
    fn average_latency(&self) -> Duration {
        if self.latency_samples.is_empty() {
            return Duration::from_millis(100);
        }
        
        let total_nanos: u64 = self.latency_samples.iter().map(|d| d.as_nanos() as u64).sum();
        Duration::from_nanos(total_nanos / self.latency_samples.len() as u64)
    }
    
    fn average_throughput(&self) -> f64 {
        if self.throughput_samples.is_empty() {
            return 1.0;
        }
        
        self.throughput_samples.iter().sum::<f64>() / self.throughput_samples.len() as f64
    }
    
    fn average_error_rate(&self) -> f64 {
        if self.error_rate_samples.is_empty() {
            return 0.0;
        }
        
        self.error_rate_samples.iter().sum::<f64>() / self.error_rate_samples.len() as f64
    }
}
```

##  Storage Performance Optimization

### Erasure Coding Optimization

```rust
// CPU-optimized erasure coding configuration
let optimized_erasure_config = ErasureConfig {
    // Balance redundancy vs performance
    data_shards: 8,    // Optimal for most CPUs (8 cores)
    parity_shards: 4,  // 50% redundancy
    
    // Enable hardware acceleration
    enable_sse: true,          // Use SSE instructions
    enable_avx: true,          // Use AVX instructions if available
    enable_neon: true,         // Use NEON on ARM
    
    // Chunk size optimization
    chunk_size: 1024 * 1024,   // 1MB chunks for good CPU cache usage
    
    // Memory optimization
    enable_zero_copy: true,    // Avoid unnecessary memory copies
    preallocate_buffers: true, // Pre-allocate encoding buffers
    
    // Parallel processing
    enable_parallel_encoding: true,
    encoding_thread_count: 0,  // Auto-detect CPU cores
    
    // Quality settings
    verify_integrity: true,    // Always verify encoded data
    enable_checksum: true,     // Add checksums for extra integrity
};

// Storage-optimized configuration
let storage_config = StorageConfig {
    // Cache optimization
    enable_content_cache: true,
    content_cache_size: 1024 * 1024 * 1024, // 1GB cache
    cache_eviction_policy: CacheEvictionPolicy::LRU,
    
    // I/O optimization
    enable_async_io: true,
    io_queue_depth: 32,        // High queue depth for NVMe SSDs
    enable_direct_io: true,    // Bypass OS cache for large files
    
    // Compression settings
    enable_compression: true,
    compression_level: 6,      // Balance speed vs ratio
    compression_threshold: 4096, // Compress files > 4KB
    
    // Storage tiers
    default_tier: StorageTier::Hot, // Use fastest storage
    enable_auto_tiering: true,
    tier_transition_threshold: 30, // Days before moving to warm
    
    // Parallel operations
    max_concurrent_reads: 20,
    max_concurrent_writes: 10,
    
    // Performance monitoring
    enable_metrics: true,
    metrics_interval: Duration::from_secs(60),
};
```

### Content Caching Strategy

```rust
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use lru::LruCache;

pub struct HighPerformanceContentCache {
    // Multi-tier cache system
    hot_cache: Arc<RwLock<LruCache<ContentHash, Arc<Vec<u8>>>>>,     // In-memory
    warm_cache: Arc<RwLock<LruCache<ContentHash, String>>>,          // SSD file paths
    access_frequency: Arc<RwLock<HashMap<ContentHash, CacheStats>>>,
    
    // Configuration
    hot_cache_size: usize,
    warm_cache_size: usize,
    access_threshold: usize,
}

#[derive(Clone, Debug)]
struct CacheStats {
    access_count: usize,
    last_accessed: std::time::Instant,
    size: usize,
}

impl HighPerformanceContentCache {
    pub fn new(hot_cache_mb: usize, warm_cache_gb: usize) -> Self {
        Self {
            hot_cache: Arc::new(RwLock::new(LruCache::new(
                hot_cache_mb.try_into().unwrap()
            ))),
            warm_cache: Arc::new(RwLock::new(LruCache::new(
                warm_cache_gb.try_into().unwrap()
            ))),
            access_frequency: Arc::new(RwLock::new(HashMap::new())),
            hot_cache_size: hot_cache_mb * 1024 * 1024,
            warm_cache_size: warm_cache_gb * 1024 * 1024 * 1024,
            access_threshold: 3, // Promote to hot cache after 3 accesses
        }
    }
    
    pub async fn get(&self, content_hash: &ContentHash) -> Option<Arc<Vec<u8>>> {
        // Try hot cache first
        {
            let mut hot_cache = self.hot_cache.write().await;
            if let Some(content) = hot_cache.get(content_hash) {
                self.record_access(content_hash, content.len()).await;
                return Some(content.clone());
            }
        }
        
        // Try warm cache
        {
            let mut warm_cache = self.warm_cache.write().await;
            if let Some(file_path) = warm_cache.get(content_hash) {
                // Load from disk
                if let Ok(content) = tokio::fs::read(file_path).await {
                    let content = Arc::new(content);
                    
                    // Check if should promote to hot cache
                    if self.should_promote_to_hot(content_hash).await {
                        let mut hot_cache = self.hot_cache.write().await;
                        hot_cache.put(content_hash.clone(), content.clone());
                    }
                    
                    self.record_access(content_hash, content.len()).await;
                    return Some(content);
                }
            }
        }
        
        None
    }
    
    pub async fn put(&self, content_hash: ContentHash, content: Vec<u8>) {
        let content_size = content.len();
        let content = Arc::new(content);
        
        // Always try to put in hot cache first
        {
            let mut hot_cache = self.hot_cache.write().await;
            hot_cache.put(content_hash.clone(), content.clone());
        }
        
        // Also store in warm cache (as file)
        if content_size > 1024 * 1024 { // Files > 1MB go to warm cache
            let file_path = format!("/tmp/zhtp_cache/{}.dat", hex::encode(content_hash.as_bytes()));
            if let Ok(()) = tokio::fs::write(&file_path, content.as_ref()).await {
                let mut warm_cache = self.warm_cache.write().await;
                warm_cache.put(content_hash.clone(), file_path);
            }
        }
        
        self.record_access(&content_hash, content_size).await;
    }
    
    async fn should_promote_to_hot(&self, content_hash: &ContentHash) -> bool {
        let access_freq = self.access_frequency.read().await;
        if let Some(stats) = access_freq.get(content_hash) {
            stats.access_count >= self.access_threshold &&
            stats.last_accessed.elapsed() < Duration::from_secs(3600) // Active in last hour
        } else {
            false
        }
    }
    
    async fn record_access(&self, content_hash: &ContentHash, size: usize) {
        let mut access_freq = self.access_frequency.write().await;
        let stats = access_freq.entry(content_hash.clone()).or_insert(CacheStats {
            access_count: 0,
            last_accessed: std::time::Instant::now(),
            size,
        });
        
        stats.access_count += 1;
        stats.last_accessed = std::time::Instant::now();
    }
    
    pub async fn get_stats(&self) -> CachePerformanceStats {
        let hot_cache = self.hot_cache.read().await;
        let warm_cache = self.warm_cache.read().await;
        let access_freq = self.access_frequency.read().await;
        
        CachePerformanceStats {
            hot_cache_entries: hot_cache.len(),
            warm_cache_entries: warm_cache.len(),
            total_accesses: access_freq.values().map(|s| s.access_count).sum(),
            cache_hit_rate: self.calculate_hit_rate().await,
        }
    }
}
```

### Database/Index Optimization

```rust
// High-performance metadata storage
use sqlx::{sqlite::SqlitePool, query};

pub struct OptimizedMetadataStore {
    pool: SqlitePool,
}

impl OptimizedMetadataStore {
    pub async fn new(db_path: &str) -> Result<Self> {
        // SQLite optimization for high-performance scenarios
        let connection_string = format!("{}?mode=rwc&cache=shared&_journal_mode=WAL&_synchronous=NORMAL&_cache_size=10000", db_path);
        
        let pool = SqlitePool::connect(&connection_string).await?;
        
        // Performance-optimized table schema
        sqlx::query(r#"
            CREATE TABLE IF NOT EXISTS content_metadata (
                content_hash BLOB PRIMARY KEY,
                filename TEXT NOT NULL,
                size INTEGER NOT NULL,
                content_type TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                last_accessed INTEGER NOT NULL,
                access_count INTEGER DEFAULT 0,
                tags JSON,
                owner_identity BLOB,
                is_encrypted BOOLEAN DEFAULT FALSE
            ) WITHOUT ROWID
        "#).execute(&pool).await?;
        
        // High-performance indexes
        sqlx::query(r#"
            CREATE INDEX IF NOT EXISTS idx_content_filename ON content_metadata(filename);
            CREATE INDEX IF NOT EXISTS idx_content_type ON content_metadata(content_type);
            CREATE INDEX IF NOT EXISTS idx_content_created ON content_metadata(created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_content_accessed ON content_metadata(last_accessed DESC);
            CREATE INDEX IF NOT EXISTS idx_content_owner ON content_metadata(owner_identity);
            CREATE INDEX IF NOT EXISTS idx_content_size ON content_metadata(size);
        "#).execute(&pool).await?;
        
        // Full-text search index for tags and descriptions
        sqlx::query(r#"
            CREATE VIRTUAL TABLE IF NOT EXISTS content_search USING fts5(
                content_hash UNINDEXED,
                filename,
                description,
                tags,
                content = 'content_metadata',
                content_rowid = 'rowid'
            );
        "#).execute(&pool).await?;
        
        Ok(Self { pool })
    }
    
    pub async fn optimized_search(&self, query: &SearchQuery) -> Result<Vec<ContentMetadata>> {
        let mut sql = String::from("SELECT * FROM content_metadata");
        let mut conditions = Vec::new();
        let mut params = Vec::new();
        
        // Build optimized WHERE clause
        if !query.keywords.is_empty() {
            // Use FTS for keyword search
            conditions.push("content_hash IN (SELECT content_hash FROM content_search WHERE content_search MATCH ?)");
            params.push(query.keywords.join(" OR "));
        }
        
        if let Some(content_type) = &query.content_type {
            conditions.push("content_type = ?");
            params.push(content_type.clone());
        }
        
        if let Some(size_range) = &query.size_range {
            conditions.push("size BETWEEN ? AND ?");
            params.push(size_range.min.to_string());
            params.push(size_range.max.to_string());
        }
        
        if !conditions.is_empty() {
            sql.push_str(" WHERE ");
            sql.push_str(&conditions.join(" AND "));
        }
        
        // Optimize ORDER BY for common cases
        sql.push_str(" ORDER BY last_accessed DESC");
        
        // Add LIMIT for performance
        sql.push_str(&format!(" LIMIT {}", query.limit));
        
        // Execute optimized query
        let mut query_builder = sqlx::query_as::<_, ContentMetadata>(&sql);
        for param in params {
            query_builder = query_builder.bind(param);
        }
        
        let results = query_builder.fetch_all(&self.pool).await?;
        Ok(results)
    }
}
```

##  Application-Level Optimization

### Async Processing Pipeline

```rust
use tokio::sync::{mpsc, Semaphore};
use futures::stream::{self, StreamExt};
use std::sync::Arc;

pub struct HighThroughputProcessor {
    storage: Arc<RwLock<UnifiedStorageSystem>>,
    upload_semaphore: Arc<Semaphore>,
    download_semaphore: Arc<Semaphore>,
    processing_semaphore: Arc<Semaphore>,
}

impl HighThroughputProcessor {
    pub fn new(storage: UnifiedStorageSystem, max_concurrent_ops: usize) -> Self {
        Self {
            storage: Arc::new(RwLock::new(storage)),
            upload_semaphore: Arc::new(Semaphore::new(max_concurrent_ops / 2)),
            download_semaphore: Arc::new(Semaphore::new(max_concurrent_ops / 2)),
            processing_semaphore: Arc::new(Semaphore::new(max_concurrent_ops)),
        }
    }
    
    pub async fn batch_upload(&self, requests: Vec<UploadRequest>, identity: ZhtpIdentity) -> Vec<Result<ContentHash>> {
        let batch_size = 10; // Process in batches of 10
        let mut results = Vec::new();
        
        for batch in requests.chunks(batch_size) {
            let batch_results: Vec<_> = stream::iter(batch)
                .map(|request| {
                    let storage = self.storage.clone();
                    let semaphore = self.upload_semaphore.clone();
                    let identity = identity.clone();
                    let request = request.clone();
                    
                    async move {
                        let _permit = semaphore.acquire().await.unwrap();
                        let mut storage = storage.write().await;
                        storage.upload_content(request, identity).await
                    }
                })
                .buffer_unordered(batch_size) // Process batch concurrently
                .collect().await;
            
            results.extend(batch_results);
            
            // Small delay between batches to prevent overwhelming the network
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        
        results
    }
    
    pub async fn batch_download(&self, hashes: Vec<ContentHash>, identity: ZhtpIdentity) -> Vec<Result<Vec<u8>>> {
        let batch_size = 20; // Downloads can be more concurrent
        let mut results = Vec::new();
        
        for batch in hashes.chunks(batch_size) {
            let batch_results: Vec<_> = stream::iter(batch)
                .map(|hash| {
                    let storage = self.storage.clone();
                    let semaphore = self.download_semaphore.clone();
                    let identity = identity.clone();
                    let hash = hash.clone();
                    
                    async move {
                        let _permit = semaphore.acquire().await.unwrap();
                        let mut storage = storage.write().await;
                        let request = DownloadRequest {
                            content_hash: hash,
                            requester: identity,
                            access_proof: None,
                        };
                        storage.download_content(request).await
                    }
                })
                .buffer_unordered(batch_size)
                .collect().await;
            
            results.extend(batch_results);
        }
        
        results
    }
    
    pub async fn streaming_upload<S>(&self, stream: S, identity: ZhtpIdentity) -> mpsc::Receiver<Result<ContentHash>>
    where
        S: Stream<Item = UploadRequest> + Send + 'static,
    {
        let (tx, rx) = mpsc::channel(100);
        let storage = self.storage.clone();
        let semaphore = self.upload_semaphore.clone();
        
        tokio::spawn(async move {
            stream
                .for_each_concurrent(10, |request| {
                    let tx = tx.clone();
                    let storage = storage.clone();
                    let semaphore = semaphore.clone();
                    let identity = identity.clone();
                    
                    async move {
                        let _permit = semaphore.acquire().await.unwrap();
                        let mut storage = storage.write().await;
                        let result = storage.upload_content(request, identity).await;
                        let _ = tx.send(result).await;
                    }
                })
                .await;
        });
        
        rx
    }
}
```

### Memory Management Optimization

```rust
use std::sync::Arc;
use bytes::{Bytes, BytesMut};

pub struct MemoryOptimizedStorage {
    storage: UnifiedStorageSystem,
    buffer_pool: Arc<BufferPool>,
}

pub struct BufferPool {
    small_buffers: Vec<BytesMut>,  // 4KB buffers
    medium_buffers: Vec<BytesMut>, // 64KB buffers  
    large_buffers: Vec<BytesMut>,  // 1MB buffers
}

impl BufferPool {
    pub fn new() -> Self {
        Self {
            small_buffers: (0..100).map(|_| BytesMut::with_capacity(4096)).collect(),
            medium_buffers: (0..50).map(|_| BytesMut::with_capacity(65536)).collect(),
            large_buffers: (0..20).map(|_| BytesMut::with_capacity(1048576)).collect(),
        }
    }
    
    pub fn get_buffer(&mut self, size: usize) -> BytesMut {
        if size <= 4096 && !self.small_buffers.is_empty() {
            let mut buf = self.small_buffers.pop().unwrap();
            buf.clear();
            buf
        } else if size <= 65536 && !self.medium_buffers.is_empty() {
            let mut buf = self.medium_buffers.pop().unwrap();
            buf.clear();
            buf
        } else if size <= 1048576 && !self.large_buffers.is_empty() {
            let mut buf = self.large_buffers.pop().unwrap();
            buf.clear();
            buf
        } else {
            BytesMut::with_capacity(size)
        }
    }
    
    pub fn return_buffer(&mut self, buf: BytesMut) {
        let capacity = buf.capacity();
        if capacity == 4096 && self.small_buffers.len() < 100 {
            self.small_buffers.push(buf);
        } else if capacity == 65536 && self.medium_buffers.len() < 50 {
            self.medium_buffers.push(buf);
        } else if capacity == 1048576 && self.large_buffers.len() < 20 {
            self.large_buffers.push(buf);
        }
        // Otherwise let it drop
    }
}

impl MemoryOptimizedStorage {
    pub async fn zero_copy_upload(&mut self, content: Bytes, metadata: ContentMetadata, identity: ZhtpIdentity) -> Result<ContentHash> {
        // Use zero-copy approach with Bytes
        let upload_req = UploadRequest {
            content: content.to_vec(), // This copies, but we can optimize further
            filename: metadata.filename,
            mime_type: metadata.content_type,
            description: metadata.description,
            tags: metadata.tags,
            encrypt: false,
            compress: true,
            access_control: AccessControlSettings::default(),
            storage_requirements: ContentStorageRequirements::default(),
        };
        
        self.storage.upload_content(upload_req, identity).await
    }
}
```

##  Performance Monitoring and Tuning

### Real-time Performance Metrics

```rust
use prometheus::{
    Counter, Histogram, Gauge, IntGauge,
    register_counter, register_histogram, register_gauge, register_int_gauge
};
use std::time::Instant;

pub struct PerformanceMetrics {
    // Throughput metrics
    uploads_per_second: Counter,
    downloads_per_second: Counter,
    bytes_uploaded_per_second: Counter,
    bytes_downloaded_per_second: Counter,
    
    // Latency metrics
    upload_latency: Histogram,
    download_latency: Histogram,
    search_latency: Histogram,
    
    // Resource usage
    memory_usage: Gauge,
    cpu_usage: Gauge,
    disk_usage: Gauge,
    network_usage: Gauge,
    
    // System health
    active_connections: IntGauge,
    cache_hit_rate: Gauge,
    error_rate: Gauge,
}

impl PerformanceMetrics {
    pub fn new() -> Result<Self> {
        Ok(Self {
            uploads_per_second: register_counter!("zhtp_uploads_per_second", "Upload rate")?,
            downloads_per_second: register_counter!("zhtp_downloads_per_second", "Download rate")?,
            bytes_uploaded_per_second: register_counter!("zhtp_bytes_uploaded_per_second", "Upload throughput")?,
            bytes_downloaded_per_second: register_counter!("zhtp_bytes_downloaded_per_second", "Download throughput")?,
            
            upload_latency: register_histogram!(
                "zhtp_upload_latency_seconds",
                "Upload latency",
                vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0]
            )?,
            download_latency: register_histogram!(
                "zhtp_download_latency_seconds", 
                "Download latency",
                vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0]
            )?,
            search_latency: register_histogram!(
                "zhtp_search_latency_seconds",
                "Search latency", 
                vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0]
            )?,
            
            memory_usage: register_gauge!("zhtp_memory_usage_bytes", "Memory usage")?,
            cpu_usage: register_gauge!("zhtp_cpu_usage_percent", "CPU usage")?,
            disk_usage: register_gauge!("zhtp_disk_usage_bytes", "Disk usage")?,
            network_usage: register_gauge!("zhtp_network_usage_bps", "Network usage")?,
            
            active_connections: register_int_gauge!("zhtp_active_connections", "Active connections")?,
            cache_hit_rate: register_gauge!("zhtp_cache_hit_rate", "Cache hit rate")?,
            error_rate: register_gauge!("zhtp_error_rate", "Error rate")?,
        })
    }
    
    pub fn record_upload(&self, start_time: Instant, bytes: u64) {
        let duration = start_time.elapsed();
        self.uploads_per_second.inc();
        self.bytes_uploaded_per_second.inc_by(bytes);
        self.upload_latency.observe(duration.as_secs_f64());
    }
    
    pub fn record_download(&self, start_time: Instant, bytes: u64) {
        let duration = start_time.elapsed();
        self.downloads_per_second.inc();
        self.bytes_downloaded_per_second.inc_by(bytes);
        self.download_latency.observe(duration.as_secs_f64());
    }
    
    pub async fn update_system_metrics(&self) {
        // Update memory usage
        if let Ok(memory) = get_memory_usage().await {
            self.memory_usage.set(memory as f64);
        }
        
        // Update CPU usage
        if let Ok(cpu) = get_cpu_usage().await {
            self.cpu_usage.set(cpu);
        }
        
        // Update disk usage
        if let Ok(disk) = get_disk_usage().await {
            self.disk_usage.set(disk as f64);
        }
    }
}

// System resource monitoring functions
async fn get_memory_usage() -> Result<u64> {
    // Implementation depends on platform
    use sysinfo::{System, SystemExt};
    let mut system = System::new();
    system.refresh_memory();
    Ok(system.used_memory() * 1024) // Convert KB to bytes
}

async fn get_cpu_usage() -> Result<f64> {
    use sysinfo::{System, SystemExt, ProcessorExt};
    let mut system = System::new();
    system.refresh_cpu();
    tokio::time::sleep(Duration::from_millis(100)).await;
    system.refresh_cpu();
    
    let cpu_usage: f32 = system.processors().iter().map(|p| p.cpu_usage()).sum::<f32>() 
                         / system.processors().len() as f32;
    Ok(cpu_usage as f64)
}

async fn get_disk_usage() -> Result<u64> {
    use sysinfo::{System, SystemExt, DiskExt};
    let mut system = System::new();
    system.refresh_disks();
    
    let used_space: u64 = system.disks().iter()
        .map(|disk| disk.total_space() - disk.available_space())
        .sum();
    
    Ok(used_space)
}
```

### Automatic Performance Tuning

```rust
pub struct AutoTuner {
    metrics: PerformanceMetrics,
    config: Arc<RwLock<UnifiedStorageConfig>>,
    tuning_history: VecDeque<TuningEvent>,
}

#[derive(Debug, Clone)]
struct TuningEvent {
    timestamp: Instant,
    parameter: String,
    old_value: f64,
    new_value: f64,
    improvement: f64,
}

impl AutoTuner {
    pub async fn run_tuning_cycle(&mut self) -> Result<Vec<TuningEvent>> {
        let mut events = Vec::new();
        
        // Analyze current performance
        let current_perf = self.analyze_current_performance().await?;
        
        // Tune network parameters
        if let Some(event) = self.tune_network_parameters(&current_perf).await? {
            events.push(event);
        }
        
        // Tune storage parameters
        if let Some(event) = self.tune_storage_parameters(&current_perf).await? {
            events.push(event);
        }
        
        // Tune economic parameters
        if let Some(event) = self.tune_economic_parameters(&current_perf).await? {
            events.push(event);
        }
        
        // Record tuning events
        for event in &events {
            self.tuning_history.push_back(event.clone());
            if self.tuning_history.len() > 100 {
                self.tuning_history.pop_front();
            }
        }
        
        Ok(events)
    }
    
    async fn tune_network_parameters(&mut self, perf: &PerformanceSnapshot) -> Result<Option<TuningEvent>> {
        let mut config = self.config.write().await;
        
        // Tune connection pool size based on utilization
        if perf.connection_utilization > 0.8 && perf.error_rate < 0.01 {
            let old_size = config.network_config.connection_pool_size;
            let new_size = (old_size as f32 * 1.2) as usize; // Increase by 20%
            config.network_config.connection_pool_size = new_size;
            
            return Ok(Some(TuningEvent {
                timestamp: Instant::now(),
                parameter: "connection_pool_size".to_string(),
                old_value: old_size as f64,
                new_value: new_size as f64,
                improvement: 0.0, // Will be measured in next cycle
            }));
        }
        
        // Tune request timeout based on latency
        if perf.avg_latency > Duration::from_secs(5) {
            let old_timeout = config.network_config.request_timeout;
            let new_timeout = old_timeout + Duration::from_secs(5);
            config.network_config.request_timeout = new_timeout;
            
            return Ok(Some(TuningEvent {
                timestamp: Instant::now(),
                parameter: "request_timeout".to_string(),
                old_value: old_timeout.as_secs_f64(),
                new_value: new_timeout.as_secs_f64(),
                improvement: 0.0,
            }));
        }
        
        Ok(None)
    }
}

#[derive(Debug)]
struct PerformanceSnapshot {
    timestamp: Instant,
    avg_latency: Duration,
    throughput_mbps: f64,
    error_rate: f64,
    connection_utilization: f64,
    memory_usage_percent: f64,
    cpu_usage_percent: f64,
    cache_hit_rate: f64,
}
```

## 🛠️ Hardware-Specific Optimizations

### NVMe SSD Optimization

```rust
// Optimized for high-speed NVMe storage
let nvme_optimized_config = StorageConfig {
    // Use direct I/O to bypass OS cache
    enable_direct_io: true,
    
    // High queue depth for NVMe
    io_queue_depth: 64,
    
    // Large block sizes for sequential operations
    block_size: 1024 * 1024, // 1MB blocks
    
    // Alignment for NVMe
    alignment: 4096, // 4KB alignment
    
    // Asynchronous I/O
    enable_async_io: true,
    max_concurrent_ios: 32,
    
    // NVMe-specific settings
    enable_nvme_passthrough: true,
    nvme_submission_queues: 8,
    nvme_completion_queues: 8,
};
```

### Multi-Core CPU Optimization

```rust
// CPU-optimized configuration
let cpu_optimized_config = ProcessingConfig {
    // Use all available cores
    worker_threads: 0, // Auto-detect
    
    // Thread affinity for NUMA systems
    enable_thread_affinity: true,
    numa_aware: true,
    
    // CPU-specific optimizations
    enable_simd: true,          // Use SIMD instructions
    enable_vectorization: true, // Auto-vectorization
    
    // Work stealing for load balancing
    enable_work_stealing: true,
    work_steal_batch_size: 8,
    
    // Cache-friendly data structures
    cache_line_size: 64,
    prefetch_distance: 8,
};
```

=======
# ZHTP Storage Performance Optimization Guide

This guide provides detailed strategies for optimizing the performance of the ZHTP Unified Storage System across different scenarios and deployment environments.

##  Performance Overview

The ZHTP Storage System is designed for high-performance distributed storage with multiple optimization layers:

- **Network Layer**: DHT routing, connection pooling, message batching
- **Storage Layer**: Erasure coding, compression, caching
- **Economic Layer**: Optimized contract processing, payment batching
- **Application Layer**: Async operations, parallel processing

##  Network Performance Optimization

### DHT Network Tuning

```rust
// Optimized DHT configuration for high-performance scenarios
let optimized_dht_config = DhtConfig {
    // Increase routing table size for faster lookups
    routing_table_size: 256, // Default: 160
    
    // Reduce lookup timeout for faster responses
    lookup_timeout: Duration::from_millis(3000), // Default: 5000ms
    
    // Increase concurrent lookups
    max_concurrent_lookups: 10, // Default: 3
    
    // Enable aggressive caching
    enable_routing_cache: true,
    routing_cache_size: 10000, // Cache 10K entries
    routing_cache_ttl: Duration::from_secs(300), // 5 minutes
    
    // Optimize message handling
    message_batch_size: 50, // Process messages in batches
    message_queue_size: 1000,
    
    // Network quality settings
    preferred_node_count: 20, // Maintain connections to top nodes
    min_node_quality: 0.8, // Only use high-quality nodes
    
    // Heartbeat optimization
    heartbeat_interval: Duration::from_secs(30), // Default: 60s
    node_timeout: Duration::from_secs(120), // Default: 300s
};

let config = UnifiedStorageConfig {
    dht_config: optimized_dht_config,
    ..Default::default()
};
```

### Connection Pool Optimization

```rust
// High-performance network configuration
let network_config = NetworkConfig {
    // Connection management
    max_connections_per_node: 8, // Multiple connections per node
    connection_pool_size: 200, // Large connection pool
    connection_timeout: Duration::from_secs(10),
    connection_keepalive: Duration::from_secs(30),
    
    // I/O optimization
    tcp_nodelay: true, // Disable Nagle's algorithm
    tcp_send_buffer_size: 1024 * 1024, // 1MB send buffer
    tcp_recv_buffer_size: 1024 * 1024, // 1MB receive buffer
    
    // Parallel processing
    max_concurrent_requests: 100,
    request_timeout: Duration::from_secs(30),
    
    // Message compression
    enable_message_compression: true,
    compression_threshold: 1024, // Compress messages > 1KB
    
    // Bandwidth management
    max_bandwidth_mbps: 100, // Limit to 100 Mbps
    enable_traffic_shaping: true,
};
```

### Network Monitoring and Adaptive Optimization

```rust
use std::collections::VecDeque;
use std::time::{Duration, Instant};

pub struct NetworkPerformanceMonitor {
    latency_samples: VecDeque<Duration>,
    throughput_samples: VecDeque<f64>,
    error_rate_samples: VecDeque<f64>,
    sample_window: usize,
}

impl NetworkPerformanceMonitor {
    pub fn new(sample_window: usize) -> Self {
        Self {
            latency_samples: VecDeque::with_capacity(sample_window),
            throughput_samples: VecDeque::with_capacity(sample_window),
            error_rate_samples: VecDeque::with_capacity(sample_window),
            sample_window,
        }
    }
    
    pub fn record_request(&mut self, latency: Duration, bytes_transferred: u64, success: bool) {
        // Record latency
        if self.latency_samples.len() >= self.sample_window {
            self.latency_samples.pop_front();
        }
        self.latency_samples.push_back(latency);
        
        // Record throughput (MB/s)
        let throughput = (bytes_transferred as f64) / (1024.0 * 1024.0) / latency.as_secs_f64();
        if self.throughput_samples.len() >= self.sample_window {
            self.throughput_samples.pop_front();
        }
        self.throughput_samples.push_back(throughput);
        
        // Record error rate
        let error_rate = if success { 0.0 } else { 1.0 };
        if self.error_rate_samples.len() >= self.sample_window {
            self.error_rate_samples.pop_front();
        }
        self.error_rate_samples.push_back(error_rate);
    }
    
    pub fn get_adaptive_config(&self) -> NetworkConfig {
        let avg_latency = self.average_latency();
        let avg_throughput = self.average_throughput();
        let avg_error_rate = self.average_error_rate();
        
        let mut config = NetworkConfig::default();
        
        // Adapt timeouts based on latency
        if avg_latency > Duration::from_millis(1000) {
            config.connection_timeout = avg_latency * 5;
            config.request_timeout = avg_latency * 10;
        }
        
        // Adapt concurrency based on throughput and error rate
        if avg_throughput > 50.0 && avg_error_rate < 0.01 {
            config.max_concurrent_requests = 200; // High performance
        } else if avg_error_rate > 0.1 {
            config.max_concurrent_requests = 20; // Conservative
        }
        
        // Adapt buffer sizes based on throughput
        let buffer_size = if avg_throughput > 100.0 {
            2 * 1024 * 1024 // 2MB for high throughput
        } else if avg_throughput > 10.0 {
            1024 * 1024 // 1MB for medium throughput
        } else {
            256 * 1024 // 256KB for low throughput
        };
        
        config.tcp_send_buffer_size = buffer_size;
        config.tcp_recv_buffer_size = buffer_size;
        
        config
    }
    
    fn average_latency(&self) -> Duration {
        if self.latency_samples.is_empty() {
            return Duration::from_millis(100);
        }
        
        let total_nanos: u64 = self.latency_samples.iter().map(|d| d.as_nanos() as u64).sum();
        Duration::from_nanos(total_nanos / self.latency_samples.len() as u64)
    }
    
    fn average_throughput(&self) -> f64 {
        if self.throughput_samples.is_empty() {
            return 1.0;
        }
        
        self.throughput_samples.iter().sum::<f64>() / self.throughput_samples.len() as f64
    }
    
    fn average_error_rate(&self) -> f64 {
        if self.error_rate_samples.is_empty() {
            return 0.0;
        }
        
        self.error_rate_samples.iter().sum::<f64>() / self.error_rate_samples.len() as f64
    }
}
```

##  Storage Performance Optimization

### Erasure Coding Optimization

```rust
// CPU-optimized erasure coding configuration
let optimized_erasure_config = ErasureConfig {
    // Balance redundancy vs performance
    data_shards: 8,    // Optimal for most CPUs (8 cores)
    parity_shards: 4,  // 50% redundancy
    
    // Enable hardware acceleration
    enable_sse: true,          // Use SSE instructions
    enable_avx: true,          // Use AVX instructions if available
    enable_neon: true,         // Use NEON on ARM
    
    // Chunk size optimization
    chunk_size: 1024 * 1024,   // 1MB chunks for good CPU cache usage
    
    // Memory optimization
    enable_zero_copy: true,    // Avoid unnecessary memory copies
    preallocate_buffers: true, // Pre-allocate encoding buffers
    
    // Parallel processing
    enable_parallel_encoding: true,
    encoding_thread_count: 0,  // Auto-detect CPU cores
    
    // Quality settings
    verify_integrity: true,    // Always verify encoded data
    enable_checksum: true,     // Add checksums for extra integrity
};

// Storage-optimized configuration
let storage_config = StorageConfig {
    // Cache optimization
    enable_content_cache: true,
    content_cache_size: 1024 * 1024 * 1024, // 1GB cache
    cache_eviction_policy: CacheEvictionPolicy::LRU,
    
    // I/O optimization
    enable_async_io: true,
    io_queue_depth: 32,        // High queue depth for NVMe SSDs
    enable_direct_io: true,    // Bypass OS cache for large files
    
    // Compression settings
    enable_compression: true,
    compression_level: 6,      // Balance speed vs ratio
    compression_threshold: 4096, // Compress files > 4KB
    
    // Storage tiers
    default_tier: StorageTier::Hot, // Use fastest storage
    enable_auto_tiering: true,
    tier_transition_threshold: 30, // Days before moving to warm
    
    // Parallel operations
    max_concurrent_reads: 20,
    max_concurrent_writes: 10,
    
    // Performance monitoring
    enable_metrics: true,
    metrics_interval: Duration::from_secs(60),
};
```

### Content Caching Strategy

```rust
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use lru::LruCache;

pub struct HighPerformanceContentCache {
    // Multi-tier cache system
    hot_cache: Arc<RwLock<LruCache<ContentHash, Arc<Vec<u8>>>>>,     // In-memory
    warm_cache: Arc<RwLock<LruCache<ContentHash, String>>>,          // SSD file paths
    access_frequency: Arc<RwLock<HashMap<ContentHash, CacheStats>>>,
    
    // Configuration
    hot_cache_size: usize,
    warm_cache_size: usize,
    access_threshold: usize,
}

#[derive(Clone, Debug)]
struct CacheStats {
    access_count: usize,
    last_accessed: std::time::Instant,
    size: usize,
}

impl HighPerformanceContentCache {
    pub fn new(hot_cache_mb: usize, warm_cache_gb: usize) -> Self {
        Self {
            hot_cache: Arc::new(RwLock::new(LruCache::new(
                hot_cache_mb.try_into().unwrap()
            ))),
            warm_cache: Arc::new(RwLock::new(LruCache::new(
                warm_cache_gb.try_into().unwrap()
            ))),
            access_frequency: Arc::new(RwLock::new(HashMap::new())),
            hot_cache_size: hot_cache_mb * 1024 * 1024,
            warm_cache_size: warm_cache_gb * 1024 * 1024 * 1024,
            access_threshold: 3, // Promote to hot cache after 3 accesses
        }
    }
    
    pub async fn get(&self, content_hash: &ContentHash) -> Option<Arc<Vec<u8>>> {
        // Try hot cache first
        {
            let mut hot_cache = self.hot_cache.write().await;
            if let Some(content) = hot_cache.get(content_hash) {
                self.record_access(content_hash, content.len()).await;
                return Some(content.clone());
            }
        }
        
        // Try warm cache
        {
            let mut warm_cache = self.warm_cache.write().await;
            if let Some(file_path) = warm_cache.get(content_hash) {
                // Load from disk
                if let Ok(content) = tokio::fs::read(file_path).await {
                    let content = Arc::new(content);
                    
                    // Check if should promote to hot cache
                    if self.should_promote_to_hot(content_hash).await {
                        let mut hot_cache = self.hot_cache.write().await;
                        hot_cache.put(content_hash.clone(), content.clone());
                    }
                    
                    self.record_access(content_hash, content.len()).await;
                    return Some(content);
                }
            }
        }
        
        None
    }
    
    pub async fn put(&self, content_hash: ContentHash, content: Vec<u8>) {
        let content_size = content.len();
        let content = Arc::new(content);
        
        // Always try to put in hot cache first
        {
            let mut hot_cache = self.hot_cache.write().await;
            hot_cache.put(content_hash.clone(), content.clone());
        }
        
        // Also store in warm cache (as file)
        if content_size > 1024 * 1024 { // Files > 1MB go to warm cache
            let file_path = format!("/tmp/zhtp_cache/{}.dat", hex::encode(content_hash.as_bytes()));
            if let Ok(()) = tokio::fs::write(&file_path, content.as_ref()).await {
                let mut warm_cache = self.warm_cache.write().await;
                warm_cache.put(content_hash.clone(), file_path);
            }
        }
        
        self.record_access(&content_hash, content_size).await;
    }
    
    async fn should_promote_to_hot(&self, content_hash: &ContentHash) -> bool {
        let access_freq = self.access_frequency.read().await;
        if let Some(stats) = access_freq.get(content_hash) {
            stats.access_count >= self.access_threshold &&
            stats.last_accessed.elapsed() < Duration::from_secs(3600) // Active in last hour
        } else {
            false
        }
    }
    
    async fn record_access(&self, content_hash: &ContentHash, size: usize) {
        let mut access_freq = self.access_frequency.write().await;
        let stats = access_freq.entry(content_hash.clone()).or_insert(CacheStats {
            access_count: 0,
            last_accessed: std::time::Instant::now(),
            size,
        });
        
        stats.access_count += 1;
        stats.last_accessed = std::time::Instant::now();
    }
    
    pub async fn get_stats(&self) -> CachePerformanceStats {
        let hot_cache = self.hot_cache.read().await;
        let warm_cache = self.warm_cache.read().await;
        let access_freq = self.access_frequency.read().await;
        
        CachePerformanceStats {
            hot_cache_entries: hot_cache.len(),
            warm_cache_entries: warm_cache.len(),
            total_accesses: access_freq.values().map(|s| s.access_count).sum(),
            cache_hit_rate: self.calculate_hit_rate().await,
        }
    }
}
```

### Database/Index Optimization

```rust
// High-performance metadata storage
use sqlx::{sqlite::SqlitePool, query};

pub struct OptimizedMetadataStore {
    pool: SqlitePool,
}

impl OptimizedMetadataStore {
    pub async fn new(db_path: &str) -> Result<Self> {
        // SQLite optimization for high-performance scenarios
        let connection_string = format!("{}?mode=rwc&cache=shared&_journal_mode=WAL&_synchronous=NORMAL&_cache_size=10000", db_path);
        
        let pool = SqlitePool::connect(&connection_string).await?;
        
        // Performance-optimized table schema
        sqlx::query(r#"
            CREATE TABLE IF NOT EXISTS content_metadata (
                content_hash BLOB PRIMARY KEY,
                filename TEXT NOT NULL,
                size INTEGER NOT NULL,
                content_type TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                last_accessed INTEGER NOT NULL,
                access_count INTEGER DEFAULT 0,
                tags JSON,
                owner_identity BLOB,
                is_encrypted BOOLEAN DEFAULT FALSE
            ) WITHOUT ROWID
        "#).execute(&pool).await?;
        
        // High-performance indexes
        sqlx::query(r#"
            CREATE INDEX IF NOT EXISTS idx_content_filename ON content_metadata(filename);
            CREATE INDEX IF NOT EXISTS idx_content_type ON content_metadata(content_type);
            CREATE INDEX IF NOT EXISTS idx_content_created ON content_metadata(created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_content_accessed ON content_metadata(last_accessed DESC);
            CREATE INDEX IF NOT EXISTS idx_content_owner ON content_metadata(owner_identity);
            CREATE INDEX IF NOT EXISTS idx_content_size ON content_metadata(size);
        "#).execute(&pool).await?;
        
        // Full-text search index for tags and descriptions
        sqlx::query(r#"
            CREATE VIRTUAL TABLE IF NOT EXISTS content_search USING fts5(
                content_hash UNINDEXED,
                filename,
                description,
                tags,
                content = 'content_metadata',
                content_rowid = 'rowid'
            );
        "#).execute(&pool).await?;
        
        Ok(Self { pool })
    }
    
    pub async fn optimized_search(&self, query: &SearchQuery) -> Result<Vec<ContentMetadata>> {
        let mut sql = String::from("SELECT * FROM content_metadata");
        let mut conditions = Vec::new();
        let mut params = Vec::new();
        
        // Build optimized WHERE clause
        if !query.keywords.is_empty() {
            // Use FTS for keyword search
            conditions.push("content_hash IN (SELECT content_hash FROM content_search WHERE content_search MATCH ?)");
            params.push(query.keywords.join(" OR "));
        }
        
        if let Some(content_type) = &query.content_type {
            conditions.push("content_type = ?");
            params.push(content_type.clone());
        }
        
        if let Some(size_range) = &query.size_range {
            conditions.push("size BETWEEN ? AND ?");
            params.push(size_range.min.to_string());
            params.push(size_range.max.to_string());
        }
        
        if !conditions.is_empty() {
            sql.push_str(" WHERE ");
            sql.push_str(&conditions.join(" AND "));
        }
        
        // Optimize ORDER BY for common cases
        sql.push_str(" ORDER BY last_accessed DESC");
        
        // Add LIMIT for performance
        sql.push_str(&format!(" LIMIT {}", query.limit));
        
        // Execute optimized query
        let mut query_builder = sqlx::query_as::<_, ContentMetadata>(&sql);
        for param in params {
            query_builder = query_builder.bind(param);
        }
        
        let results = query_builder.fetch_all(&self.pool).await?;
        Ok(results)
    }
}
```

##  Application-Level Optimization

### Async Processing Pipeline

```rust
use tokio::sync::{mpsc, Semaphore};
use futures::stream::{self, StreamExt};
use std::sync::Arc;

pub struct HighThroughputProcessor {
    storage: Arc<RwLock<UnifiedStorageSystem>>,
    upload_semaphore: Arc<Semaphore>,
    download_semaphore: Arc<Semaphore>,
    processing_semaphore: Arc<Semaphore>,
}

impl HighThroughputProcessor {
    pub fn new(storage: UnifiedStorageSystem, max_concurrent_ops: usize) -> Self {
        Self {
            storage: Arc::new(RwLock::new(storage)),
            upload_semaphore: Arc::new(Semaphore::new(max_concurrent_ops / 2)),
            download_semaphore: Arc::new(Semaphore::new(max_concurrent_ops / 2)),
            processing_semaphore: Arc::new(Semaphore::new(max_concurrent_ops)),
        }
    }
    
    pub async fn batch_upload(&self, requests: Vec<UploadRequest>, identity: ZhtpIdentity) -> Vec<Result<ContentHash>> {
        let batch_size = 10; // Process in batches of 10
        let mut results = Vec::new();
        
        for batch in requests.chunks(batch_size) {
            let batch_results: Vec<_> = stream::iter(batch)
                .map(|request| {
                    let storage = self.storage.clone();
                    let semaphore = self.upload_semaphore.clone();
                    let identity = identity.clone();
                    let request = request.clone();
                    
                    async move {
                        let _permit = semaphore.acquire().await.unwrap();
                        let mut storage = storage.write().await;
                        storage.upload_content(request, identity).await
                    }
                })
                .buffer_unordered(batch_size) // Process batch concurrently
                .collect().await;
            
            results.extend(batch_results);
            
            // Small delay between batches to prevent overwhelming the network
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        
        results
    }
    
    pub async fn batch_download(&self, hashes: Vec<ContentHash>, identity: ZhtpIdentity) -> Vec<Result<Vec<u8>>> {
        let batch_size = 20; // Downloads can be more concurrent
        let mut results = Vec::new();
        
        for batch in hashes.chunks(batch_size) {
            let batch_results: Vec<_> = stream::iter(batch)
                .map(|hash| {
                    let storage = self.storage.clone();
                    let semaphore = self.download_semaphore.clone();
                    let identity = identity.clone();
                    let hash = hash.clone();
                    
                    async move {
                        let _permit = semaphore.acquire().await.unwrap();
                        let mut storage = storage.write().await;
                        let request = DownloadRequest {
                            content_hash: hash,
                            requester: identity,
                            access_proof: None,
                        };
                        storage.download_content(request).await
                    }
                })
                .buffer_unordered(batch_size)
                .collect().await;
            
            results.extend(batch_results);
        }
        
        results
    }
    
    pub async fn streaming_upload<S>(&self, stream: S, identity: ZhtpIdentity) -> mpsc::Receiver<Result<ContentHash>>
    where
        S: Stream<Item = UploadRequest> + Send + 'static,
    {
        let (tx, rx) = mpsc::channel(100);
        let storage = self.storage.clone();
        let semaphore = self.upload_semaphore.clone();
        
        tokio::spawn(async move {
            stream
                .for_each_concurrent(10, |request| {
                    let tx = tx.clone();
                    let storage = storage.clone();
                    let semaphore = semaphore.clone();
                    let identity = identity.clone();
                    
                    async move {
                        let _permit = semaphore.acquire().await.unwrap();
                        let mut storage = storage.write().await;
                        let result = storage.upload_content(request, identity).await;
                        let _ = tx.send(result).await;
                    }
                })
                .await;
        });
        
        rx
    }
}
```

### Memory Management Optimization

```rust
use std::sync::Arc;
use bytes::{Bytes, BytesMut};

pub struct MemoryOptimizedStorage {
    storage: UnifiedStorageSystem,
    buffer_pool: Arc<BufferPool>,
}

pub struct BufferPool {
    small_buffers: Vec<BytesMut>,  // 4KB buffers
    medium_buffers: Vec<BytesMut>, // 64KB buffers  
    large_buffers: Vec<BytesMut>,  // 1MB buffers
}

impl BufferPool {
    pub fn new() -> Self {
        Self {
            small_buffers: (0..100).map(|_| BytesMut::with_capacity(4096)).collect(),
            medium_buffers: (0..50).map(|_| BytesMut::with_capacity(65536)).collect(),
            large_buffers: (0..20).map(|_| BytesMut::with_capacity(1048576)).collect(),
        }
    }
    
    pub fn get_buffer(&mut self, size: usize) -> BytesMut {
        if size <= 4096 && !self.small_buffers.is_empty() {
            let mut buf = self.small_buffers.pop().unwrap();
            buf.clear();
            buf
        } else if size <= 65536 && !self.medium_buffers.is_empty() {
            let mut buf = self.medium_buffers.pop().unwrap();
            buf.clear();
            buf
        } else if size <= 1048576 && !self.large_buffers.is_empty() {
            let mut buf = self.large_buffers.pop().unwrap();
            buf.clear();
            buf
        } else {
            BytesMut::with_capacity(size)
        }
    }
    
    pub fn return_buffer(&mut self, buf: BytesMut) {
        let capacity = buf.capacity();
        if capacity == 4096 && self.small_buffers.len() < 100 {
            self.small_buffers.push(buf);
        } else if capacity == 65536 && self.medium_buffers.len() < 50 {
            self.medium_buffers.push(buf);
        } else if capacity == 1048576 && self.large_buffers.len() < 20 {
            self.large_buffers.push(buf);
        }
        // Otherwise let it drop
    }
}

impl MemoryOptimizedStorage {
    pub async fn zero_copy_upload(&mut self, content: Bytes, metadata: ContentMetadata, identity: ZhtpIdentity) -> Result<ContentHash> {
        // Use zero-copy approach with Bytes
        let upload_req = UploadRequest {
            content: content.to_vec(), // This copies, but we can optimize further
            filename: metadata.filename,
            mime_type: metadata.content_type,
            description: metadata.description,
            tags: metadata.tags,
            encrypt: false,
            compress: true,
            access_control: AccessControlSettings::default(),
            storage_requirements: ContentStorageRequirements::default(),
        };
        
        self.storage.upload_content(upload_req, identity).await
    }
}
```

##  Performance Monitoring and Tuning

### Real-time Performance Metrics

```rust
use prometheus::{
    Counter, Histogram, Gauge, IntGauge,
    register_counter, register_histogram, register_gauge, register_int_gauge
};
use std::time::Instant;

pub struct PerformanceMetrics {
    // Throughput metrics
    uploads_per_second: Counter,
    downloads_per_second: Counter,
    bytes_uploaded_per_second: Counter,
    bytes_downloaded_per_second: Counter,
    
    // Latency metrics
    upload_latency: Histogram,
    download_latency: Histogram,
    search_latency: Histogram,
    
    // Resource usage
    memory_usage: Gauge,
    cpu_usage: Gauge,
    disk_usage: Gauge,
    network_usage: Gauge,
    
    // System health
    active_connections: IntGauge,
    cache_hit_rate: Gauge,
    error_rate: Gauge,
}

impl PerformanceMetrics {
    pub fn new() -> Result<Self> {
        Ok(Self {
            uploads_per_second: register_counter!("zhtp_uploads_per_second", "Upload rate")?,
            downloads_per_second: register_counter!("zhtp_downloads_per_second", "Download rate")?,
            bytes_uploaded_per_second: register_counter!("zhtp_bytes_uploaded_per_second", "Upload throughput")?,
            bytes_downloaded_per_second: register_counter!("zhtp_bytes_downloaded_per_second", "Download throughput")?,
            
            upload_latency: register_histogram!(
                "zhtp_upload_latency_seconds",
                "Upload latency",
                vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0]
            )?,
            download_latency: register_histogram!(
                "zhtp_download_latency_seconds", 
                "Download latency",
                vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0]
            )?,
            search_latency: register_histogram!(
                "zhtp_search_latency_seconds",
                "Search latency", 
                vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0]
            )?,
            
            memory_usage: register_gauge!("zhtp_memory_usage_bytes", "Memory usage")?,
            cpu_usage: register_gauge!("zhtp_cpu_usage_percent", "CPU usage")?,
            disk_usage: register_gauge!("zhtp_disk_usage_bytes", "Disk usage")?,
            network_usage: register_gauge!("zhtp_network_usage_bps", "Network usage")?,
            
            active_connections: register_int_gauge!("zhtp_active_connections", "Active connections")?,
            cache_hit_rate: register_gauge!("zhtp_cache_hit_rate", "Cache hit rate")?,
            error_rate: register_gauge!("zhtp_error_rate", "Error rate")?,
        })
    }
    
    pub fn record_upload(&self, start_time: Instant, bytes: u64) {
        let duration = start_time.elapsed();
        self.uploads_per_second.inc();
        self.bytes_uploaded_per_second.inc_by(bytes);
        self.upload_latency.observe(duration.as_secs_f64());
    }
    
    pub fn record_download(&self, start_time: Instant, bytes: u64) {
        let duration = start_time.elapsed();
        self.downloads_per_second.inc();
        self.bytes_downloaded_per_second.inc_by(bytes);
        self.download_latency.observe(duration.as_secs_f64());
    }
    
    pub async fn update_system_metrics(&self) {
        // Update memory usage
        if let Ok(memory) = get_memory_usage().await {
            self.memory_usage.set(memory as f64);
        }
        
        // Update CPU usage
        if let Ok(cpu) = get_cpu_usage().await {
            self.cpu_usage.set(cpu);
        }
        
        // Update disk usage
        if let Ok(disk) = get_disk_usage().await {
            self.disk_usage.set(disk as f64);
        }
    }
}

// System resource monitoring functions
async fn get_memory_usage() -> Result<u64> {
    // Implementation depends on platform
    use sysinfo::{System, SystemExt};
    let mut system = System::new();
    system.refresh_memory();
    Ok(system.used_memory() * 1024) // Convert KB to bytes
}

async fn get_cpu_usage() -> Result<f64> {
    use sysinfo::{System, SystemExt, ProcessorExt};
    let mut system = System::new();
    system.refresh_cpu();
    tokio::time::sleep(Duration::from_millis(100)).await;
    system.refresh_cpu();
    
    let cpu_usage: f32 = system.processors().iter().map(|p| p.cpu_usage()).sum::<f32>() 
                         / system.processors().len() as f32;
    Ok(cpu_usage as f64)
}

async fn get_disk_usage() -> Result<u64> {
    use sysinfo::{System, SystemExt, DiskExt};
    let mut system = System::new();
    system.refresh_disks();
    
    let used_space: u64 = system.disks().iter()
        .map(|disk| disk.total_space() - disk.available_space())
        .sum();
    
    Ok(used_space)
}
```

### Automatic Performance Tuning

```rust
pub struct AutoTuner {
    metrics: PerformanceMetrics,
    config: Arc<RwLock<UnifiedStorageConfig>>,
    tuning_history: VecDeque<TuningEvent>,
}

#[derive(Debug, Clone)]
struct TuningEvent {
    timestamp: Instant,
    parameter: String,
    old_value: f64,
    new_value: f64,
    improvement: f64,
}

impl AutoTuner {
    pub async fn run_tuning_cycle(&mut self) -> Result<Vec<TuningEvent>> {
        let mut events = Vec::new();
        
        // Analyze current performance
        let current_perf = self.analyze_current_performance().await?;
        
        // Tune network parameters
        if let Some(event) = self.tune_network_parameters(&current_perf).await? {
            events.push(event);
        }
        
        // Tune storage parameters
        if let Some(event) = self.tune_storage_parameters(&current_perf).await? {
            events.push(event);
        }
        
        // Tune economic parameters
        if let Some(event) = self.tune_economic_parameters(&current_perf).await? {
            events.push(event);
        }
        
        // Record tuning events
        for event in &events {
            self.tuning_history.push_back(event.clone());
            if self.tuning_history.len() > 100 {
                self.tuning_history.pop_front();
            }
        }
        
        Ok(events)
    }
    
    async fn tune_network_parameters(&mut self, perf: &PerformanceSnapshot) -> Result<Option<TuningEvent>> {
        let mut config = self.config.write().await;
        
        // Tune connection pool size based on utilization
        if perf.connection_utilization > 0.8 && perf.error_rate < 0.01 {
            let old_size = config.network_config.connection_pool_size;
            let new_size = (old_size as f32 * 1.2) as usize; // Increase by 20%
            config.network_config.connection_pool_size = new_size;
            
            return Ok(Some(TuningEvent {
                timestamp: Instant::now(),
                parameter: "connection_pool_size".to_string(),
                old_value: old_size as f64,
                new_value: new_size as f64,
                improvement: 0.0, // Will be measured in next cycle
            }));
        }
        
        // Tune request timeout based on latency
        if perf.avg_latency > Duration::from_secs(5) {
            let old_timeout = config.network_config.request_timeout;
            let new_timeout = old_timeout + Duration::from_secs(5);
            config.network_config.request_timeout = new_timeout;
            
            return Ok(Some(TuningEvent {
                timestamp: Instant::now(),
                parameter: "request_timeout".to_string(),
                old_value: old_timeout.as_secs_f64(),
                new_value: new_timeout.as_secs_f64(),
                improvement: 0.0,
            }));
        }
        
        Ok(None)
    }
}

#[derive(Debug)]
struct PerformanceSnapshot {
    timestamp: Instant,
    avg_latency: Duration,
    throughput_mbps: f64,
    error_rate: f64,
    connection_utilization: f64,
    memory_usage_percent: f64,
    cpu_usage_percent: f64,
    cache_hit_rate: f64,
}
```

## 🛠️ Hardware-Specific Optimizations

### NVMe SSD Optimization

```rust
// Optimized for high-speed NVMe storage
let nvme_optimized_config = StorageConfig {
    // Use direct I/O to bypass OS cache
    enable_direct_io: true,
    
    // High queue depth for NVMe
    io_queue_depth: 64,
    
    // Large block sizes for sequential operations
    block_size: 1024 * 1024, // 1MB blocks
    
    // Alignment for NVMe
    alignment: 4096, // 4KB alignment
    
    // Asynchronous I/O
    enable_async_io: true,
    max_concurrent_ios: 32,
    
    // NVMe-specific settings
    enable_nvme_passthrough: true,
    nvme_submission_queues: 8,
    nvme_completion_queues: 8,
};
```

### Multi-Core CPU Optimization

```rust
// CPU-optimized configuration
let cpu_optimized_config = ProcessingConfig {
    // Use all available cores
    worker_threads: 0, // Auto-detect
    
    // Thread affinity for NUMA systems
    enable_thread_affinity: true,
    numa_aware: true,
    
    // CPU-specific optimizations
    enable_simd: true,          // Use SIMD instructions
    enable_vectorization: true, // Auto-vectorization
    
    // Work stealing for load balancing
    enable_work_stealing: true,
    work_steal_batch_size: 8,
    
    // Cache-friendly data structures
    cache_line_size: 64,
    prefetch_distance: 8,
};
```

>>>>>>> 160e135c54d30cf715cbb2bc4e005cffdc6e9f77
This performance optimization guide provides comprehensive strategies for maximizing ZHTP Storage System performance across all layers. Apply these optimizations based on your specific use case, hardware configuration, and performance requirements.