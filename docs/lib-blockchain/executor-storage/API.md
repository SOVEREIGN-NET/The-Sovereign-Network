# Persistent Contract Storage API Reference

## Module Overview

The `contracts::executor::storage` module provides production-ready persistent contract state storage with crash recovery, caching, and state verification.

**Feature flag:** `persistent-contracts`

```rust
use lib_blockchain::contracts::executor::storage::*;
```

## Core Types

### PersistentStorage

Durable contract state storage backed by Sled embedded database.

```rust
pub struct PersistentStorage {
    db: Arc<sled::Db>,
}

impl PersistentStorage {
    /// Create new persistent storage instance
    pub fn new(path: &str, tree_name: Option<&str>) -> StorageResult<Self>

    /// Open existing storage or create if not exists
    pub fn open(path: &str) -> StorageResult<Self>

    /// Get reference to Sled tree for advanced operations
    pub fn get_tree(&self) -> StorageResult<sled::Tree>

    /// Flush all pending operations to disk
    pub fn flush(&mut self) -> StorageResult<()>

    /// Get storage statistics
    pub fn stats(&self) -> StorageResult<StorageStats>

    /// Scan all keys with given prefix
    pub fn scan_prefix(&self, prefix: &[u8]) -> StorageResult<Vec<(Vec<u8>, Vec<u8>)>>

    /// Delete all keys with given prefix
    pub fn delete_prefix(&mut self, prefix: &[u8]) -> StorageResult<()>
}

impl ContractStorage for PersistentStorage {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>>
    fn set(&mut self, key: &[u8], value: &[u8]) -> Result<()>
    fn delete(&mut self, key: &[u8]) -> Result<()>
    fn exists(&self, key: &[u8]) -> Result<bool>
}
```

**Example:**
```rust
let storage = PersistentStorage::new("./state/contracts", None)?;
let contract_state = storage.get(b"contract:token:balance:alice")?;
```

### CachedPersistentStorage

High-performance wrapper combining persistent durability with hot-path caching.

```rust
pub struct CachedPersistentStorage {
    storage: PersistentStorage,
    cache: StateCache,
}

impl CachedPersistentStorage {
    /// Create with default cache configuration (16MB)
    pub fn new(storage: PersistentStorage) -> StorageResult<Self>

    /// Create with custom cache configuration
    pub fn with_cache_config(
        storage: PersistentStorage,
        cache_config: CacheConfig,
    ) -> StorageResult<Self>

    /// Get current cache statistics
    pub fn cache_stats(&self) -> StorageResult<CacheStats>

    /// Clear all cached entries
    pub fn clear_cache(&self) -> StorageResult<()>

    /// Get underlying storage reference
    pub fn underlying_storage(&self) -> &PersistentStorage
}

impl ContractStorage for CachedPersistentStorage {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>>
    fn set(&mut self, key: &[u8], value: &[u8]) -> Result<()>
    fn delete(&mut self, key: &[u8]) -> Result<()>
    fn exists(&self, key: &[u8]) -> Result<bool>
}
```

**Example:**
```rust
let storage = PersistentStorage::new("./state/contracts", None)?;
let cached = CachedPersistentStorage::new(storage)?;

// First access: cache miss, loads from disk
let balance = cached.get(b"balance:alice")?;

// Subsequent accesses: cache hit, <1 microsecond latency
for _ in 0..1000 {
    let _ = cached.get(b"balance:alice")?;
}

// Monitor cache effectiveness
let stats = cached.cache_stats()?;
println!("Hit rate: {:.1}%", stats.hit_rate());
```

### StateCache

LRU cache for hot contract state with configurable size and eviction.

```rust
pub struct StateCache {
    cache: Arc<Mutex<LruCache<Vec<u8>, Vec<u8>>>>,
    stats: Arc<Mutex<CacheStats>>,
}

impl StateCache {
    /// Create cache with default configuration (16MB)
    pub fn new() -> StorageResult<Self>

    /// Create cache with custom configuration
    pub fn with_config(config: CacheConfig) -> StorageResult<Self>

    /// Get cached value if exists
    pub fn get(&self, key: &[u8]) -> StorageResult<Option<Vec<u8>>>

    /// Put value in cache
    pub fn put(&self, key: Vec<u8>, value: Vec<u8>) -> StorageResult<()>

    /// Invalidate cache entry
    pub fn invalidate(&self, key: &[u8]) -> StorageResult<()>

    /// Clear all cache entries
    pub fn clear(&self) -> StorageResult<()>

    /// Get cache statistics
    pub fn stats(&self) -> StorageResult<CacheStats>

    /// Reset statistics (useful for profiling)
    pub fn reset_stats(&self) -> StorageResult<()>
}
```

**Configuration:**
```rust
pub struct CacheConfig {
    pub max_size: usize,           // Bytes (default: 16MB)
    pub eviction_policy: EvictionPolicy,
}

pub enum EvictionPolicy {
    Lru,  // Least Recently Used
}

// Example: 32MB cache
let cache = StateCache::with_config(CacheConfig {
    max_size: 32 * 1024 * 1024,
    eviction_policy: EvictionPolicy::Lru,
})?;
```

**Statistics:**
```rust
pub struct CacheStats {
    pub hits: u64,           // Number of cache hits
    pub misses: u64,         // Number of cache misses
    pub evictions: u64,      // Number of entries evicted
    pub entry_count: u64,    // Current entries in cache
    pub size: usize,         // Current size in bytes
}

impl CacheStats {
    pub fn hit_rate(&self) -> f64 {
        // Returns hit_rate as 0.0-100.0
    }
}
```

### StateVersionManager

Block height-based state versioning for historical queries and recovery.

```rust
pub struct StateVersionManager {
    storage: Arc<PersistentStorage>,
    retention_blocks: Option<u64>,
}

impl StateVersionManager {
    /// Create version manager with specified retention
    pub fn new(storage: Arc<PersistentStorage>, retention: Option<u64>) -> Self

    /// Store versioned state at block height
    pub fn store_versioned(
        &self,
        height: u64,
        key: &[u8],
        value: &[u8],
    ) -> Result<()>

    /// Get state at specific block height
    pub fn get_versioned(
        &self,
        key: &[u8],
        height: u64,
    ) -> Result<Option<Vec<u8>>>

    /// Get current (latest) state
    pub fn get_latest(&self, key: &[u8]) -> Result<Option<Vec<u8>>>

    /// Update last finalized height for recovery
    pub fn update_last_finalized_height(&self, height: u64) -> Result<()>

    /// Get last finalized height
    pub fn get_last_finalized_height(&self) -> Result<Option<u64>>

    /// Prune old versions beyond retention period
    pub fn prune_old_versions(&self, up_to_height: u64) -> Result<()>
}
```

**Key Format:** `state:{block_height}:{original_key}`

**Example:**
```rust
let mgr = StateVersionManager::new(storage, Some(1000));

// Store state at block height
mgr.store_versioned(100, b"balance:alice", b"1000")?;

// Query historical state
let state_at_100 = mgr.get_versioned(b"balance:alice", 100)?;

// Query latest state
let current = mgr.get_latest(b"balance:alice")?;

// Finalize block - update checkpoint for recovery
mgr.update_last_finalized_height(100)?;

// Clean up old versions (>100 blocks old)
mgr.prune_old_versions(100)?;
```

### StateRootComputation

Merkle root computation for block header consensus validation.

```rust
pub struct StateRootComputation {
    storage: Arc<PersistentStorage>,
}

impl StateRootComputation {
    /// Create state root computer
    pub fn new(storage: Arc<PersistentStorage>) -> Self

    /// Compute merkle root for all state at height
    pub fn compute_state_root(&self, height: u64) -> Result<Vec<u8>>

    /// Verify state against known root
    pub fn verify_state_root(&self, height: u64, expected_root: &[u8]) -> Result<bool>
}
```

**Hash Algorithm:** blake3 with lexicographic key sorting

**Example:**
```rust
let computer = StateRootComputation::new(storage);

// Compute state root for block
let root = computer.compute_state_root(100)?;

// Root is 32 bytes (blake3 hash)
assert_eq!(root.len(), 32);

// Include in block header
block.state_root = root.clone();

// Later, verify root is correct
let verified = computer.verify_state_root(100, &root)?;
assert!(verified);
```

### WalRecoveryManager

Write-Ahead Log crash recovery from incomplete transactions.

```rust
pub struct WalRecoveryManager {
    storage: Arc<PersistentStorage>,
}

pub struct RecoveryStats {
    pub wal_entries_found: usize,
    pub entries_recovered: usize,
    pub entries_discarded: usize,
    pub last_finalized_height: Option<u64>,
}

impl WalRecoveryManager {
    /// Create recovery manager
    pub fn new(storage: Arc<PersistentStorage>) -> Self

    /// Recover from crash - run on startup
    pub fn recover_from_crash(&self) -> Result<RecoveryStats>

    /// Check if block was incomplete (has WAL entry)
    pub fn is_incomplete_block(&self, height: u64) -> Result<bool>

    /// Clean up old WAL entries
    pub fn cleanup_old_wal(&self) -> Result<()>

    /// Build WAL key for height
    fn make_wal_key(&self, height: u64) -> Vec<u8>
}
```

**WAL Key Format:** `wal:{block_height}`

**Example:**
```rust
let recovery = WalRecoveryManager::new(storage);

// Run on startup
let stats = recovery.recover_from_crash()?;
println!("Recovery: found={}, recovered={}, discarded={}",
         stats.wal_entries_found,
         stats.entries_recovered,
         stats.entries_discarded);

// Check if specific block needs recovery
if recovery.is_incomplete_block(100)? {
    println!("Block 100 incomplete, recovering...");
}

// Clean up old WAL entries after finalization
recovery.cleanup_old_wal()?;
```

## Error Types

### StorageError

All storage operations return `StorageResult<T>` (alias for `Result<T, StorageError>`).

```rust
pub enum StorageError {
    /// Database corruption detected
    Corruption(String),

    /// Write operation failed
    WriteFailed(String),

    /// WAL recovery failed
    WalRecovery(String),

    /// Cache operation failed
    CacheError(String),

    /// State inconsistency detected
    StateInconsistency(String),

    /// Sled backend error
    BackendError(String),

    /// Serialization/deserialization error
    SerializationError(String),

    /// State root verification failed
    InvalidStateRoot(String),

    /// Key not found
    KeyNotFound(String),

    /// Generic internal error
    Internal(String),
}

pub type StorageResult<T> = Result<T, StorageError>;
```

### RecoveryStrategy

Recommended recovery strategy for different error types:

```rust
pub enum RecoveryStrategy {
    /// Stop and fail immediately
    Fail,

    /// Use last known good state
    UseLastGoodState,

    /// Skip affected entries
    Skip,

    /// Attempt automatic repair
    Repair,

    /// Manual intervention required
    Manual,
}

impl StorageError {
    /// Recommend recovery strategy for this error
    pub fn recovery_strategy(&self) -> RecoveryStrategy { ... }
}
```

## ContractStorage Trait

All backends implement this trait:

```rust
pub trait ContractStorage: Send + Sync {
    /// Get value for key, returns None if not exists
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>>;

    /// Set key-value pair (overwrites if exists)
    fn set(&mut self, key: &[u8], value: &[u8]) -> Result<()>;

    /// Delete key (no-op if not exists)
    fn delete(&mut self, key: &[u8]) -> Result<()>;

    /// Check if key exists
    fn exists(&self, key: &[u8]) -> Result<bool>;
}
```

## Feature Gating

### Default (No Feature)

Only `MemoryStorage` available (for tests):

```rust
use lib_blockchain::contracts::executor::MemoryStorage;

let storage = MemoryStorage::new();
let executor = ContractExecutor::new(storage);
```

### With `persistent-contracts` Feature

All persistent storage types available:

```rust
#[cfg(feature = "persistent-contracts")]
use lib_blockchain::contracts::executor::storage::*;

#[cfg(feature = "persistent-contracts")]
fn setup() -> Result<()> {
    let storage = PersistentStorage::new("./state", None)?;
    let cached = CachedPersistentStorage::new(storage)?;
    Ok(())
}
```

## Complete Example

Full integration example:

```rust
use lib_blockchain::contracts::executor::{
    ContractExecutor,
    storage::*,
};
use lib_blockchain::contracts::ContractCall;

#[cfg(feature = "persistent-contracts")]
fn run_with_persistence() -> anyhow::Result<()> {
    // 1. Initialize storage
    let storage = PersistentStorage::new("./state/contracts", None)?;
    let cached = CachedPersistentStorage::new(storage)?;

    // 2. Recover from crash
    let recovery = WalRecoveryManager::new(
        cached.underlying_storage().clone()
    );
    let recovery_stats = recovery.recover_from_crash()?;
    println!("Recovery stats: {:?}", recovery_stats);

    // 3. Create executor
    let mut executor = ContractExecutor::new(cached.clone());

    // 4. Execute contracts
    for call in contract_calls {
        let mut context = ExecutionContext::new(
            caller,
            block_height,
            timestamp,
            gas_limit,
            tx_hash,
        );
        executor.execute_call(call, &mut context)?;
    }

    // 5. Finalize block and get state root
    let state_root = executor.finalize_block_state(block_height)?;
    println!("State root: {:?}", hex::encode(&state_root));

    // 6. Monitor cache
    let stats = cached.cache_stats()?;
    println!("Cache hit rate: {:.1}%", stats.hit_rate());

    // 7. Query historical state
    let version_mgr = StateVersionManager::new(
        cached.underlying_storage().clone(),
        Some(1000),
    );
    let old_state = version_mgr.get_versioned(
        b"balance:alice",
        100,  // Query state at block 100
    )?;

    Ok(())
}
```

## Performance Characteristics

### Operations

| Operation | Typical Latency | Notes |
|-----------|-----------------|-------|
| get (cache hit) | <1 μs | Sub-microsecond, in-memory |
| get (cache miss) | 1-10 ms | Disk I/O from Sled |
| set | 1-10 ms | Disk write + WAL entry |
| delete | 1-10 ms | Disk delete + WAL entry |
| compute_state_root | 10-100 ms | For 100k entries |
| recover_from_crash | <1 s | For 1000 WAL entries |

### Memory

| Component | Typical Size |
|-----------|--------------|
| StateCache (default) | 16 MB |
| Sled page cache | 64 MB |
| PersistentStorage overhead | <1 MB |
| **Total** | **~81 MB** |

### Disk

Depends on state size:

```
Small (10k entries)   ~10-50 MB
Medium (100k entries) ~100-500 MB
Large (1M entries)    ~1-5 GB
```

## Thread Safety

All types are thread-safe:

```rust
use std::sync::Arc;
use std::thread;

let storage = Arc::new(CachedPersistentStorage::new(
    PersistentStorage::new("./state", None)?
)?);

let mut handles = vec![];
for _ in 0..10 {
    let s = Arc::clone(&storage);
    handles.push(thread::spawn(move || {
        let _ = s.get(b"key");
    }));
}

for h in handles {
    h.join().unwrap();
}
```

## Debugging

### Enable Logging

```rust
// In main or tests
tracing_subscriber::fmt()
    .with_max_level(tracing::Level::DEBUG)
    .init();

// Now see storage debug logs
let storage = PersistentStorage::new("./state", None)?;
```

### Check Storage Integrity

```rust
// Verify state root computation
let computer = StateRootComputation::new(storage);
let root = computer.compute_state_root(height)?;

// Compute twice - should be identical
let root2 = computer.compute_state_root(height)?;
assert_eq!(root, root2, "Non-deterministic state root!");
```

### Monitor Performance

```rust
// Track cache effectiveness
let stats = cached.cache_stats()?;
if stats.hit_rate() < 80.0 {
    warn!("Low cache hit rate: {:.1}%", stats.hit_rate());
}

// Check disk usage
std::process::Command::new("du")
    .arg("-sh")
    .arg("./state/contracts")
    .output()?;
```

## See Also

- [MIGRATION.md](MIGRATION.md) - Migration guide from MemoryStorage
- [Issue #841](https://github.com/TheSovereignNetwork/The-Sovereign-Network/issues/841) - Persistent Contract Storage
- [Mega-ticket #840](https://github.com/TheSovereignNetwork/The-Sovereign-Network/issues/840) - Contract Deployment Infrastructure
