# Persistent Contract Storage Migration Guide

## Overview

This guide covers migrating from the ephemeral `MemoryStorage` implementation to the production-ready `PersistentStorage` backend. The new persistent storage layer ensures contract state survives node restarts and provides state verification for network consensus.

**Key Benefits:**
- ✅ Contract state persistence across restarts
- ✅ Crash recovery with Write-Ahead Logging (WAL)
- ✅ State root computation for consensus validation
- ✅ Hot-path caching with 16MB LRU cache (>90% hit rate expected)
- ✅ Block height-based state versioning for historical queries
- ✅ Backward compatible - existing tests use MemoryStorage by default

## Compatibility Matrix

| Component | MemoryStorage | PersistentStorage | Notes |
|-----------|---------------|-------------------|-------|
| Local testing | ✅ Default | ⚠️ Opt-in via feature | Tests use memory by default for speed |
| Development nodes | ✅ Works | ✅ Recommended | Enable `persistent-contracts` feature |
| Production nodes | ❌ Not recommended | ✅ Required | Must use persistent backend |
| Contract executor | ✅ Works with both | ✅ Trait abstraction | No code changes needed |
| State verification | ❌ No root hash | ✅ Merkle root | New consensus validation |
| Historical queries | ❌ Not supported | ✅ Via block height | Full version history available |

## Feature Flag Configuration

### Enable for Development

Add to your `Cargo.toml`:

```toml
[dependencies]
lib-blockchain = { path = "lib-blockchain", features = ["persistent-contracts"] }
```

Or enable on command line:

```bash
cargo build --features persistent-contracts
cargo test --lib --features persistent-contracts
```

### Enable for Production

Update `Cargo.toml` in binary crates:

```toml
[features]
default = ["persistent-contracts"]

[dependencies]
lib-blockchain = { path = "lib-blockchain", features = ["persistent-contracts"] }
```

## Storage Backend Selection

### Configuration Example

```rust
use lib_blockchain::contracts::executor::{ContractExecutor, storage::*};

// For testing (ephemeral, fast)
let storage = MemoryStorage::new();
let executor = ContractExecutor::new(storage);

// For production (persistent, durable)
#[cfg(feature = "persistent-contracts")]
{
    let persistent = PersistentStorage::new("./state/contracts", None)?;
    let cached = CachedPersistentStorage::new(persistent)?;
    let executor = ContractExecutor::new(cached);

    // Automatic WAL recovery on startup
    let recovery_mgr = WalRecoveryManager::new(cached.underlying_storage().clone());
    let stats = recovery_mgr.recover_from_crash()?;
    println!("Recovered from crash: {:?}", stats);
}
```

### Configuration File Approach

Create `config.toml`:

```toml
[storage]
backend = "persistent"  # or "memory" for testing
data_dir = "./state/contracts"
cache_size_mb = 16
version_retention = 1000  # Keep 1000 historical versions
```

Parse and use:

```rust
use lib_blockchain::contracts::executor::storage::*;

enum StorageBackend {
    Memory,
    Persistent {
        data_dir: String,
        cache_config: Option<CacheConfig>
    },
}

fn create_storage(backend: StorageBackend) -> Result<Box<dyn ContractStorage>> {
    match backend {
        StorageBackend::Memory => {
            Ok(Box::new(MemoryStorage::new()))
        }
        StorageBackend::Persistent { data_dir, cache_config } => {
            let persistent = PersistentStorage::new(&data_dir, None)?;
            let cached = if let Some(cfg) = cache_config {
                CachedPersistentStorage::with_cache_config(persistent, cfg)?
            } else {
                CachedPersistentStorage::new(persistent)?
            };
            Ok(Box::new(cached))
        }
    }
}
```

## Migration Steps

### Step 1: Enable Feature Flag

**Before:**
```bash
cargo build
```

**After:**
```bash
cargo build --features persistent-contracts
```

### Step 2: Update Storage Initialization

**Before (MemoryStorage - test only):**
```rust
use lib_blockchain::contracts::executor::{ContractExecutor, MemoryStorage};

let storage = MemoryStorage::new();
let mut executor = ContractExecutor::new(storage);
```

**After (PersistentStorage - production):**
```rust
#[cfg(feature = "persistent-contracts")]
use lib_blockchain::contracts::executor::storage::*;

#[cfg(feature = "persistent-contracts")]
{
    let storage = PersistentStorage::new("./state/contracts", None)?;
    let cached = CachedPersistentStorage::new(storage)?;
    let mut executor = ContractExecutor::new(cached);

    // Recovery happens automatically on first access
}

#[cfg(not(feature = "persistent-contracts"))]
{
    use lib_blockchain::contracts::executor::MemoryStorage;
    let storage = MemoryStorage::new();
    let mut executor = ContractExecutor::new(storage);
}
```

### Step 3: Handle State Root in Block Finalization

**Before (returns `()`):**
```rust
executor.finalize_block_state(block_height)?;
```

**After (returns `Hash` - state root):**
```rust
let state_root = executor.finalize_block_state(block_height)?;
// Include state_root in block header for consensus validation
block.state_root = state_root;
```

### Step 4: Add WAL Recovery on Startup

**Before (no recovery needed):**
```rust
fn start_node() -> Result<()> {
    let storage = MemoryStorage::new();
    let executor = ContractExecutor::new(storage);
    Ok(())
}
```

**After (with automatic recovery):**
```rust
#[cfg(feature = "persistent-contracts")]
fn start_node() -> Result<()> {
    let storage = PersistentStorage::new("./state/contracts", None)?;
    let cached = CachedPersistentStorage::new(storage)?;

    // Automatic recovery from incomplete WAL entries
    let recovery_mgr = WalRecoveryManager::new(cached.underlying_storage().clone());
    let stats = recovery_mgr.recover_from_crash()?;

    if stats.entries_discarded > 0 {
        warn!("Discarded {} incomplete contract transactions during recovery",
              stats.entries_discarded);
    }

    let executor = ContractExecutor::new(cached);
    Ok(())
}
```

## Code Migration Examples

### Example 1: Contract Token Transfer

**Before (MemoryStorage):**
```rust
use lib_blockchain::contracts::{ContractCall, ContractType};
use lib_blockchain::types::CallPermissions;

// Transfer stored in memory, lost on restart
let call = ContractCall {
    contract_type: ContractType::Token,
    method: "transfer".to_string(),
    params: vec![recipient_id, amount],
    permissions: CallPermissions::Public,
};

let result = executor.execute_call(call, &mut context)?;
// State only in memory!
```

**After (PersistentStorage):**
```rust
use lib_blockchain::contracts::{ContractCall, ContractType};
use lib_blockchain::types::CallPermissions;

// Same call, but state persists to disk
let call = ContractCall {
    contract_type: ContractType::Token,
    method: "transfer".to_string(),
    params: vec![recipient_id, amount],
    permissions: CallPermissions::Public,
};

let result = executor.execute_call(call, &mut context)?;

// Finalize block to compute state root and persist to disk
let state_root = executor.finalize_block_state(block_height)?;

// If node crashes here, recovery will restore state on restart
// State root can be included in block header for consensus
```

### Example 2: Historical State Queries

**Before (Not possible):**
```rust
// MemoryStorage cannot query historical state
// Would need to maintain separate archive
```

**After (Supported):**
```rust
#[cfg(feature = "persistent-contracts")]
{
    use lib_blockchain::contracts::executor::storage::*;

    // Query state at specific block height
    let version_mgr = StateVersionManager::new(
        storage.clone(),
        Some(1000)  // Keep 1000 versions
    );

    let historical_state = version_mgr.get_versioned(
        b"contract:token:balance:alice",
        block_height_100
    )?;

    // Query latest state
    let current_state = version_mgr.get_latest(
        b"contract:token:balance:alice"
    )?;
}
```

### Example 3: Cache Monitoring

**Before (No caching):**
```rust
// Every access hits storage
let balance = storage.get(key)?;
```

**After (Transparent caching):**
```rust
#[cfg(feature = "persistent-contracts")]
{
    use lib_blockchain::contracts::executor::storage::*;

    let cached_storage = CachedPersistentStorage::new(storage)?;

    // First access: cache miss, loads from disk
    let balance = cached_storage.get(key)?;

    // Subsequent accesses: cache hits, sub-microsecond latency
    for _ in 0..1000 {
        let balance = cached_storage.get(key)?;
    }

    // Monitor cache effectiveness
    let stats = cached_storage.cache_stats()?;
    println!("Cache stats: {:#?}", stats);
    // Output:
    // - hits: 999
    // - misses: 1
    // - hit_rate: 99.9%
    // - entry_count: 1
    // - evictions: 0
}
```

## Directory Structure

When using PersistentStorage, contract state is stored in a Sled database:

```
./state/
├── contracts/              # Configured storage directory
│   ├── data                # Sled data files
│   │   ├── 0.sled
│   │   ├── 1.sled
│   │   └── ...
│   ├── blobs              # Large value storage
│   ├── state              # Contract state tree
│   ├── wal                # Write-ahead log entries
│   └── manifest           # Sled manifest file
```

### Cleanup and Maintenance

To clear all contract state (use carefully!):

```bash
# Development only - clears persistent state
rm -rf ./state/contracts

# This forces a clean restart on next node launch
```

To backup contract state:

```bash
# Full backup
cp -r ./state/contracts ./state/contracts.backup

# Or use Sled's export/import for compatibility
```

## Troubleshooting

### Issue: "State directory not found"

**Error:**
```
Error: Storage error: Path not found: ./state/contracts
```

**Solution:**
```rust
// Create directory if it doesn't exist
let state_dir = "./state/contracts";
std::fs::create_dir_all(state_dir)?;

let storage = PersistentStorage::new(state_dir, None)?;
```

### Issue: "Cache hit rate is low"

**Problem:** Cache hit rate below 50% indicates poor access patterns.

**Diagnosis:**
```rust
let stats = cached_storage.cache_stats()?;
if stats.hits as f64 / (stats.hits + stats.misses) as f64 < 0.5 {
    warn!("Low cache hit rate: {:.1}%",
          stats.hits as f64 / (stats.hits + stats.misses) as f64 * 100);
}
```

**Solution:** Increase cache size:

```rust
use lib_blockchain::contracts::executor::storage::CacheConfig;

let cache_config = CacheConfig {
    max_size: 32 * 1024 * 1024,  // Increase to 32MB
    eviction_policy: EvictionPolicy::Lru,
};

let cached = CachedPersistentStorage::with_cache_config(
    persistent,
    cache_config
)?;
```

### Issue: "WAL recovery taking too long"

**Problem:** Startup is slow due to recovering many WAL entries.

**Typical causes:**
- Many incomplete blocks from previous crash
- Slow disk I/O
- Large contract states

**Solution:**
```rust
// 1. Check recovery stats
let recovery_mgr = WalRecoveryManager::new(storage.clone());
let stats = recovery_mgr.recover_from_crash()?;
println!("Recovery stats: {:#?}", stats);

// 2. If too many entries, consider a clean restart
if stats.wal_entries_found > 10000 {
    warn!("Large number of WAL entries - consider full resync");
    // Clear old WAL entries manually
    recovery_mgr.cleanup_old_wal()?;
}
```

### Issue: "State root mismatch in consensus"

**Problem:** Block state root doesn't match expected value.

**Cause:** Likely due to non-deterministic state updates or clock skew.

**Debug:**
```rust
use lib_blockchain::contracts::executor::storage::StateRootComputation;

let computer = StateRootComputation::new(storage.clone());

// Compute root at specific height
let root = computer.compute_state_root(block_height)?;

// Verify it's deterministic
let root2 = computer.compute_state_root(block_height)?;
assert_eq!(root, root2, "Root should be deterministic!");

// Compare with expected
if root != expected_root {
    eprintln!("Root mismatch! Computed: {:?}, Expected: {:?}",
              hex::encode(&root),
              hex::encode(&expected_root));
}
```

## Performance Considerations

### Cache Configuration

The default cache size is 16MB, suitable for most deployments:

```rust
// Typical cache performance
// - Hit rate: >90% for UBI, ZHTP, token contracts
// - Memory overhead: 16MB LRU cache + Sled page cache (64MB default)
// - Cache hit latency: <1 microsecond

// For larger deployments, increase cache:
let cache_config = CacheConfig {
    max_size: 64 * 1024 * 1024,  // 64MB for high-volume networks
    eviction_policy: EvictionPolicy::Lru,
};
```

### State Versioning Retention

Keep 1000 historical versions by default:

```rust
let version_mgr = StateVersionManager::new(
    storage.clone(),
    Some(1000)  // Default: 1000 blocks
);

// For high-volume networks, reduce retention:
let version_mgr = StateVersionManager::new(
    storage.clone(),
    Some(100)  // Keep only last 100 blocks
);
```

### Benchmarks

Expected performance with persistent storage:

| Operation | MemoryStorage | PersistentStorage (Cache Miss) | PersistentStorage (Cache Hit) |
|-----------|---------------|--------------------------------|------------------------------|
| Read state | <1 μs | 1-10 ms (disk I/O) | <1 μs |
| Write state | <1 μs | 1-10 ms (disk I/O + WAL) | 1-10 ms (WAL dominates) |
| Finalize block (100k state) | N/A | <100 ms | <100 ms |
| State root computation | N/A | <100 ms | Same |
| Startup recovery | N/A | <1s (1000 WAL entries) | Same |

**Cache Effectiveness:**
- Cold start: 50% hit rate (first 1000 blocks)
- Warm cache: >90% hit rate (established contracts)
- UBI contracts: 98%+ hit rate (frequent, few keys)

## Rollback Plan

If issues arise with persistent storage, rollback is straightforward:

### Temporary Rollback

```rust
// Disable persistent storage by removing feature flag
#[cfg(not(feature = "persistent-contracts"))]
{
    use lib_blockchain::contracts::executor::MemoryStorage;
    let storage = MemoryStorage::new();
    let executor = ContractExecutor::new(storage);
}
```

### Permanent Data Removal

If returning to MemoryStorage permanently:

```bash
# Remove persistent data directory
rm -rf ./state/contracts

# Or backup for analysis
mv ./state/contracts ./state/contracts.archive
```

**Note:** State from persistent storage will be lost. Plan accordingly.

## Next Steps

After enabling persistent storage:

1. **Monitor cache hit rate** - Run with verbose logging for first week
2. **Validate state roots** - Ensure consensus agreement on block headers
3. **Test crash recovery** - Simulate crashes and verify WAL recovery works
4. **Benchmark performance** - Compare actual vs. expected metrics
5. **Scale testing** - Validate performance with 1M+ contract states

## FAQ

**Q: Will existing tests continue to work?**
A: Yes! Tests use `MemoryStorage` by default. Only enable `persistent-contracts` feature when needed.

**Q: What happens to data on disk if I disable the feature?**
A: Nothing - the data stays on disk. Re-enable the feature to access it again.

**Q: Can I switch between MemoryStorage and PersistentStorage?**
A: Yes, but state won't transfer. Each backend has its own state. Start fresh or migrate data manually.

**Q: What's the startup time overhead?**
A: Typically <1s for WAL recovery, plus 1-5s for cache warm-up depending on dataset size.

**Q: Is concurrent access safe?**
A: Yes! PersistentStorage uses Arc and is thread-safe. Sled handles concurrent access.

**Q: How do I monitor disk usage?**
A: Check `./state/contracts` directory size: `du -sh ./state/contracts`

**Q: Can state be corrupted?**
A: Sled is very robust, but use `WalRecoveryManager` to detect and recover from incomplete entries on startup.

## Support

For issues with persistent storage:

1. Check WAL recovery stats on startup
2. Monitor cache hit rate and performance
3. Review error logs for storage errors
4. Consider running `verify_state_root()` to check consistency
5. File an issue with recovery stats and error logs

## References

- **Sled Documentation**: https://github.com/spacejam/sled
- **blake3 Hash Function**: https://github.com/BLAKE3-team/BLAKE3
- **LRU Cache**: https://github.com/jeromefroe/lru-rs
- **Issue #841**: Persistent Contract Storage
- **Mega-ticket #840**: Contract Deployment Infrastructure
