# Storage Migration Guide - v0.2.0

## Overview

Version 0.2.0 unifies DHT storage abstractions under `UnifiedStorageSystem`. This guide helps you migrate from the old API to the new one.

## Breaking Changes Summary

### 1. ZkDHTIntegration Constructor (lib-network)

**Issue:** `ZkDHTIntegration::new()` is now async and returns `Result`.

#### Before (v0.1.x)
```rust
let dht = ZkDHTIntegration::new(); // Sync, no error handling
```

#### After (v0.2.0)
```rust
// Production code - proper error handling
let dht = ZkDHTIntegration::new().await?;

// Test code - acceptable to panic
let dht = ZkDHTIntegration::new().await.expect("DHT init failed");

// Legacy test code only - will be removed in v0.3.0
#[allow(deprecated)]
let dht = ZkDHTIntegration::new_sync(); // Panics on error
```

**Migration Checklist:**
- [ ] Replace all `ZkDHTIntegration::new()` calls with `ZkDHTIntegration::new().await?`
- [ ] Ensure calling functions are async or use a runtime
- [ ] Add proper error handling (don't just unwrap)
- [ ] Update tests to use async test framework (`#[tokio::test]`)

---

### 2. DhtStorage Visibility (lib-storage)

**Issue:** `DhtStorage` is now `pub(crate)` - not directly accessible from external crates.

#### Before (v0.1.x)
```rust
use lib_storage::dht::storage::DhtStorage;

let dht = DhtStorage::new(node_id, max_size);
dht.store(key, value, ttl).await?;
let data = dht.get(&key).await?;
```

#### After (v0.2.0) - Recommended
```rust
use lib_storage::{UnifiedStorageSystem, UnifiedStorageConfig};

let config = UnifiedStorageConfig::default();
let mut storage = UnifiedStorageSystem::new(config).await?;

// Store with validation
storage.store(key, value, Some(ttl)).await?;

// Retrieve
let data = storage.get(&key).await?;

// Statistics
let stats = storage.get_storage_stats();
let nodes = storage.get_known_nodes();
```

#### After (v0.2.0) - Compatibility Layer
```rust
use lib_storage::compat;

// Create DHT-focused storage (minimal config)
let mut storage = compat::create_dht_focused_storage(
    node_id, 
    max_storage_size, 
    Some(persist_path)
).await?;

// Use same API as UnifiedStorageSystem
storage.store(key, value, Some(ttl)).await?;
```

**Migration Checklist:**
- [ ] Replace direct `DhtStorage` usage with `UnifiedStorageSystem`
- [ ] Update imports to use `lib_storage::UnifiedStorageSystem`
- [ ] Use `compat::create_dht_focused_storage()` for minimal migration
- [ ] Test with persistence path configuration

---

### 3. Generic Storage Operations (lib-storage)

**Issue:** `UnifiedStorageSystem::store()`/`get()`/`remove()` now have validation and limits.

#### Changes in v0.2.0

**Validation Added:**
- Maximum key size: 256 bytes
- Maximum value size: 10 MB per operation
- TTL enforcement: Now properly applied when specified
- Quota: Soft limit of 100 MB per key prefix (logged warning)

#### Before (v0.1.x)
```rust
// No limits, TTL ignored
storage.store(very_long_key, huge_value, Some(3600)).await?;
```

#### After (v0.2.0)
```rust
// Keys > 256 bytes will error
// Values > 10 MB will error
// TTL is now enforced
storage.store(key, value, Some(3600)).await?;

// Large files should use content manager
let upload_req = UploadRequest {
    content: large_data,
    // ... other fields
};
let hash = storage.upload_content(upload_req, uploader_identity).await?;
```

**Error Handling:**
```rust
match storage.store(key, value, ttl).await {
    Ok(_) => println!("Stored successfully"),
    Err(e) if e.to_string().contains("exceeds maximum") => {
        // Use upload_content for large data
        eprintln!("Data too large for generic store: {}", e);
    }
    Err(e) => return Err(e),
}
```

**Migration Checklist:**
- [ ] Audit all `store()` calls for key/value size
- [ ] Add error handling for validation failures
- [ ] Use `upload_content()` for files > 10 MB
- [ ] Monitor logs for quota warnings on key prefixes

---

## Complete Migration Examples

### Example 1: Simple DHT Client

#### Before (v0.1.x)
```rust
use lib_network::dht::ZkDHTIntegration;

fn setup_dht() -> ZkDHTIntegration {
    let dht = ZkDHTIntegration::new();
    dht.initialize(identity).unwrap();
    dht
}
```

#### After (v0.2.0)
```rust
use lib_network::dht::ZkDHTIntegration;
use anyhow::Result;

async fn setup_dht(identity: ZhtpIdentity) -> Result<ZkDHTIntegration> {
    let mut dht = ZkDHTIntegration::new().await?;
    dht.initialize(identity).await?;
    Ok(dht)
}

// In tests
#[tokio::test]
async fn test_dht() {
    let identity = create_test_identity();
    let dht = setup_dht(identity).await.expect("DHT setup failed");
    // ... test logic
}
```

---

### Example 2: Storage Operations

#### Before (v0.1.x)
```rust
use lib_storage::dht::storage::DhtStorage;

let mut dht = DhtStorage::new(node_id, 1_000_000);
dht.store("key", data, None).await?; // TTL ignored
```

#### After (v0.2.0)
```rust
use lib_storage::{UnifiedStorageSystem, UnifiedStorageConfig};

let config = UnifiedStorageConfig {
    node_id,
    storage_config: StorageConfig {
        max_storage_size: 1_000_000,
        dht_persist_path: Some("./data/dht.bin".into()),
        ..Default::default()
    },
    ..Default::default()
};

let mut storage = UnifiedStorageSystem::new(config).await?;
storage.store("key".to_string(), data, Some(3600)).await?; // TTL enforced
```

---

### Example 3: Blockchain Indexing

#### Before (v0.1.x)
```rust
// Direct DhtStorage access
let mut dht_storage = DhtStorage::new(node_id, max_size);

// No validation
dht_storage.store("block/12345", block_data, None).await?;
```

#### After (v0.2.0)
```rust
use lib_storage::UnifiedStorageSystem;

let mut storage = UnifiedStorageSystem::new(config).await?;

// Validated storage with quota monitoring
storage.store(
    format!("block/{}", block_height),
    block_data,
    Some(86400), // 24 hour TTL
).await?;

// Monitor prefix usage
let block_prefix_usage = storage.get_prefix_usage("block/").await?;
if block_prefix_usage > 50_000_000 { // 50 MB
    // Trigger cleanup or archival
}
```

---

## Deprecation Timeline

| Version | Change | Action |
|---------|--------|--------|
| **v0.2.0** (Current) | `new_sync()` deprecated | Add deprecation warnings |
| **v0.2.0** (Current) | `DhtStorage` hidden | Use `UnifiedStorageSystem` |
| **v0.2.0** (Current) | Validation added | Update error handling |
| **v0.3.0** (Q1 2026) | `new_sync()` removed | Migrate all callers to async |
| **v0.3.0** (Q1 2026) | Compat layer deprecated | Complete migration to unified API |

---

## Testing Your Migration

### 1. Check for Deprecation Warnings
```bash
cargo build --all-features 2>&1 | grep "warning: use of deprecated"
```

### 2. Run All Tests
```bash
cargo test --all-features
```

### 3. Test Persistence
```rust
#[tokio::test]
async fn test_persistence_migration() {
    let persist_path = PathBuf::from("./test_data/dht.bin");
    
    // Create and store
    let config = UnifiedStorageConfig {
        storage_config: StorageConfig {
            dht_persist_path: Some(persist_path.clone()),
            ..Default::default()
        },
        ..Default::default()
    };
    
    let mut storage = UnifiedStorageSystem::new(config.clone()).await?;
    storage.store("test_key".to_string(), b"test_value".to_vec(), None).await?;
    drop(storage); // Trigger persistence
    
    // Reload and verify
    let mut storage = UnifiedStorageSystem::new(config).await?;
    let value = storage.get("test_key").await?;
    assert_eq!(value, Some(b"test_value".to_vec()));
}
```

---

## Common Issues & Solutions

### Issue: "DhtStorage is private"
**Solution:** Use `UnifiedStorageSystem` instead:
```rust
// ❌ Old
use lib_storage::dht::storage::DhtStorage;

// ✅ New
use lib_storage::UnifiedStorageSystem;
```

### Issue: "cannot call new() without await"
**Solution:** Make function async and add `.await`:
```rust
// ❌ Old
fn create_dht() -> ZkDHTIntegration {
    ZkDHTIntegration::new()
}

// ✅ New
async fn create_dht() -> Result<ZkDHTIntegration> {
    ZkDHTIntegration::new().await
}
```

### Issue: "Storage key exceeds maximum length"
**Solution:** Use shorter keys or hash long identifiers:
```rust
use lib_crypto::hashing::hash_blake3;

// ❌ Key too long
let key = format!("very/long/path/with/many/segments/{}", long_identifier);

// ✅ Hash long parts
let key_hash = hex::encode(&hash_blake3(long_identifier.as_bytes())[..16]);
let key = format!("data/{}", key_hash);
```

### Issue: "Storage value exceeds maximum size"
**Solution:** Use `upload_content()` for large data:
```rust
// ❌ Direct store for large file
storage.store(key, large_file, None).await?;

// ✅ Use content manager
let upload_req = UploadRequest {
    content: large_file,
    filename: "document.pdf".to_string(),
    // ... configure requirements
};
let hash = storage.upload_content(upload_req, identity).await?;
```

---

## Support

- **Documentation:** See module-level docs in `lib-storage` and `lib-network`
- **Issues:** Report migration problems at GitHub issue tracker
- **Questions:** Use compatibility layer for gradual migration

## Quick Reference

| Old API | New API | Notes |
|---------|---------|-------|
| `ZkDHTIntegration::new()` | `ZkDHTIntegration::new().await?` | Now async |
| `DhtStorage::new()` | `UnifiedStorageSystem::new(config).await?` | Use unified system |
| `dht.store(k, v, ttl)` | `storage.store(k, v, Some(ttl)).await?` | TTL enforced |
| Direct DhtStorage access | `UnifiedStorageSystem` + compat layer | Migration path |
