# NodeId Migration Guide

## Overview

This guide helps migrate from the old `type NodeId = Hash` (lib-storage) to the new canonical `NodeId` struct in lib-identity.

## What Changed

### Before (lib-storage)
```rust
// lib-storage/src/types/mod.rs
pub type NodeId = Hash;  // Just a 32-byte canonical NodeId
```

**Problems:**
- No DID-based derivation
- 32 bytes (incompatible with DHT's 32-byte UID)
- No validation
- No semantic meaning

### After (lib-identity)
```rust
// lib-identity/src/types/node_id.rs
pub struct NodeId([u8; 32]);

impl NodeId {
    pub fn from_did_device(did: &str, device: &str) -> Result<Self>;
    pub fn to_storage_hash(&self) -> Hash;  // For lib-storage compatibility
    // ... full API
}
```

**Benefits:**
- DID-based deterministic derivation
- 32 bytes (DHT-compatible)
- Strict validation (DID format, device names)
- Rich API (hex, XOR distance, storage conversion)

## Migration Steps

### Step 1: Update Imports

**Before:**
```rust
use lib_storage::NodeId;
```

**After:**
```rust
use lib_identity::types::NodeId;
```

### Step 2: Update NodeId Creation

**Before:**
```rust
// Creating from hash
let node_id: NodeId = some_hash.clone();
```

**After:**
```rust
// Create from DID + device
let node_id = NodeId::from_did_device("did:zhtp:abc123", "laptop")?;

// Or from existing hash (storage compatibility)
let node_id = NodeId::from_storage_hash(&some_hash);
```

### Step 3: Storage Compatibility

If you need to store NodeId as a 32-byte Hash:

```rust
// Convert NodeId → Hash for storage
let hash: Hash = node_id.to_storage_hash();

// Convert Hash → NodeId when loading
let node_id = NodeId::from_storage_hash(&hash);
```

**Note:** `to_storage_hash()` converts directly to 32 bytes (no padding needed - NodeId is now 32 bytes).

### Step 4: Update Comparisons

NodeId now has proper equality:

```rust
// Before (comparing hashes)
if node_id_hash == other_hash { ... }

// After (comparing NodeIds)
if node_id == other_node_id { ... }
```

### Step 5: DHT Distance Calculations

**Before:**
```rust
// Manual XOR on hashes
let distance = xor_hash(&hash1, &hash2);
```

**After:**
```rust
// Built-in XOR distance
let distance = node1.xor_distance(&node2);
```

## Common Patterns

### Pattern 1: User Registration

**Before:**
```rust
let node_id = Hash::from_bytes(&random_bytes);
```

**After:**
```rust
let node_id = NodeId::from_did_device(
    &identity.did,
    &device_name
)?;
```

### Pattern 2: Display/Logging

**Before:**
```rust
println!("NodeId: {}", hex::encode(node_id.as_bytes()));
```

**After:**
```rust
println!("NodeId: {}", node_id);  // Uses Display trait
// Or explicitly:
println!("NodeId: {}", node_id.to_hex());
```

### Pattern 3: Serialization

NodeId implements `Serialize`/`Deserialize`:

```rust
// Automatic serde support
#[derive(Serialize, Deserialize)]
struct Record {
    node_id: NodeId,
}
```

### Pattern 4: Database Storage

```rust
// Store as 32-byte hash for compatibility
let hash = node_id.to_storage_hash();
db.insert("node_id", hash.as_bytes())?;

// Load from database
let hash = Hash::from_bytes(&db.get("node_id")?);
let node_id = NodeId::from_storage_hash(&hash);
```

## Breaking Changes

1. **Size:** Both old and new are 32 bytes
   - Old: Just a Hash alias (no structure)
   - New: Proper struct with DID-based derivation
   - Use `to_storage_hash()` / `from_storage_hash()` for compatibility

2. **Creation Method:** Random → Deterministic
   - Must provide DID + device name
   - No more random NodeId generation

3. **Type Safety:** Type alias → Proper struct
   - Can't directly assign Hash to NodeId
   - Must use conversion methods

## Deprecation Timeline

### Phase 1 (Current)
- ✅ New `NodeId` struct in lib-identity
- ✅ Storage compatibility via `to_storage_hash()`
- ⚠️ Old `type NodeId = Hash` still exists in lib-storage

### Phase 2 (DHT Integration)
- Add lib-dht with 32-byte UID
- Add `to_dht_uid()` / `from_dht_uid()` methods
- Update all packages to use lib-identity NodeId

### Phase 3 (Cleanup)
- Remove `type NodeId = Hash` from lib-storage
- Remove storage compatibility methods (if no longer needed)
- Full migration complete

## Validation Rules

Be aware of new validation constraints:

### DID Validation
- Must start with `did:zhtp:`
- Maximum 256 characters
- No whitespace in identifier
- No special characters: `!@#$%^&*()+=[]{}|\;:'",<>?/`

### Device Name Validation
- Non-empty after trimming
- 1-64 characters
- Only: `a-z A-Z 0-9 . _ -`
- Normalized to lowercase

**Example:**
```rust
// Valid
NodeId::from_did_device("did:zhtp:abc123", "MyLaptop")?;  // → "mylaptop"

// Invalid - will return Err
NodeId::from_did_device("abc123", "laptop")?;              // Missing did:zhtp:
NodeId::from_did_device("did:zhtp:abc", "my laptop")?;    // Space in device
NodeId::from_did_device("did:zhtp:abc", "")?;             // Empty device
```

## Testing Migration

Test checklist:

- [ ] All NodeId creation uses `from_did_device()`
- [ ] Storage operations use `to_storage_hash()` / `from_storage_hash()`
- [ ] No direct Hash → NodeId assignments
- [ ] All DID strings validated
- [ ] Device names follow naming rules
- [ ] Existing stored NodeIds can be loaded
- [ ] Round-trip conversions work (NodeId → Hash → NodeId)

## Need Help?

- See [NodeId documentation](./node_id.md) for complete API reference
- See [Types documentation](./types.md) for integration examples
- Check GitHub issue [#3](https://github.com/SOVEREIGN-NET/lib-identity/issues/3) for implementation details

## Summary

**Key Points:**
1. Import from `lib_identity::types::NodeId`
2. Create using `from_did_device(did, device)`
3. Use `to_storage_hash()` for 32-byte compatibility
4. NodeId is now 32 bytes (DHT-ready)
5. Strict validation prevents malformed identities
