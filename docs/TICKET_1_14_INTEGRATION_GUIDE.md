# Ticket #1.14: DHT Unified Registry Integration Guide

**Status:** ARCHITECTURE ALIGNED WITH PR #461
**Branch:** 148-arch-d-114-migrate-dht-to-use-unified-peer-registry
**Objective:** Enable DHT layer to use unified peer storage via trait-based dependency injection

## Overview

This ticket defines a trait-based interface (`DhtPeerRegistryTrait`) that allows the DHT layer to work with any peer registry implementation. The integration happens at the zhtp level via dependency injection, following the architecture established in PR #461.

## Architecture

### Design Principle (Following PR #461)

PR #461 resolved the lib-network ↔ lib-storage circular dependency by:
1. Creating `lib-types` for behavior-free primitives
2. Removing lib-storage dependency from lib-network
3. Moving integration logic to the zhtp layer

This PR extends that pattern by defining a trait in lib-storage that zhtp can use to wire components together.

```
┌─────────────────────────────────────────────────────────┐
│                    zhtp (integration layer)              │
│  ┌─────────────────────────────────────────────────────┐│
│  │ Creates unified registry, wires to both layers      ││
│  └─────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────┘
         │                              │
         ▼                              ▼
┌─────────────────┐          ┌─────────────────────────────┐
│   lib-network    │          │        lib-storage          │
│ (no storage dep) │          │ DhtPeerRegistryTrait        │
│                  │          │ DhtPeerRegistry (impl)      │
│                  │          │ KademliaRouter              │
└─────────────────┘          └─────────────────────────────┘
```

**IMPORTANT:** lib-network MUST NOT import from lib-storage. Integration happens in zhtp only.

## Implementation

### ✅ Completed

1. **DhtPeerRegistryTrait** ([lib-storage/src/dht/registry_trait.rs](../lib-storage/src/dht/registry_trait.rs))
   - Defines minimal interface DHT needs from a peer registry
   - Methods: `add_dht_peer`, `find_closest_dht_peers`, `get_dht_bucket_peers`, etc.

2. **DhtPeerRegistry implements DhtPeerRegistryTrait** ([lib-storage/src/dht/peer_registry.rs](../lib-storage/src/dht/peer_registry.rs))
   - lib-storage's internal registry implements the trait
   - Provides DHT peer storage with K-bucket semantics

3. **KademliaRouter supports external registry** ([lib-storage/src/dht/routing.rs](../lib-storage/src/dht/routing.rs))
   - Added `external_registry: Option<Arc<RwLock<dyn DhtPeerRegistryTrait>>>` field
   - Added `set_external_registry()` method for dependency injection
   - Keeps internal registry as fallback for backwards compatibility

## Integration Pattern (zhtp layer)

If unified peer storage is needed across DHT and mesh layers, the integration
must happen in zhtp (NOT in lib-network to avoid circular dependencies):

```rust
// In zhtp/src/integration/
use lib_storage::dht::{DhtPeerRegistryTrait, KademliaRouter};

// Option 1: Use lib-storage's DhtPeerRegistry directly
let dht_registry = Arc::new(RwLock::new(DhtPeerRegistry::new(20)));
router.set_external_registry(dht_registry.clone());

// Option 2: Create a zhtp-level unified registry that implements DhtPeerRegistryTrait
// This wrapper could bridge lib-network::PeerRegistry with DhtPeerRegistryTrait
// Implementation would live in zhtp/src/integration/, NOT in lib-network
```

## What This PR Does NOT Do

- ❌ Does NOT add lib-storage dependency to lib-network (would re-introduce circular dep)
- ❌ Does NOT implement DhtPeerRegistryTrait for lib-network::PeerRegistry directly
- ❌ Does NOT merge DhtPeerRegistry with lib-network::PeerRegistry at compile time

## Benefits

| Metric | Before | After | Improvement |
|--------|--------|-------|-------------|
| Circular Dependency | Risk | None | **Architecturally clean** |
| DHT Peer Storage | Internal only | Trait-based | **Flexible** |
| Integration Point | Scattered | zhtp layer | **Centralized** |

## Acceptance Criteria

- [x] `DhtPeerRegistryTrait` defined in lib-storage
- [x] `DhtPeerRegistry` implements `DhtPeerRegistryTrait`
- [x] `KademliaRouter` accepts external registry via trait
- [x] No circular dependency errors
- [x] lib-network has NO imports from lib-storage
- [x] `cargo check --workspace` passes

## Related Files

- **lib-storage/src/dht/registry_trait.rs** - Trait definition
- **lib-storage/src/dht/peer_registry.rs** - DhtPeerRegistry trait implementation
- **lib-storage/src/dht/routing.rs** - KademliaRouter with injection support
- **zhtp/src/integration/** - Where unified registry wiring would happen

## Notes

- Circular dependency avoided: trait defined in lib-storage, NOT implemented in lib-network
- Integration layer (zhtp) owns the wiring logic
- This follows the pattern established in PR #461
