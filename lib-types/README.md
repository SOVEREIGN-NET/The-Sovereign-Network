# lib-types

Sovereign Network primitives and protocol-neutral data shapes. Behavior-free and runtime-free.

## Purpose

`lib-types` is the **canonical source** for all protocol-neutral, behavior-free data types used across the Sovereign Network codebase.

## Type Architecture Rule

**Principle**: `lib-types` is the canonical source for all protocol-neutral, behavior-free data types.

### What belongs in lib-types:

- ✅ **Pure data structs/enums** - No methods beyond basic constructors/accessors
- ✅ **Types used across multiple crates** - Shared primitives
- ✅ **Serialization-stable types** - Consensus-relevant data
- ✅ **Primitive types** - `Address`, `Hash`, `Amount`, `BlockHeight`, etc.

### What does NOT belong in lib-types:

- ❌ **Business logic / calculation methods** - Use extension traits in domain crates
- ❌ **I/O operations** - No async, networking, storage, or logging
- ❌ **Complex external dependencies** - Avoid crypto, storage dependencies
- ❌ **Implementation details** - Keep domain-specific behavior in domain crates

### Pattern for adding behavior:

```rust
// In lib-types: pure data
pub struct MyType {
    pub field: u64,
}

// In domain crate: behavior via extension trait
pub trait MyTypeExt {
    fn calculate_something(&self) -> Result<u64, Error>;
}

impl MyTypeExt for MyType {
    fn calculate_something(&self) -> Result<u64, Error> {
        // Business logic here
    }
}
```

### Examples

| Type | Location | Extension Trait |
|------|----------|-----------------|
| `TxKind` | `lib-types::fees` | `TxKindExt` in `lib-fees` |
| `FeeInput` | `lib-types::fees` | `FeeInputExt` in `lib-fees` |
| `ConsensusStep` | `lib-types::consensus` | `ConsensusStepExt` in `lib-consensus` |
| `MempoolConfig` | `lib-types::mempool` | `MempoolConfigExt` in `lib-mempool` |
| `WorkMetrics` | `lib-types::economy` | `WorkMetricsExt` in `lib-economy` |

## Non-goals

- No async, no tokio
- No networking, no storage, no logging
- No feature flags
- No dependency on any internal crate
- No behavior or policy; if a type needs logic, it lives elsewhere

## Dependency Policy

- Only `serde` (derive), `blake3`, `hex`, `anyhow`, `getrandom`
- Nothing else; adding dependencies requires explicit approval

## Stability Contract (v0.1.0)

- Binary layout of `NodeId` and `ChunkId` must not change
- Serialized field names and enum variants are stable
- Allowed: adding new enums/structs/modules
- Breaking changes (require v1.0): changing existing struct fields, enum variants, or serialization behavior

## Module Overview

```
lib-types/
└── src/
    ├── lib.rs              # Main exports
    ├── primitives.rs       # Address, BlockHash, TxHash, TokenId, Amount, BlockHeight
    ├── node_id.rs          # NodeId (96-byte with entropy)
    ├── peer.rs             # PeerId
    ├── dht/                # DHT-related types
    │   ├── mod.rs          # DHT module root
    │   └── types.rs        # Core DHT type definitions
    ├── chunk.rs            # Chunk types
    ├── fees.rs             # TxKind, SigScheme, FeeInput, FeeParams, FeeDeficit
    ├── consensus.rs        # ConsensusStep, VoteType, ConsensusConfig, FeeDistributionResult
    ├── economy.rs          # Priority, TreasuryFund, WorkMetrics, NetworkStats
    ├── mempool.rs          # MempoolConfig, MempoolState, AdmitResult, AdmitTx
    └── errors.rs           # Shared error types
```

## Migration Guide

### Moving a type from a domain crate to lib-types

1. **Move the type definition** to appropriate `lib-types/src/<module>.rs`
2. **Keep only pure data** - Remove all methods, keep only fields and Serde derives
3. **Re-export from domain crate** - `pub use lib_types::<module>::TypeName;`
4. **Create extension trait** - Move behavior methods to `<Type>Ext` trait in domain crate
5. **Update imports** - Other crates should import from lib-types (or domain re-export)
6. **Add tests** - Serialization roundtrip tests in lib-types

### Example: Moving `MempoolConfig`

```rust
// lib-types/src/mempool.rs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MempoolConfig {
    pub max_mempool_bytes: u64,
    pub max_tx_count: u32,
    // ... fields only, no methods
}

// lib-mempool/src/config.rs
pub use lib_types::mempool::MempoolConfig;

pub trait MempoolConfigExt {
    fn effective_min_fee(&self, computed_fee: Amount) -> Amount;
}

impl MempoolConfigExt for MempoolConfig {
    fn effective_min_fee(&self, computed_fee: Amount) -> Amount {
        computed_fee.saturating_mul(self.min_fee_multiplier_bps as Amount) / 10_000
    }
}
```

## Adding New Types

When adding a new shared type:

1. Does it need to be shared across multiple crates? → Yes, put in lib-types
2. Does it need business logic methods? → Put data in lib-types, methods in domain crate via extension trait
3. Is it consensus-relevant? → Must be in lib-types for serialization stability

## Related

- [TYPES-EPIC #1642](https://github.com/SOVEREIGN-NET/The-Sovereign-Network/issues/1642) - Type centralization tracking
- [AGENTS.md](../AGENTS.md) - Agent responsibilities including type architecture
