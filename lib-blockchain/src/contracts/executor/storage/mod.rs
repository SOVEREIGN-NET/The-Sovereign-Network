//! Persistent Contract Storage Module
//!
//! This module provides a persistent storage backend for contract state,
//! replacing the ephemeral MemoryStorage implementation. It includes:
//!
//! - **PersistentStorage**: Sync wrapper around SledBackend for contract state
//! - **StateVersionManager**: Block height-based state versioning
//! - **StateCache**: Hot state caching with configurable eviction
//! - **WalRecoveryManager**: Crash recovery from write-ahead logs
//! - **StateRootComputation**: Merkle root for consensus validation
//!
//! # Architecture
//!
//! ```text
//! ContractExecutor
//!     ├─> PersistentStorage (implements ContractStorage trait)
//!     │   ├─> StateCache (16MB ARC cache)
//!     │   └─> SledBackend (persistent KV store)
//!     ├─> StateVersionManager (block height-based versioning)
//!     └─> WalRecoveryManager (startup crash recovery)
//! ```
//!
//! # Execution Boundary (CRITICAL ARCHITECTURAL CONSTRAINT)
//!
//! **RULE: This module is STORAGE ONLY. It does NOT execute economic transactions.**
//!
//! All value movement (mint, burn, transfer, lock, release) is executed EXCLUSIVELY
//! by the Treasury Kernel, never by this storage layer.
//!
//! ## What This Module Does
//! - ✅ Persist contract state durably
//! - ✅ Cache hot state for performance
//! - ✅ Record economic INTENT (e.g., "claim UBI", "vote", "propose")
//! - ✅ Compute state roots for consensus
//! - ✅ Provide audit trail via events
//!
//! ## What This Module Does NOT Do
//! - ❌ Mutate token balances
//! - ❌ Mint or burn tokens
//! - ❌ Enforce caps, vesting, or allocation rules
//! - ❌ Execute scheduled payouts
//! - ❌ Make economic policy decisions
//!
//! ## Why This Matters
//! Economic transactions are declarative intent. Execution is deferred to:
//! - **Treasury Kernel**: Sole authority for value movement
//! - **Compensation DAO**: Sole authority for compensation logic
//! - **Role Registry**: Sole authority for identity classification
//!
//! This separation ensures:
//! - No alternative economic execution paths
//! - Clear audit trail
//! - Governance-traceable decisions
//! - Forward compatibility with ABI standardization (#843)
//!
//! **Related Issues:** #841 (this), #840 (mega-ticket), #842, #843, #844
//!
//! # Storage Format
//!
//! Keys are stored with versioning to enable schema evolution:
//! - `state:{block_height}:{original_key}` - Versioned contract state
//! - `wal:{block_height}` - Write-ahead log entries
//! - `state_root:{block_height}` - Merkle root per block
//! - `meta:last_finalized_height` - Recovery metadata
//! - `meta:version` - Schema version

pub mod errors;
pub mod persistent;
pub mod versioning;
pub mod cache;
pub mod recovery;
pub mod state_root;
pub mod cached_persistent;

#[cfg(test)]
mod tests;

#[cfg(all(test, feature = "persistent-contracts"))]
mod benchmarks;

pub use errors::{StorageError, StorageResult};
pub use persistent::PersistentStorage;
pub use versioning::StateVersionManager;
pub use cache::{StateCache, CacheConfig, CacheStats};
pub use recovery::WalRecoveryManager;
pub use state_root::StateRootComputation;
pub use cached_persistent::CachedPersistentStorage;
