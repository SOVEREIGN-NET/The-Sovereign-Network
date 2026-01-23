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
