//! Core storage type definitions and type aliases
//!
//! This module contains all the fundamental types used throughout the
//! lib-storage system, extracted from unified_storage.rs for modularization.

use lib_crypto::Hash;

// Sub-modules for organized type definitions
pub mod dht_types;
pub mod storage_types;
pub mod economic_types;
pub mod config_types;
pub mod stats_types;
pub mod node_address;

// Re-export commonly used types for convenience
pub use dht_types::*;
pub use storage_types::*;
pub use economic_types::*;
pub use config_types::*;
pub use stats_types::*;
pub use node_address::*;

/// Node identifier for DHT routing - imported from lib-identity
/// Provides deterministic identity-based NodeIds derived from DIDs
pub use lib_identity::NodeId;

/// Content hash for addressing
pub type ContentHash = Hash;

/// DHT key type
pub type DhtKey = Hash;

/// Storage pricing per GB per day (in ZHTP tokens)
pub const STORAGE_PRICE_PER_GB_DAY: u64 = 100; // 0.001 ZHTP

/// Minimum replication factor
pub const MIN_REPLICATION: u8 = 3;

/// Maximum replication factor
pub const MAX_REPLICATION: u8 = 12;
