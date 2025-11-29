//! DHT (Distributed Hash Table) Foundation Layer
//! 
//! This module implements the core DHT functionality that serves as the foundation
//! for the economic storage layer. It provides Kademlia-based routing, peer discovery,
//! and basic key-value operations with zero-knowledge privacy.

pub mod node;
pub mod routing;
pub mod network;
pub mod storage;
pub mod messaging;
pub mod peer_management;
pub mod replication;

// Re-export main DHT components
pub use node::*;
pub use routing::*;
pub use network::*;
pub use storage::*;
pub use messaging::*;
pub use peer_management::*;
pub use replication::*;

// DHT Configuration Constants
pub const DHT_PORT: u16 = 33442;
pub const K_BUCKET_SIZE: usize = 20;
pub const DHT_REPLICATION_FACTOR: usize = 3;
pub const PING_TIMEOUT_SECS: u64 = 5;
pub const QUERY_TIMEOUT_SECS: u64 = 10;
