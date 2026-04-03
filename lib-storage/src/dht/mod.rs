//! DHT (Distributed Hash Table) Foundation Layer
//!
//! This module implements the core DHT functionality that serves as the foundation
//! for the economic storage layer. It provides Kademlia-based routing, peer discovery,
//! and basic key-value operations with zero-knowledge privacy.
//!
//! # Logging
//!
//! This module uses structured logging via the `tracing` crate with appropriate
//! log levels and structured fields for filtering and observability:
//!
//! - `trace!` - Exhaustive debugging (internal state, byte-level details)
//! - `debug!` - Development visibility (successful operations, routine events)
//! - `info!` - Operational milestones (DHT maintenance, node additions)
//! - `warn!` - Recoverable problems (failed pings, missing data)
//! - `error!` - Critical failures (network errors, contract failures)
//!
//! Key functions are decorated with `#[instrument]` for automatic span creation.

pub mod backend;
pub mod messaging;
pub mod network;
pub mod node;
pub mod peer_management;
pub mod peer_registry; // Ticket #148: Internal DHT peer registry
pub mod registry_trait; // Ticket #1.14: Trait for unified registry integration
pub mod replication;
pub mod routing;
pub mod signing;
pub mod storage;
pub mod transport; // Ticket #152: Multi-protocol transport abstraction // Issue #676: DHT message signing and verification

// Re-export main DHT components
pub use messaging::*;
pub use network::*;
pub use node::*;
pub use peer_management::*;
pub use peer_registry::*; // Ticket #148
pub use registry_trait::DhtPeerRegistryTrait; // Ticket #1.14
pub use replication::*;
pub use routing::*;
pub use signing::{
    requires_signature, verify_message_signature, verify_message_signature_bytes, MessageSigner,
    SigningError, VerificationError, MAX_FUTURE_TIMESTAMP_SECS,
};
pub use storage::*;
pub use transport::{DhtTransport, PeerId, UdpDhtTransport}; // Ticket #152 // Issue #676

// DHT Configuration Constants
pub const DHT_PORT: u16 = 33442;
pub const K_BUCKET_SIZE: usize = 20;
pub const DHT_REPLICATION_FACTOR: usize = 3;
pub const PING_TIMEOUT_SECS: u64 = 5;
pub const QUERY_TIMEOUT_SECS: u64 = 10;
