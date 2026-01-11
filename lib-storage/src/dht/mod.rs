//! DHT (Distributed Hash Table) Foundation Layer
//!
//! This module implements the core DHT functionality that serves as the foundation
//! for the economic storage layer. It provides Kademlia-based routing, peer discovery,
//! and basic key-value operations with zero-knowledge privacy.
//!
//! # Logging (MED-9)
//!
//! **TODO:** Replace `println!` with `tracing` throughout this module.
//!
//! This module currently uses `println!` for debug output in multiple files.
//! For production, migrate all logging to use the `tracing` crate:
//!
//! - `tracing::debug!()` for internal state transitions
//! - `tracing::info!()` for significant operations (node add/remove, store/retrieve)
//! - `tracing::warn!()` for recoverable errors
//! - `tracing::error!()` for critical failures
//!
//! Files requiring migration:
//! - `storage.rs` (~40 println! statements)
//! - `replication.rs` (~5 println! statements)
//! - `messaging.rs` (~1 println! statements)
//! - `routing.rs` (~3 println! statements, mostly tests)

pub mod node;
pub mod routing;
pub mod network;
pub mod storage;
pub mod messaging;
pub mod peer_management;
pub mod replication;
pub mod peer_registry; // Ticket #148: Internal DHT peer registry
pub mod transport; // Ticket #152: Multi-protocol transport abstraction
pub mod registry_trait; // Ticket #1.14: Trait for unified registry integration
pub mod signing; // Issue #676: DHT message signing and verification

// Re-export main DHT components
pub use node::*;
pub use routing::*;
pub use network::*;
pub use storage::*;
pub use messaging::*;
pub use peer_management::*;
pub use replication::*;
pub use peer_registry::*; // Ticket #148
pub use transport::{DhtTransport, PeerId, UdpDhtTransport}; // Ticket #152
pub use registry_trait::DhtPeerRegistryTrait; // Ticket #1.14
pub use signing::{
    MessageSigner,
    verify_message_signature,
    verify_message_signature_bytes,
    requires_signature,
    SigningError,
    VerificationError,
    MAX_FUTURE_TIMESTAMP_SECS,
}; // Issue #676

// DHT Configuration Constants
pub const DHT_PORT: u16 = 33442;
pub const K_BUCKET_SIZE: usize = 20;
pub const DHT_REPLICATION_FACTOR: usize = 3;
pub const PING_TIMEOUT_SECS: u64 = 5;
pub const QUERY_TIMEOUT_SECS: u64 = 10;
