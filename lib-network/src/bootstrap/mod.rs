// DEPRECATED: TCP/UDP bootstrap removed - using QUIC-only architecture
// pub mod tcp_server;  // REMOVED
// pub mod udp_server;  // REMOVED
pub mod handshake;
pub mod peer_discovery;

// Re-exports for convenience
pub use handshake::{handshake_as_initiator, handshake_as_responder};
pub use peer_discovery::{discover_bootstrap_peers, validate_peer_node_id, PeerInfo};

// Bootstrap and peer discovery functionality
