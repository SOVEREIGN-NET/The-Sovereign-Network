// DEPRECATED: TCP/UDP bootstrap removed - using QUIC-only architecture
// pub mod tcp_server;  // REMOVED
// pub mod udp_server;  // REMOVED
pub mod handshake;
pub mod peer_discovery;

// Re-exports for convenience
pub use handshake::*;
pub use peer_discovery::*;

// Bootstrap and peer discovery functionality
