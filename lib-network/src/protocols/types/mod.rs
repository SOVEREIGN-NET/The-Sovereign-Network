//! Type definitions for protocol framework
//!
//! This module organizes all protocol-related types into logical sub-modules:
//! - `network.rs` - Network protocol enumeration
//! - `capabilities.rs` - Protocol capabilities and power profiles
//! - `security.rs` - Authentication, cipher suites, PQC modes
//! - `peer.rs` - Peer addressing and identity
//! - `session.rs` - Session management, keys, lifecycle, replay protection

pub mod capabilities;
pub mod network;
pub mod peer;
pub mod security;
pub mod session;

// Re-export commonly used types at module level for convenience
pub use capabilities::{PowerProfile, ProtocolCapabilities, CAPABILITY_VERSION};
pub use network::NetworkProtocol;
pub use peer::{
    BluetoothMac, PeerAddress, ValidatedDeviceId, ValidatedSatelliteId, ValidatedSocketAddr,
    VerifiedPeerIdentity,
};
pub use security::{AuthScheme, CipherSuite, PqcMode, UnsafeAuthScheme, UnsafeCipherSuite};
pub use session::{
    ProtocolSession, ReplayProtectionState, SessionId, SessionKeys, SessionLifecycle,
    SessionRenewalReason,
};
