//! Type definitions for protocol framework
//!
//! This module organizes all protocol-related types into logical sub-modules:
//! - `network.rs` - Network protocol enumeration
//! - `capabilities.rs` - Protocol capabilities and power profiles
//! - `security.rs` - Authentication, cipher suites, PQC modes
//! - `peer.rs` - Peer addressing and identity
//! - `session.rs` - Session management, keys, lifecycle, replay protection

pub mod network;
pub mod capabilities;
pub mod security;
pub mod peer;
pub mod session;

// Re-export commonly used types at module level for convenience
pub use network::NetworkProtocol;
pub use capabilities::{ProtocolCapabilities, PowerProfile, CAPABILITY_VERSION};
pub use security::{AuthScheme, UnsafeAuthScheme, CipherSuite, UnsafeCipherSuite, PqcMode};
pub use peer::{BluetoothMac, ValidatedSocketAddr, ValidatedDeviceId, ValidatedSatelliteId, PeerAddress, VerifiedPeerIdentity};
pub use session::{
    SessionId, SessionKeys, ReplayProtectionState, SessionLifecycle, SessionRenewalReason,
    ProtocolSession,
};
