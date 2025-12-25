//! WiFi Direct Protocol Suite
//!
//! Peer-to-peer wireless protocol implementation:
//! - WiFi Direct device discovery and group formation
//! - Service discovery (mDNS/Bonjour)
//! - ChaCha20Poly1305 encryption with peer context
//! - Group owner and legacy setup
//! - Enhanced parsing with FCIS architecture
//! - UHP handshake adapter for WiFi Direct

pub mod wifi_direct;
pub mod wifi_direct_encryption;
pub mod wifi_direct_handshake;
pub mod enhanced_wifi_direct;

// Re-exports for convenience
pub use self::wifi_direct::*;
pub use self::wifi_direct_encryption::WiFiDirectEncryption;
pub use self::wifi_direct_handshake::*;
pub use self::enhanced_wifi_direct::*;
