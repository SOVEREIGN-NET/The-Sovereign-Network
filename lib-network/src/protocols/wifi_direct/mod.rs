//! WiFi Direct Protocol Suite
//!
//! Peer-to-peer wireless protocol implementation following FCIS (Functional Core / Imperative Shell):
//! - WiFi Direct device discovery and group formation
//! - Service discovery (mDNS/Bonjour)
//! - ChaCha20Poly1305 encryption with peer context
//! - Group owner and legacy setup
//! - Enhanced parsing with FCIS architecture
//! - UHP handshake adapter for WiFi Direct
//! - Platform abstraction (Linux, Windows, macOS)
//!
//! # Architecture
//!
//! The WiFi Direct protocol is organized into functional areas:
//! - `types.rs` - Data structures and enums for the protocol
//! - `platform/` - Platform-specific implementations with trait abstraction
//! - `enhanced/` - Enhanced implementations with FCIS-compliant modules
//! - `core/` - Pure functional algorithms (when extracted)
//! - `wifi_direct*.rs` - Legacy modules (to be refactored)

pub mod wifi_direct;
pub mod wifi_direct_encryption;
pub mod wifi_direct_handshake;
pub mod enhanced_wifi_direct;

// New modular structure
pub mod platform;
pub mod enhanced;

// Re-exports for convenience
pub use self::wifi_direct::*;
pub use self::wifi_direct_encryption::WiFiDirectEncryption;
pub use self::wifi_direct_handshake::*;
pub use self::enhanced_wifi_direct::*;
pub use self::platform::WiFiDirectPlatform;
