//! Protocol Discovery Modules
//!
//! Manages peer discovery via local area network protocols.
//! These are for LOCAL peer discovery only - not entry points.
//!
//! QUIC (UDP port 9334) is the sole entry point for remote communication.
//!
//! ## Discovery Protocols
//!
//! - **WiFi Direct**: P2P mesh with mDNS service discovery
//! - **Bluetooth LE**: Low-energy GATT for phone integration
//! - **Bluetooth Classic**: High-throughput RFCOMM for mobile devices

pub mod wifi;
pub mod bluetooth_le;
pub mod bluetooth_classic;

pub use wifi::WiFiRouter;
pub use bluetooth_le::BluetoothRouter;
pub use bluetooth_classic::{BluetoothClassicRouter, ClassicProtocol};
