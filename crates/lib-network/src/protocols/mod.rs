use serde::{Deserialize, Serialize};

// Bluetooth protocol suite (includes BLE mesh, Classic RFCOMM, platform-specific)
pub mod bluetooth;

// Other protocols
pub mod wifi_direct;
pub mod lorawan;
pub mod satellite;
pub mod zhtp_auth;
pub mod zhtp_encryption;
pub mod quic_mesh;  // QUIC transport with PQC encryption


// Enhanced protocol implementations with platform-specific optimizations
// NOTE: enhanced_bluetooth functionality is in bluetooth/enhanced.rs, not a separate top-level module
// #[cfg(feature = "enhanced-bluetooth")]
// pub mod enhanced_bluetooth;

#[cfg(feature = "enhanced-wifi-direct")]
pub mod enhanced_wifi_direct;

/// Network protocol enumeration
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NetworkProtocol {
    /// Bluetooth Low Energy for device-to-device communication
    BluetoothLE,
    /// Bluetooth Classic (BR/EDR) for high-throughput mesh
    BluetoothClassic,
    /// WiFi Direct for medium-range peer connections
    WiFiDirect,
    /// LoRaWAN for long-range low-power communication
    LoRaWAN,
    /// Satellite for global coverage
    Satellite,
    /// TCP for internet bridging
    TCP,
    /// UDP for mesh networking
    UDP,
    /// QUIC for modern mesh transport (replaces TCP/UDP split)
    QUIC,
}
