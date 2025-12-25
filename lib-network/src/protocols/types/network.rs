//! Network protocol enumeration

use serde::{Deserialize, Serialize};

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
