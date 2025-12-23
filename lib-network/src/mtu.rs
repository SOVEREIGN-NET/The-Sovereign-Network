//! MTU (Maximum Transmission Unit) Constants
//!
//! Centralized MTU values for all network protocols to ensure consistency
//! and prevent hardcoded values scattered across the codebase.
//!
//! ## Protocol-Specific MTU Values
//!
//! - **BLE (Bluetooth Low Energy)**: 512 bytes (max negotiated), 247 bytes (typical)
//! - **Bluetooth Classic (RFCOMM)**: 1000 bytes
//! - **LoRaWAN**: 242 bytes (SF7/SF8), lower for higher spreading factors
//! - **WiFi Direct**: 1400 bytes (safe UDP payload)
//! - **UDP**: 1400 bytes (avoids fragmentation on most networks)
//! - **QUIC**: 1200 bytes (conservative for initial packets)
//! - **Mesh**: 65536 bytes (internal routing, no wire limit)

use serde::{Deserialize, Serialize};

/// BLE minimum MTU (ATT protocol minimum)
pub const BLE_MIN_MTU: usize = 23;

/// BLE typical MTU (common negotiated value)
pub const BLE_TYPICAL_MTU: usize = 247;

/// BLE maximum MTU (maximum negotiated value)
pub const BLE_MAX_MTU: usize = 512;

/// BLE recommended chunk size for fragmentation (leaves room for headers)
pub const BLE_CHUNK_SIZE: usize = 200;

/// Bluetooth Classic (RFCOMM) MTU
pub const BLUETOOTH_CLASSIC_MTU: usize = 1000;

/// Bluetooth Classic recommended chunk size
pub const BLUETOOTH_CLASSIC_CHUNK_SIZE: usize = 1000;

/// LoRaWAN maximum payload size (SF7/SF8)
/// Note: Higher spreading factors have lower maximums:
/// - SF9: 115 bytes
/// - SF10: 51 bytes
/// - SF11: 11 bytes
/// - SF12: 11 bytes
pub const LORAWAN_MAX_PAYLOAD: usize = 242;

/// WiFi Direct MTU (safe UDP payload size)
pub const WIFI_DIRECT_MTU: usize = 1400;

/// WiFi Direct recommended chunk size
pub const WIFI_DIRECT_CHUNK_SIZE: usize = 1400;

/// UDP recommended MTU (avoids IP fragmentation on most networks)
pub const UDP_MTU: usize = 1400;

/// QUIC conservative MTU (for initial packets before path MTU discovery)
pub const QUIC_MTU: usize = 1200;

/// Internal mesh routing MTU (no wire constraint)
pub const MESH_MTU: usize = 65536;

/// Default chunk size for unknown protocols
pub const DEFAULT_CHUNK_SIZE: usize = 200;

/// Protocol identifier for MTU selection
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Protocol {
    BluetoothLE,
    BluetoothClassic,
    LoRaWAN,
    WiFiDirect,
    Udp,
    Quic,
    Mesh,
}

impl Protocol {
    /// Get the MTU for this protocol
    pub fn mtu(&self) -> usize {
        match self {
            Protocol::BluetoothLE => BLE_MAX_MTU,
            Protocol::BluetoothClassic => BLUETOOTH_CLASSIC_MTU,
            Protocol::LoRaWAN => LORAWAN_MAX_PAYLOAD,
            Protocol::WiFiDirect => WIFI_DIRECT_MTU,
            Protocol::Udp => UDP_MTU,
            Protocol::Quic => QUIC_MTU,
            Protocol::Mesh => MESH_MTU,
        }
    }

    /// Get the recommended chunk size for this protocol
    /// (MTU minus typical header overhead)
    pub fn chunk_size(&self) -> usize {
        match self {
            Protocol::BluetoothLE => BLE_CHUNK_SIZE,
            Protocol::BluetoothClassic => BLUETOOTH_CLASSIC_CHUNK_SIZE,
            Protocol::LoRaWAN => LORAWAN_MAX_PAYLOAD, // LoRa has no chunking, use full payload
            Protocol::WiFiDirect => WIFI_DIRECT_CHUNK_SIZE,
            Protocol::Udp => UDP_MTU,
            Protocol::Quic => QUIC_MTU,
            Protocol::Mesh => MESH_MTU,
        }
    }

    /// Get the MTU with a custom negotiated value (for BLE)
    pub fn negotiated_mtu(&self, negotiated: usize) -> usize {
        match self {
            Protocol::BluetoothLE => negotiated.min(BLE_MAX_MTU).max(BLE_MIN_MTU),
            _ => self.mtu(),
        }
    }

    /// Get chunk size for a negotiated MTU (leaves room for protocol headers)
    pub fn chunk_size_for_mtu(&self, mtu: usize) -> usize {
        match self {
            Protocol::BluetoothLE => {
                // Leave room for fragment header (8 bytes: msg_id + total + index + flags)
                mtu.saturating_sub(8).max(20)
            }
            Protocol::BluetoothClassic => {
                // Leave room for RFCOMM overhead
                mtu.saturating_sub(10).max(100)
            }
            Protocol::LoRaWAN => {
                // LoRa has fixed payload, no additional headers
                mtu
            }
            _ => {
                // General UDP/IP overhead
                mtu.saturating_sub(50).max(512)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_mtu() {
        assert_eq!(Protocol::BluetoothLE.mtu(), BLE_MAX_MTU);
        assert_eq!(Protocol::BluetoothClassic.mtu(), BLUETOOTH_CLASSIC_MTU);
        assert_eq!(Protocol::LoRaWAN.mtu(), LORAWAN_MAX_PAYLOAD);
        assert_eq!(Protocol::WiFiDirect.mtu(), WIFI_DIRECT_MTU);
    }

    #[test]
    fn test_negotiated_mtu() {
        // BLE MTU clamping
        assert_eq!(Protocol::BluetoothLE.negotiated_mtu(1000), BLE_MAX_MTU);
        assert_eq!(Protocol::BluetoothLE.negotiated_mtu(10), BLE_MIN_MTU);
        assert_eq!(Protocol::BluetoothLE.negotiated_mtu(247), 247);

        // Other protocols ignore negotiation
        assert_eq!(Protocol::Udp.negotiated_mtu(1000), UDP_MTU);
    }

    #[test]
    fn test_chunk_size_calculation() {
        // BLE chunk should leave room for headers
        assert!(Protocol::BluetoothLE.chunk_size_for_mtu(512) < 512);
        assert!(Protocol::BluetoothLE.chunk_size_for_mtu(512) >= 500);

        // LoRa uses full payload
        assert_eq!(
            Protocol::LoRaWAN.chunk_size_for_mtu(LORAWAN_MAX_PAYLOAD),
            LORAWAN_MAX_PAYLOAD
        );
    }

    #[test]
    fn test_constants() {
        // Sanity checks
        assert!(BLE_MIN_MTU < BLE_TYPICAL_MTU);
        assert!(BLE_TYPICAL_MTU < BLE_MAX_MTU);
        assert!(BLE_CHUNK_SIZE < BLE_TYPICAL_MTU);
        assert!(LORAWAN_MAX_PAYLOAD < UDP_MTU);
        assert!(QUIC_MTU < UDP_MTU);
    }
}
