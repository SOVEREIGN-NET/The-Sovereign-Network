//! Maximum Transmission Unit (MTU) Constants
//! 
//! Centralized MTU constants for all network protocols to ensure consistent
//! message sizing across the mesh network.

/// Bluetooth Low Energy (BLE) MTU
/// 
/// BLE specification allows negotiable MTU up to 512 bytes, but 247 is a
/// safe default that works across all devices. The actual MTU can be negotiated
/// higher during connection establishment.
pub const BLE_MTU: u16 = 247;

/// Bluetooth Low Energy minimum MTU per spec
pub const BLE_MIN_MTU: u16 = 23;

/// Bluetooth Low Energy maximum MTU
pub const BLE_MAX_MTU: u16 = 512;

/// LoRaWAN maximum payload size
/// 
/// Conservative estimate for SF7/SF8 (Spreading Factor 7/8) which provides
/// good balance between range and data rate. Actual payload sizes:
/// - EU868: SF7=242, SF8=242, SF9=115, SF10=59, SF11=59, SF12=59
/// - US915: SF7=242, SF8=242, SF9=115, SF10=11
pub const LORA_MAX_PAYLOAD: usize = 242;

/// LoRaWAN fragment header size
pub const LORA_FRAGMENT_HEADER: usize = 8;

/// LoRaWAN effective chunk size (payload - header)
pub const LORA_CHUNK_SIZE: usize = LORA_MAX_PAYLOAD - LORA_FRAGMENT_HEADER;

/// WiFi Direct MTU
/// 
/// WiFi Direct uses TCP over P2P WiFi interface, typical Ethernet MTU is 1500,
/// minus TCP/IP headers (~40 bytes) gives us ~1460 bytes safe payload.
pub const WIFI_DIRECT_MTU: usize = 1460;

/// WiFi Direct chunk size for fragmentation
/// 
/// Slightly conservative to account for protocol overhead while still allowing
/// efficient transmission over WiFi Direct links.
pub const WIFI_DIRECT_CHUNK_SIZE: usize = 1400;

/// Bluetooth Classic RFCOMM MTU
/// 
/// RFCOMM over Bluetooth Classic typically supports much larger MTU than BLE.
/// Common values range from 672 to 1021 bytes.
pub const BT_CLASSIC_MTU: usize = 672;

/// Satellite link MTU
/// 
/// Satellite links often have smaller MTUs due to bandwidth constraints
/// and error correction overhead.
pub const SATELLITE_MTU: usize = 512;

/// QUIC protocol MTU
/// 
/// QUIC over UDP typically uses path MTU discovery, but we set a conservative
/// default that works well for most networks.
pub const QUIC_MTU: usize = 1280;

/// Get protocol-specific MTU
/// 
/// Returns the appropriate MTU for a given protocol type.
/// 
/// # Examples
/// 
/// ```
/// use lib_network::mtu::{get_protocol_mtu, ProtocolType};
/// 
/// let ble_mtu = get_protocol_mtu(ProtocolType::BluetoothLE);
/// assert_eq!(ble_mtu, 247);
/// ```
pub fn get_protocol_mtu(protocol: ProtocolType) -> usize {
    match protocol {
        ProtocolType::BluetoothLE => BLE_MTU as usize,
        ProtocolType::BluetoothClassic => BT_CLASSIC_MTU,
        ProtocolType::LoRaWAN => LORA_MAX_PAYLOAD,
        ProtocolType::WiFiDirect => WIFI_DIRECT_MTU,
        ProtocolType::Satellite => SATELLITE_MTU,
        ProtocolType::QUIC => QUIC_MTU,
    }
}

/// Get protocol-specific chunk size for fragmentation
/// 
/// Returns the optimal chunk size for fragmented transmission.
/// This accounts for protocol headers and overhead.
pub fn get_chunk_size(protocol: ProtocolType) -> usize {
    match protocol {
        ProtocolType::BluetoothLE => (BLE_MTU - 20) as usize, // Account for ATT overhead
        ProtocolType::BluetoothClassic => BT_CLASSIC_MTU - 32, // Account for RFCOMM overhead
        ProtocolType::LoRaWAN => LORA_CHUNK_SIZE,
        ProtocolType::WiFiDirect => WIFI_DIRECT_CHUNK_SIZE,
        ProtocolType::Satellite => SATELLITE_MTU - 64, // Extra overhead for error correction
        ProtocolType::QUIC => QUIC_MTU - 100, // Account for QUIC/UDP headers
    }
}

/// Protocol types for MTU lookup
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProtocolType {
    /// Bluetooth Low Energy (GATT)
    BluetoothLE,
    /// Bluetooth Classic (RFCOMM)
    BluetoothClassic,
    /// LoRaWAN long-range radio
    LoRaWAN,
    /// WiFi Direct P2P
    WiFiDirect,
    /// Satellite communications
    Satellite,
    /// QUIC over UDP
    QUIC,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ble_mtu_constants() {
        assert_eq!(BLE_MTU, 247);
        assert_eq!(BLE_MIN_MTU, 23);
        assert_eq!(BLE_MAX_MTU, 512);
        assert!(BLE_MTU >= BLE_MIN_MTU);
        assert!(BLE_MTU <= BLE_MAX_MTU);
    }

    #[test]
    fn test_lora_constants() {
        assert_eq!(LORA_MAX_PAYLOAD, 242);
        assert_eq!(LORA_FRAGMENT_HEADER, 8);
        assert_eq!(LORA_CHUNK_SIZE, 234); // 242 - 8
    }

    #[test]
    fn test_wifi_constants() {
        assert_eq!(WIFI_DIRECT_MTU, 1460);
        assert_eq!(WIFI_DIRECT_CHUNK_SIZE, 1400);
        assert!(WIFI_DIRECT_CHUNK_SIZE < WIFI_DIRECT_MTU);
    }

    #[test]
    fn test_get_protocol_mtu() {
        assert_eq!(get_protocol_mtu(ProtocolType::BluetoothLE), 247);
        assert_eq!(get_protocol_mtu(ProtocolType::LoRaWAN), 242);
        assert_eq!(get_protocol_mtu(ProtocolType::WiFiDirect), 1460);
    }

    #[test]
    fn test_get_chunk_size() {
        // Chunk sizes should always be less than MTU
        for protocol in [
            ProtocolType::BluetoothLE,
            ProtocolType::BluetoothClassic,
            ProtocolType::LoRaWAN,
            ProtocolType::WiFiDirect,
            ProtocolType::Satellite,
            ProtocolType::QUIC,
        ] {
            let chunk_size = get_chunk_size(protocol);
            let mtu = get_protocol_mtu(protocol);
            assert!(chunk_size < mtu, "Chunk size must be less than MTU for {:?}", protocol);
            assert!(chunk_size > 0, "Chunk size must be positive for {:?}", protocol);
        }
    }

    #[test]
    fn test_lora_chunk_calculation() {
        let chunk = get_chunk_size(ProtocolType::LoRaWAN);
        assert_eq!(chunk, LORA_CHUNK_SIZE);
        assert_eq!(chunk, 234); // 242 - 8 byte header
    }
}
