use serde::{Deserialize, Serialize};
use anyhow::Result;
use async_trait::async_trait;
use crate::types::mesh_message::MeshMessageEnvelope;

// Bluetooth protocol suite (includes BLE mesh, Classic RFCOMM, platform-specific)
pub mod bluetooth;

// Other protocols
pub mod wifi_direct;
pub mod wifi_direct_handshake; // UHP handshake adapter for WiFi Direct
pub mod lorawan;
pub mod satellite;
pub mod zhtp_auth;
pub mod zhtp_encryption;
pub mod quic_mesh;           // QUIC transport with PQC encryption
pub mod quic_handshake;      // UHP handshake adapter for QUIC with Kyber binding
pub mod quic_api_dispatcher; // QUIC API request dispatcher for Web4 client


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

/// Protocol capabilities describing technical characteristics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolCapabilities {
    /// Maximum Transmission Unit in bytes
    pub mtu: u16,
    /// Estimated throughput in Mbps
    pub throughput_mbps: f64,
    /// Estimated latency in milliseconds
    pub latency_ms: u32,
    /// Effective range in meters (None for global protocols like satellite)
    pub range_meters: Option<u32>,
    /// Power consumption profile
    pub power_profile: PowerProfile,
    /// Whether the protocol supports reliable delivery
    pub reliable: bool,
    /// Whether the protocol requires internet connectivity
    pub requires_internet: bool,
}

/// Power consumption profile for protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PowerProfile {
    /// Ultra-low power (< 10mW average)
    UltraLow,
    /// Low power (10-100mW)
    Low,
    /// Medium power (100mW-1W)
    Medium,
    /// High power (1W-10W)
    High,
    /// Very high power (> 10W)
    VeryHigh,
}

/// Unified protocol trait for all mesh network transports
/// 
/// All protocols (BLE, WiFi Direct, LoRaWAN, QUIC, Satellite, Bluetooth Classic)
/// implement this trait to provide a consistent interface for message transmission.
/// 
/// # Example
/// ```no_run
/// use lib_network::protocols::{Protocol, ProtocolCapabilities};
/// use lib_network::types::mesh_message::MeshMessageEnvelope;
/// 
/// async fn send_via_protocol<P: Protocol>(
///     protocol: &P,
///     target: &str,
///     envelope: &MeshMessageEnvelope
/// ) -> anyhow::Result<()> {
///     let caps = protocol.capabilities();
///     println!("Sending via protocol with MTU: {}", caps.mtu);
///     protocol.send_message(target, envelope).await
/// }
/// ```
#[async_trait]
pub trait Protocol: Send + Sync {
    /// Send a mesh message to a specific peer
    /// 
    /// # Arguments
    /// * `target_address` - Protocol-specific peer identifier (MAC, IP, device ID, etc.)
    /// * `envelope` - The message envelope containing routing and payload data
    /// 
    /// # Returns
    /// * `Ok(())` if message was successfully transmitted (or queued for transmission)
    /// * `Err(...)` if transmission failed
    async fn send_message(
        &self,
        target_address: &str,
        envelope: &MeshMessageEnvelope,
    ) -> Result<()>;

    /// Get the protocol's technical capabilities
    /// 
    /// Returns characteristics like MTU, throughput, latency, range, and power consumption.
    fn capabilities(&self) -> ProtocolCapabilities;

    /// Get the protocol type identifier
    fn protocol_type(&self) -> NetworkProtocol;

    /// Check if the protocol is currently available/enabled
    /// 
    /// Returns `false` if hardware is unavailable, disabled, or in error state.
    fn is_available(&self) -> bool {
        true // Default implementation - protocols can override
    }
}
