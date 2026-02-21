//! Mesh Mode Configuration Management
//!
//! Defines mesh networking operation modes.
//!
//! ⚠️ NOTE: Only PureMesh (QUIC-only) is currently supported.
//! TCP/IP hybrid mode is no longer available - the system is fully QUIC-based.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Mesh networking operation modes
///
/// ⚠️ QUIC-ONLY: Only PureMesh is supported. TCP/IP and hybrid modes are deprecated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MeshMode {
    /// Pure mesh mode - QUIC-only with local mesh protocols
    PureMesh,
    /// ⚠️ DEPRECATED: Hybrid mode is no longer supported (TCP/IP removed)
    #[deprecated(note = "QUIC is the only transport - hybrid TCP/IP mode is not supported")]
    Hybrid,
}

impl fmt::Display for MeshMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MeshMode::PureMesh => write!(f, "Pure Mesh (QUIC-only, ISP-free)"),
            #[allow(deprecated)]
            MeshMode::Hybrid => write!(f, "Hybrid (deprecated - use Pure Mesh)"),
        }
    }
}

impl Default for MeshMode {
    fn default() -> Self {
        MeshMode::PureMesh // Default to pure mesh for local-only operation
    }
}

/// Protocol selection for different mesh modes
#[derive(Debug, Clone)]
pub struct ProtocolSelection {
    pub bluetooth_le: bool,
    pub wifi_direct: bool,
    pub lorawan: bool,
    pub tcp_ip: bool,
    pub websockets: bool,
    pub quic: bool,
}

impl MeshMode {
    /// Get appropriate protocol selection for this mode
    pub fn get_protocol_selection(&self) -> ProtocolSelection {
        match self {
            MeshMode::PureMesh => ProtocolSelection {
                bluetooth_le: true,
                wifi_direct: true,
                lorawan: true,
                tcp_ip: false,        // No TCP/IP - QUIC-only
                websockets: false,    // No WebSockets
                quic: true,           // QUIC is required and primary transport
            },
            #[allow(deprecated)]
            MeshMode::Hybrid => {
                // Hybrid mode is deprecated - treat as PureMesh (QUIC-only)
                ProtocolSelection {
                    bluetooth_le: true,
                    wifi_direct: true,
                    lorawan: true,
                    tcp_ip: false,
                    websockets: false,
                    quic: true,
                }
            }
        }
    }
    
    /// Check if this mode requires long-range relays
    pub fn requires_long_range_relays(&self) -> bool {
        match self {
            MeshMode::PureMesh => true,  // Critical for global coverage without ISPs
            #[allow(deprecated)]
            MeshMode::Hybrid => true,     // Hybrid is deprecated - treat as mesh-only
        }
    }

    /// Get bootstrap strategy for this mode
    pub fn get_bootstrap_strategy(&self) -> BootstrapStrategy {
        match self {
            MeshMode::PureMesh => BootstrapStrategy::MeshDiscovery,
            #[allow(deprecated)]
            MeshMode::Hybrid => BootstrapStrategy::MeshDiscovery, // Hybrid is deprecated - use mesh discovery
        }
    }
    
    /// Validate that required capabilities are available for this mode
    pub fn validate_capabilities(&self, available_protocols: &[String]) -> Result<(), String> {
        let _required = self.get_protocol_selection();

        match self {
            MeshMode::PureMesh => {
                // Must have at least one mesh protocol
                let has_mesh_protocol = available_protocols.iter().any(|p| {
                    matches!(p.as_str(), "bluetooth" | "wifi_direct" | "lorawan")
                });

                if !has_mesh_protocol {
                    return Err("Pure mesh mode requires at least one mesh protocol (Bluetooth, WiFi Direct, or LoRaWAN)".to_string());
                }

                // QUIC is required in all modes
                let has_quic = available_protocols.iter().any(|p| {
                    matches!(p.as_str(), "quic")
                });

                if !has_quic {
                    return Err("QUIC is required for all mesh modes".to_string());
                }
            }
            #[allow(deprecated)]
            MeshMode::Hybrid => {
                // Hybrid mode is deprecated - validate as PureMesh instead
                return Self::PureMesh.validate_capabilities(available_protocols);
            }
        }

        Ok(())
    }
}

/// Bootstrap discovery strategy
#[derive(Debug, Clone)]
pub enum BootstrapStrategy {
    /// Discover peers through mesh protocols only
    MeshDiscovery,
    /// Use QUIC bootstrap peers plus mesh discovery
    QuicAndMesh,
}

impl BootstrapStrategy {
    /// Get bootstrap peer discovery methods
    pub fn get_discovery_methods(&self) -> Vec<DiscoveryMethod> {
        match self {
            BootstrapStrategy::MeshDiscovery => vec![
                DiscoveryMethod::BluetoothScan,
                DiscoveryMethod::WiFiDirectScan,
                DiscoveryMethod::LoRaWANScan,
                DiscoveryMethod::SatelliteUplink,
            ],
            BootstrapStrategy::QuicAndMesh => vec![
                DiscoveryMethod::QuicBootstrap,
                DiscoveryMethod::BluetoothScan,
                DiscoveryMethod::WiFiDirectScan,
                DiscoveryMethod::DnsDiscovery,
            ],
        }
    }
}

/// Peer discovery methods
#[derive(Debug, Clone)]
pub enum DiscoveryMethod {
    QuicBootstrap,
    BluetoothScan,
    WiFiDirectScan,
    LoRaWANScan,
    SatelliteUplink,
    DnsDiscovery,
}

/// Configuration for  functionality
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IspBypassConfig {
    pub enabled: bool,
    pub prefer_mesh_routes: bool,
    pub fallback_to_internet: bool,
    pub long_range_relay_timeout_ms: u64,
    pub mesh_route_priority: u8, // 0-255, higher = more preferred
}

impl Default for IspBypassConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            prefer_mesh_routes: true,
            fallback_to_internet: false, // Pure mesh mode - no internet fallback
            long_range_relay_timeout_ms: 10000,
            mesh_route_priority: 255, // Maximum preference for mesh routes
        }
    }
}

impl IspBypassConfig {
    /// Validate configuration for the given mesh mode
    pub fn validate_for_mode(&self, mode: &MeshMode) -> Result<(), String> {
        match mode {
            MeshMode::PureMesh => {
                if self.fallback_to_internet {
                    return Err("Internet fallback not allowed in pure mesh mode".to_string());
                }
                if !self.enabled {
                    return Err(" must be enabled in pure mesh mode".to_string());
                }
            }
            MeshMode::Hybrid => {
                // All settings are valid in hybrid mode
            }
        }
        Ok(())
    }
}
