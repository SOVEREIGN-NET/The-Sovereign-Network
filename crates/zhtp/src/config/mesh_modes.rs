//! Mesh Mode Configuration Management
//! 
//! Handles pure mesh vs hybrid mode settings and protocol selection

use serde::{Deserialize, Serialize};
use std::fmt;

/// Mesh networking operation modes
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MeshMode {
    /// Pure mesh mode - Complete  using only mesh protocols
    PureMesh,
    /// Hybrid mode - Mesh networking with TCP/IP fallback for transition
    Hybrid,
}

impl fmt::Display for MeshMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MeshMode::PureMesh => write!(f, "Pure Mesh (ISP-free)"),
            MeshMode::Hybrid => write!(f, "Hybrid (Mesh + TCP/IP)"),
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
                tcp_ip: false,        // No TCP/IP in pure mesh
                websockets: false,    // No WebSockets in pure mesh
                quic: false,          // No QUIC in pure mesh
            },
            MeshMode::Hybrid => ProtocolSelection {
                bluetooth_le: true,
                wifi_direct: true,
                lorawan: true,
                tcp_ip: true,         // TCP/IP available for fallback
                websockets: true,     // WebSockets for browser integration
                quic: true,           // QUIC for modern transport
            },
        }
    }
    
    /// Check if this mode requires long-range relays
    pub fn requires_long_range_relays(&self) -> bool {
        match self {
            MeshMode::PureMesh => true,  // Critical for global coverage without ISPs
            MeshMode::Hybrid => false,   // TCP/IP provides fallback connectivity
        }
    }
    
    /// Get bootstrap strategy for this mode
    pub fn get_bootstrap_strategy(&self) -> BootstrapStrategy {
        match self {
            MeshMode::PureMesh => BootstrapStrategy::MeshDiscovery,
            MeshMode::Hybrid => BootstrapStrategy::TcpAndMesh,
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
                
                // Check for TCP/IP protocols that shouldn't be present
                let has_tcp_ip = available_protocols.iter().any(|p| {
                    matches!(p.as_str(), "tcp" | "websocket" | "quic")
                });
                
                if has_tcp_ip {
                    return Err("Pure mesh mode cannot use TCP/IP protocols".to_string());
                }
            }
            MeshMode::Hybrid => {
                // Should have both mesh and TCP/IP capabilities
                let has_mesh = available_protocols.iter().any(|p| {
                    matches!(p.as_str(), "bluetooth" | "wifi_direct" | "lorawan")
                });
                
                let has_tcp_ip = available_protocols.iter().any(|p| {
                    matches!(p.as_str(), "tcp" | "websocket")
                });
                
                if !has_mesh {
                    tracing::warn!("Hybrid mode without mesh protocols - falling back to TCP/IP only");
                }
                
                if !has_tcp_ip {
                    tracing::warn!("Hybrid mode without TCP/IP protocols - operating as pure mesh");
                }
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
    /// Use both TCP bootstrap servers and mesh discovery
    TcpAndMesh,
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
            BootstrapStrategy::TcpAndMesh => vec![
                DiscoveryMethod::TcpBootstrap,
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
    TcpBootstrap,
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
