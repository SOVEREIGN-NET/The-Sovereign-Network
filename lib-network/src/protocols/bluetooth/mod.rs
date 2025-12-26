//! Bluetooth Protocol Suite
//! 
//! Comprehensive Bluetooth implementation including:
//! - BLE mesh networking (main module)
//! - Bluetooth Classic RFCOMM (classic module)
//! - Platform-specific implementations (windows_gatt, macos_core)
//! - Common utilities (common, device, gatt modules)

// Core Bluetooth modules
pub mod common;
pub mod device;
pub mod gatt;

// Bluetooth Classic RFCOMM protocol
pub mod classic;

// Platform-specific implementations
#[cfg(target_os = "windows")]
pub mod windows_gatt;

#[cfg(target_os = "macos")]
pub mod macos_core;

#[cfg(target_os = "macos")]
pub mod macos_delegate;

#[cfg(target_os = "macos")]
pub mod macos_error;

#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(test)]
mod tests;

// Linux D-Bus BlueZ integration
#[cfg(all(target_os = "linux", feature = "linux-dbus"))]
pub mod dbus_bluez;

// Linux operations with D-Bus and CLI fallback
#[cfg(target_os = "linux")]
pub mod linux_ops;

// Enhanced Bluetooth features
#[cfg(feature = "enhanced-parsing")]
pub mod enhanced;

// GATT adapter with UHP framing (Issue #141)
pub mod gatt_adapter;
pub mod gatt_stream;
pub mod authentication;
pub mod events;
pub mod commands;
pub mod discovery;
pub mod messaging;
pub mod edge_sync;
pub mod monitoring;
pub mod parsing;
pub mod connectivity;
pub mod gatt_io;
pub mod handshake_io;
pub mod advertising;
pub mod gatt_backend;
pub mod platform_init;
pub mod handshake_send;
pub mod device_discovery;
pub mod identity;
pub mod core_bluetooth_init;
pub mod config;
pub mod capabilities;
pub mod lifecycle;
pub mod core;

// Mock BLE link for CI testing (Issue #141)
#[cfg(any(test, feature = "ble-mock"))]
pub mod mock;

// Main BLE Mesh Protocol Implementation
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use lib_crypto::PublicKey;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// Import ZHTP authentication
use crate::protocols::zhtp_auth::{ZhtpAuthManager, ZhtpAuthVerification};

// Import common Bluetooth utilities from submodules
use self::device::BleDevice;
use self::gatt::GattMessage;

// Import platform-specific managers
#[cfg(target_os = "macos")]
use self::macos_core::CoreBluetoothManager;

#[cfg(all(target_os = "linux", feature = "enhanced-parsing"))]
use self::enhanced::BlueZGattParser;

#[cfg(all(target_os = "macos", feature = "macos-corebluetooth"))]
use self::enhanced::MacOSBluetoothManager;

// Re-export public types
pub use self::gatt::GattMessage as GattMessageType;
pub use self::device::BleConnection as BluetoothConnection;

/// Untrusted BLE discovery envelope (does not confer identity).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshHandshake {
    pub version: u16,
    pub node_id: Uuid,
    pub public_key: PublicKey,
    pub mesh_port: u16,
    pub protocols: Vec<String>,
    pub discovered_via: u8,
    pub capabilities: crate::handshake::HandshakeCapabilities,
}

/// Bluetooth LE mesh protocol handler
pub struct BluetoothMeshProtocol {
    /// Node ID for this mesh node
    pub node_id: [u8; 32],
    /// Cryptographic public key for peer authentication
    pub public_key: lib_crypto::PublicKey,
    /// Bluetooth MAC address
    pub device_id: [u8; 6],
    /// Advertising interval in milliseconds
    pub advertising_interval: u16,
    /// Connection interval in milliseconds
    pub connection_interval: u16,
    /// Maximum number of connections
    pub max_connections: u8,
    /// Current active connections
    pub current_connections: Arc<RwLock<HashMap<String, BluetoothConnection>>>,
    /// Discovery active flag
    pub discovery_active: bool,
    /// Tracked devices for address resolution
    pub tracked_devices: Arc<RwLock<HashMap<String, BleDevice>>>,
    /// Address to device mapping
    pub address_mapping: Arc<RwLock<HashMap<String, String>>>,
    /// ZHTP transmission monitoring active flag
    pub zhtp_monitor_active: Arc<std::sync::atomic::AtomicBool>,
    /// ZHTP authentication manager
    pub auth_manager: Arc<RwLock<Option<ZhtpAuthManager>>>,
    /// Authenticated peers (address -> verification)
    pub authenticated_peers: Arc<RwLock<HashMap<String, ZhtpAuthVerification>>>,
    /// Windows GATT Service Provider (kept alive to maintain advertising)
    #[cfg(target_os = "windows")]
    pub gatt_service_provider: Arc<RwLock<Option<Box<dyn std::any::Any + Send + Sync>>>>,
    #[cfg(any(test, feature = "ble-mock"))]
    pub gatt_backend: Arc<RwLock<Option<std::sync::Arc<dyn gatt_backend::GattBackend>>>>,
    /// Windows BLE Advertiser with service UUID (for peer discovery)
    #[cfg(target_os = "windows")]
    pub ble_advertiser: Arc<RwLock<Option<Box<dyn std::any::Any + Send + Sync>>>>,
    /// Channel for forwarding GATT messages to unified server
    pub gatt_message_tx: Arc<RwLock<Option<tokio::sync::mpsc::UnboundedSender<GattMessage>>>>,
    /// Core Bluetooth manager for macOS (wrapped in Arc for event loop)
    #[cfg(target_os = "macos")]
    pub core_bluetooth: Arc<RwLock<Option<Arc<CoreBluetoothManager>>>>,
    /// Blockchain provider for serving headers/proofs to edge nodes
    pub blockchain_provider: Arc<RwLock<Option<Arc<dyn crate::blockchain_sync::BlockchainProvider>>>>,
    /// Fragment reassembler for large BLE messages
    pub fragment_reassembler: Arc<RwLock<gatt::FragmentReassembler>>,
}

impl std::fmt::Debug for BluetoothMeshProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BluetoothMeshProtocol")
            .field("node_id", &self.node_id)
            .field("public_key", &self.public_key)
            .field("device_id", &self.device_id)
            .field("advertising_interval", &self.advertising_interval)
            .field("connection_interval", &self.connection_interval)
            .field("max_connections", &self.max_connections)
            .field("current_connections", &"<connections>")
            .field("discovery_active", &self.discovery_active)
            .field("tracked_devices", &"<devices>")
            .field("address_mapping", &"<mapping>")
            .field("blockchain_provider", &"<provider>")
            .field("fragment_reassembler", &"<reassembler>")
            .finish()
    }
}

// Note: Old duplicate re-export removed - types are already available through the module structure
