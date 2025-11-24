//! Bluetooth Device Abstractions
//! 
//! Provides unified device information structures for both BLE and Classic Bluetooth

use serde::{Serialize, Deserialize};
use std::collections::HashMap;

/// Connection state for Bluetooth devices
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Connected,
    Disconnecting,
}

/// Common trait for all Bluetooth device types
pub trait BluetoothDeviceInfo {
    /// Get device address (may be ephemeral for BLE)
    fn address(&self) -> &str;
    
    /// Get device name if available
    fn name(&self) -> Option<&str>;
    
    /// Get RSSI (signal strength)
    fn rssi(&self) -> Option<i16>;
    
    /// Get list of advertised service UUIDs
    fn services(&self) -> &[String];
    
    /// Check if device is currently connected
    fn is_connected(&self) -> bool;
    
    /// Get last seen timestamp (Unix epoch seconds)
    fn last_seen(&self) -> u64;
}

/// BLE device with secure addressing (never exposes raw MAC)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BleDevice {
    /// Encrypted MAC address hash (one-way, cannot recover original)
    pub encrypted_mac_hash: [u8; 32],
    
    /// Secure node identifier derived from node_id + MAC
    pub secure_node_id: [u8; 32],
    
    /// Ephemeral discovery address (rotates every 15 minutes for privacy)
    pub ephemeral_address: String,
    
    /// Device name if advertised
    pub device_name: Option<String>,
    
    /// Advertised service UUIDs
    pub services: Vec<String>,
    
    /// GATT characteristics discovered
    pub characteristics: HashMap<String, CharacteristicInfo>,
    
    /// Connection handle (if connected)
    pub connection_handle: Option<u16>,
    
    /// Connection state
    pub connection_state: ConnectionState,
    
    /// Signal strength (RSSI)
    pub signal_strength: i16,
    
    /// Last seen timestamp (Unix epoch)
    pub last_seen: u64,
}

/// Classic Bluetooth device (paired/discoverable devices)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassicBluetoothDevice {
    /// Bluetooth address (MAC address for Classic BT)
    pub address: String,
    
    /// Device name
    pub name: Option<String>,
    
    /// Device class (indicates device type)
    pub device_class: u32,
    
    /// Whether device is paired
    pub is_paired: bool,
    
    /// Whether device is currently connected
    pub is_connected: bool,
    
    /// Signal strength (if available)
    pub rssi: Option<i16>,
    
    /// Last seen timestamp
    pub last_seen: u64,
}

/// GATT characteristic information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CharacteristicInfo {
    /// Characteristic UUID
    pub uuid: String,
    
    /// Handle for accessing the characteristic
    pub handle: u16,
    
    /// Properties (read, write, notify, indicate, etc.)
    pub properties: Vec<String>,
    
    /// Value handle for reading/writing
    pub value_handle: u16,
    
    /// D-Bus object path (Linux only)
    pub dbus_path: Option<String>,
}

/// Mesh peer information for P2P connections
#[derive(Debug, Clone)]
pub struct MeshPeer {
    pub peer_id: String,
    pub address: String,
    pub rssi: i16,
    pub last_seen: u64,
    pub mesh_capable: bool,
    pub services: Vec<String>,
    pub quantum_secure: bool,
}

/// BLE connection information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BleConnection {
    pub peer_id: String,
    pub connected_at: u64,
    pub mtu: u16,
    pub address: String,
    pub last_seen: u64,
    pub rssi: i16,
}

// Trait implementations

impl BluetoothDeviceInfo for BleDevice {
    fn address(&self) -> &str {
        &self.ephemeral_address
    }
    
    fn name(&self) -> Option<&str> {
        self.device_name.as_deref()
    }
    
    fn rssi(&self) -> Option<i16> {
        Some(self.signal_strength)
    }
    
    fn services(&self) -> &[String] {
        &self.services
    }
    
    fn is_connected(&self) -> bool {
        matches!(self.connection_state, ConnectionState::Connected)
    }
    
    fn last_seen(&self) -> u64 {
        self.last_seen
    }
}

impl BluetoothDeviceInfo for ClassicBluetoothDevice {
    fn address(&self) -> &str {
        &self.address
    }
    
    fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }
    
    fn rssi(&self) -> Option<i16> {
        self.rssi
    }
    
    fn services(&self) -> &[String] {
        &[] // Classic BT uses profiles, not UUIDs
    }
    
    fn is_connected(&self) -> bool {
        self.is_connected
    }
    
    fn last_seen(&self) -> u64 {
        self.last_seen
    }
}
