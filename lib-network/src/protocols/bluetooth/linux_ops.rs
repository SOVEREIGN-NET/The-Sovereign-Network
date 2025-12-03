//! Linux Bluetooth operations with D-Bus and CLI fallback
//!
//! This module provides unified Linux Bluetooth operations that prefer D-Bus
//! but fall back to command-line tools when D-Bus is unavailable.

#![cfg(target_os = "linux")]

use anyhow::{Result, anyhow};
use tracing::{info, warn, debug};
use crate::protocols::bluetooth::device::MeshPeer;

#[cfg(feature = "linux-dbus")]
use crate::protocols::bluetooth::dbus_bluez::{BlueZDBusClient, DeviceInfo};

/// Linux Bluetooth operation handler
pub struct LinuxBluetoothOps {
    #[cfg(feature = "linux-dbus")]
    dbus_client: Option<BlueZDBusClient>,
}

impl LinuxBluetoothOps {
    /// Create new Linux Bluetooth operations handler
    pub fn new() -> Self {
        #[cfg(feature = "linux-dbus")]
        {
            info!(" Initializing Linux Bluetooth with D-Bus support");
            let dbus_client = match BlueZDBusClient::new() {
                Ok(client) => {
                    info!(" D-Bus BlueZ client initialized");
                    Some(client)
                }
                Err(e) => {
                    warn!(" Failed to initialize D-Bus client: {}", e);
                    warn!("   Falling back to CLI tools (bluetoothctl, hcitool)");
                    None
                }
            };
            
            Self { dbus_client }
        }
        
        #[cfg(not(feature = "linux-dbus"))]
        {
            info!(" Using CLI-only Bluetooth (no D-Bus support compiled in)");
            Self {}
        }
    }
    
    /// Start device discovery
    pub async fn start_discovery(&self) -> Result<()> {
        #[cfg(feature = "linux-dbus")]
        if let Some(ref client) = self.dbus_client {
            return client.start_discovery();
        }
        
        // Fallback: CLI-based discovery
        self.cli_start_discovery().await
    }
    
    /// Stop device discovery
    pub async fn stop_discovery(&self) -> Result<()> {
        #[cfg(feature = "linux-dbus")]
        if let Some(ref client) = self.dbus_client {
            return client.stop_discovery();
        }
        
        // Fallback: CLI stop (no-op, discovery times out naturally)
        Ok(())
    }
    
    /// Scan for ZHTP mesh peers
    pub async fn scan_mesh_peers(&self) -> Result<Vec<MeshPeer>> {
        #[cfg(feature = "linux-dbus")]
        if let Some(ref client) = self.dbus_client {
            return self.dbus_scan_mesh_peers(client).await;
        }
        
        // Fallback: CLI-based scanning
        self.cli_scan_mesh_peers().await
    }
    
    /// Connect to a device
    pub async fn connect_device(&self, address: &str) -> Result<()> {
        #[cfg(feature = "linux-dbus")]
        if let Some(ref client) = self.dbus_client {
            return client.connect_device(address);
        }
        
        // Fallback: CLI connection
        self.cli_connect_device(address).await
    }
    
    /// Disconnect from a device
    pub async fn disconnect_device(&self, address: &str) -> Result<()> {
        #[cfg(feature = "linux-dbus")]
        if let Some(ref client) = self.dbus_client {
            return client.disconnect_device(address);
        }
        
        // Fallback: CLI disconnection
        self.cli_disconnect_device(address).await
    }
    
    /// Read GATT characteristic
    pub async fn read_gatt_characteristic(&self, device_address: &str, char_uuid: &str) -> Result<Vec<u8>> {
        #[cfg(feature = "linux-dbus")]
        if let Some(ref client) = self.dbus_client {
            return client.read_gatt_characteristic(device_address, char_uuid);
        }
        
        // Fallback: CLI GATT read
        self.cli_read_gatt_characteristic(device_address, char_uuid).await
    }
    
    /// Write GATT characteristic
    pub async fn write_gatt_characteristic(&self, device_address: &str, char_uuid: &str, data: &[u8]) -> Result<()> {
        #[cfg(feature = "linux-dbus")]
        if let Some(ref client) = self.dbus_client {
            return client.write_gatt_characteristic(device_address, char_uuid, data);
        }
        
        // Fallback: CLI GATT write
        self.cli_write_gatt_characteristic(device_address, char_uuid, data).await
    }
    
    /// Enable notifications on a characteristic
    pub async fn enable_notifications(&self, device_address: &str, char_uuid: &str) -> Result<()> {
        #[cfg(feature = "linux-dbus")]
        if let Some(ref client) = self.dbus_client {
            return client.enable_notifications(device_address, char_uuid);
        }
        
        // Fallback: CLI notifications (limited support)
        warn!(" GATT notifications not supported via CLI tools");
        Ok(())
    }
    
    // ========== D-Bus Implementation ==========
    
    #[cfg(feature = "linux-dbus")]
    async fn dbus_scan_mesh_peers(&self, client: &BlueZDBusClient) -> Result<Vec<MeshPeer>> {
        info!(" Scanning for ZHTP mesh peers via D-Bus");
        
        client.start_discovery()?;
        
        // Wait for discovery
        tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
        
        let devices = client.get_devices()?;
        client.stop_discovery()?;
        
        let mut peers = Vec::new();
        
        for device in devices {
            // Check if device name contains ZHTP or SOVNET
            if let Some(ref name) = device.name {
                if name.contains("ZHTP") || name.contains("SOVNET") {
                    let peer = MeshPeer {
                        peer_id: device.address.clone(),
                        address: device.address.clone(),
                        rssi: device.rssi as i16,
                        last_seen: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs(),
                        mesh_capable: true,
                        services: vec!["ZHTP-MESH".to_string()],
                        quantum_secure: true,
                    };
                    info!(" Found ZHTP mesh peer: {} ({})", peer.peer_id, device.address);
                    peers.push(peer);
                }
            }
        }
        
        info!(" Found {} ZHTP mesh peers via D-Bus", peers.len());
        Ok(peers)
    }
    
    // ========== CLI Fallback Implementation ==========
    
    async fn cli_start_discovery(&self) -> Result<()> {
        use std::process::Command;
        
        debug!(" Starting discovery via bluetoothctl");
        
        let _ = Command::new("bluetoothctl")
            .args(&["scan", "on"])
            .spawn();
        
        Ok(())
    }
    
    async fn cli_scan_mesh_peers(&self) -> Result<Vec<MeshPeer>> {
        use std::process::Command;
        
        info!(" Scanning for ZHTP mesh peers via CLI tools");
        
        // Start BLE scan
        let scan_output = Command::new("timeout")
            .args(&["10s", "hcitool", "lescan"])
            .output();
        
        let mut peers = Vec::new();
        
        if let Ok(result) = scan_output {
            let output = String::from_utf8_lossy(&result.stdout);
            for line in output.lines() {
                if let Some(peer) = Self::parse_hcitool_peer(line) {
                    peers.push(peer);
                }
            }
        }
        
        // Also scan using bluetoothctl for services
        let bt_scan = Command::new("timeout")
            .args(&["10s", "bluetoothctl", "scan", "on"])
            .output();
        
        if let Ok(bt_result) = bt_scan {
            let bt_output = String::from_utf8_lossy(&bt_result.stdout);
            for line in bt_output.lines() {
                if let Some(peer) = Self::parse_bluetoothctl_peer(line) {
                    peers.push(peer);
                }
            }
        }
        
        info!(" Found {} ZHTP mesh peers via CLI", peers.len());
        Ok(peers)
    }
    
    async fn cli_connect_device(&self, address: &str) -> Result<()> {
        use std::process::Command;
        
        info!(" Connecting to device {} via bluetoothctl", address);
        
        let connect_output = Command::new("bluetoothctl")
            .args(&["connect", address])
            .output()?;
        
        let output = String::from_utf8_lossy(&connect_output.stdout);
        if output.contains("Connection successful") {
            info!(" Connected to {}", address);
            Ok(())
        } else {
            Err(anyhow!("Failed to connect: {}", output))
        }
    }
    
    async fn cli_disconnect_device(&self, address: &str) -> Result<()> {
        use std::process::Command;
        
        debug!(" Disconnecting from device {} via bluetoothctl", address);
        
        let _ = Command::new("bluetoothctl")
            .args(&["disconnect", address])
            .output()?;
        
        Ok(())
    }
    
    async fn cli_read_gatt_characteristic(&self, device_address: &str, char_uuid: &str) -> Result<Vec<u8>> {
        use std::process::Command;
        
        debug!(" Reading GATT characteristic {} via gatttool", char_uuid);
        
        // Note: gatttool requires handle, not UUID - this is a limitation
        warn!(" gatttool requires characteristic handle, not UUID");
        warn!("   Production systems should use D-Bus for proper GATT operations");
        
        Err(anyhow!("GATT read via CLI requires characteristic handle"))
    }
    
    async fn cli_write_gatt_characteristic(&self, device_address: &str, char_uuid: &str, data: &[u8]) -> Result<()> {
        use std::process::Command;
        
        debug!(" Writing GATT characteristic {} via gatttool", char_uuid);
        
        // Note: gatttool requires handle, not UUID - this is a limitation
        warn!(" gatttool requires characteristic handle, not UUID");
        warn!("   Production systems should use D-Bus for proper GATT operations");
        
        Err(anyhow!("GATT write via CLI requires characteristic handle"))
    }
    
    // ========== Parsing Helpers ==========
    
    fn parse_hcitool_peer(line: &str) -> Option<MeshPeer> {
        // Parse hcitool lescan output: "AA:BB:CC:DD:EE:FF ZHTP-BYPASS"
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 && parts[0].len() == 17 && parts[1].contains("ZHTP") {
            Some(MeshPeer {
                peer_id: parts[0].to_string(),
                address: parts[0].to_string(),
                rssi: -60, // Default RSSI
                last_seen: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                mesh_capable: true,
                services: vec!["ZHTP-MESH".to_string()],
                quantum_secure: true,
            })
        } else {
            None
        }
    }
    
    fn parse_bluetoothctl_peer(line: &str) -> Option<MeshPeer> {
        // Parse bluetoothctl format: "[CHG] Device AA:BB:CC:DD:EE:FF Name: ZHTP-BYPASS"
        if let Some(device_start) = line.find("Device ") {
            let device_part = &line[device_start + 7..];
            if let Some(space_pos) = device_part.find(' ') {
                let address = &device_part[..space_pos];
                if address.len() == 17 && line.contains("ZHTP") {
                    return Some(MeshPeer {
                        peer_id: address.to_string(),
                        address: address.to_string(),
                        rssi: -55,
                        last_seen: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs(),
                        mesh_capable: true,
                        services: vec!["ZHTP-MESH".to_string()],
                        quantum_secure: true,
                    });
                }
            }
        }
        None
    }
}

impl Default for LinuxBluetoothOps {
    fn default() -> Self {
        Self::new()
    }
}
