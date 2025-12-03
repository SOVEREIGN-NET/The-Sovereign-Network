//! Direct D-Bus integration with BlueZ stack
//!
//! This module provides direct D-Bus communication with the BlueZ Bluetooth stack,
//! replacing command-line tools for better performance and reliability.

#![cfg(all(target_os = "linux", feature = "linux-dbus"))]

use anyhow::{Result, anyhow};
use dbus::blocking::Connection;
use dbus::blocking::stdintf::org_freedesktop_dbus::Properties;
use dbus::arg::{RefArg, Variant};
use std::collections::HashMap;
use std::time::Duration;
use tracing::{info, warn, debug};

/// BlueZ D-Bus service name
const BLUEZ_SERVICE: &str = "org.bluez";

/// BlueZ D-Bus adapter interface
const ADAPTER_INTERFACE: &str = "org.bluez.Adapter1";

/// BlueZ D-Bus device interface
const DEVICE_INTERFACE: &str = "org.bluez.Device1";

/// BlueZ D-Bus GATT service interface
const GATT_SERVICE_INTERFACE: &str = "org.bluez.GattService1";

/// BlueZ D-Bus GATT characteristic interface
const GATT_CHARACTERISTIC_INTERFACE: &str = "org.bluez.GattCharacteristic1";

/// D-Bus properties interface
const PROPERTIES_INTERFACE: &str = "org.freedesktop.DBus.Properties";

/// BlueZ D-Bus client for direct communication
pub struct BlueZDBusClient {
    connection: Connection,
    adapter_path: String,
}

impl BlueZDBusClient {
    /// Create a new BlueZ D-Bus client
    pub fn new() -> Result<Self> {
        info!(" Initializing BlueZ D-Bus client");
        
        let connection = Connection::new_system()
            .map_err(|e| anyhow!("Failed to connect to system D-Bus: {}", e))?;
        
        // Default adapter path (usually hci0)
        let adapter_path = "/org/bluez/hci0".to_string();
        
        info!(" BlueZ D-Bus client initialized on {}", adapter_path);
        Ok(Self {
            connection,
            adapter_path,
        })
    }
    
    /// Start device discovery
    pub fn start_discovery(&self) -> Result<()> {
        info!(" Starting BlueZ device discovery via D-Bus");
        
        let proxy = self.connection.with_proxy(
            BLUEZ_SERVICE,
            &self.adapter_path,
            Duration::from_secs(5),
        );
        
        proxy.method_call(ADAPTER_INTERFACE, "StartDiscovery", ())
            .map_err(|e| anyhow!("Failed to start discovery: {}", e))?;
        
        info!(" Discovery started");
        Ok(())
    }
    
    /// Stop device discovery
    pub fn stop_discovery(&self) -> Result<()> {
        debug!("🛑 Stopping BlueZ device discovery");
        
        let proxy = self.connection.with_proxy(
            BLUEZ_SERVICE,
            &self.adapter_path,
            Duration::from_secs(5),
        );
        
        proxy.method_call(ADAPTER_INTERFACE, "StopDiscovery", ())
            .map_err(|e| anyhow!("Failed to stop discovery: {}", e))?;
        
        Ok(())
    }
    
    /// Get list of discovered devices
    pub fn get_devices(&self) -> Result<Vec<DeviceInfo>> {
        debug!(" Getting device list via D-Bus");
        
        let proxy = self.connection.with_proxy(
            BLUEZ_SERVICE,
            "/org/bluez",
            Duration::from_secs(5),
        );
        
        // Get managed objects (all BlueZ objects)
        let (objects,): (HashMap<dbus::Path, HashMap<String, HashMap<String, Variant<Box<dyn RefArg>>>>>,) = 
            proxy.method_call("org.freedesktop.DBus.ObjectManager", "GetManagedObjects", ())
                .map_err(|e| anyhow!("Failed to get managed objects: {}", e))?;
        
        let mut devices = Vec::new();
        
        for (path, interfaces) in objects {
            // Check if this object is a device
            if let Some(device_props) = interfaces.get(DEVICE_INTERFACE) {
                let address = device_props.get("Address")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                
                let name = device_props.get("Name")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                
                let rssi = device_props.get("RSSI")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(0) as i32;
                
                let connected = device_props.get("Connected")
                    .and_then(|v| v.as_i64())
                    .map(|v| v != 0)
                    .unwrap_or(false);
                
                if !address.is_empty() {
                    devices.push(DeviceInfo {
                        path: path.to_string(),
                        address,
                        name,
                        rssi,
                        connected,
                    });
                }
            }
        }
        
        debug!(" Found {} devices", devices.len());
        Ok(devices)
    }
    
    /// Connect to a device by address
    pub fn connect_device(&self, device_address: &str) -> Result<()> {
        info!(" Connecting to device {} via D-Bus", device_address);
        
        let device_path = self.get_device_path(device_address)?;
        
        let proxy = self.connection.with_proxy(
            BLUEZ_SERVICE,
            device_path,
            Duration::from_secs(30), // Longer timeout for connection
        );
        
        proxy.method_call(DEVICE_INTERFACE, "Connect", ())
            .map_err(|e| anyhow!("Failed to connect to device: {}", e))?;
        
        info!(" Connected to {}", device_address);
        Ok(())
    }
    
    /// Disconnect from a device
    pub fn disconnect_device(&self, device_address: &str) -> Result<()> {
        info!("🔌 Disconnecting from device {} via D-Bus", device_address);
        
        let device_path = self.get_device_path(device_address)?;
        
        let proxy = self.connection.with_proxy(
            BLUEZ_SERVICE,
            device_path,
            Duration::from_secs(10),
        );
        
        proxy.method_call(DEVICE_INTERFACE, "Disconnect", ())
            .map_err(|e| anyhow!("Failed to disconnect from device: {}", e))?;
        
        info!(" Disconnected from {}", device_address);
        Ok(())
    }
    
    /// Read GATT characteristic value
    pub fn read_gatt_characteristic(&self, device_address: &str, char_uuid: &str) -> Result<Vec<u8>> {
        debug!("📖 Reading GATT characteristic {} via D-Bus", char_uuid);
        
        let char_path = self.get_characteristic_path(device_address, char_uuid)?;
        
        let proxy = self.connection.with_proxy(
            BLUEZ_SERVICE,
            char_path,
            Duration::from_secs(10),
        );
        
        // Call ReadValue method with empty options
        let options: HashMap<String, Variant<Box<dyn RefArg>>> = HashMap::new();
        let (value,): (Vec<u8>,) = proxy.method_call(GATT_CHARACTERISTIC_INTERFACE, "ReadValue", (options,))
            .map_err(|e| anyhow!("Failed to read characteristic: {}", e))?;
        
        debug!("📖 Read {} bytes from characteristic {}", value.len(), char_uuid);
        Ok(value)
    }
    
    /// Write GATT characteristic value
    pub fn write_gatt_characteristic(&self, device_address: &str, char_uuid: &str, data: &[u8]) -> Result<()> {
        debug!("✍️ Writing {} bytes to GATT characteristic {} via D-Bus", data.len(), char_uuid);
        
        let char_path = self.get_characteristic_path(device_address, char_uuid)?;
        
        let proxy = self.connection.with_proxy(
            BLUEZ_SERVICE,
            char_path,
            Duration::from_secs(10),
        );
        
        // Call WriteValue method
        let options: HashMap<String, Variant<Box<dyn RefArg>>> = HashMap::new();
        proxy.method_call(GATT_CHARACTERISTIC_INTERFACE, "WriteValue", (data.to_vec(), options))
            .map_err(|e| anyhow!("Failed to write characteristic: {}", e))?;
        
        debug!(" Wrote {} bytes to characteristic {}", data.len(), char_uuid);
        Ok(())
    }
    
    /// Enable notifications on a characteristic
    pub fn enable_notifications(&self, device_address: &str, char_uuid: &str) -> Result<()> {
        info!(" Enabling notifications for characteristic {} via D-Bus", char_uuid);
        
        let char_path = self.get_characteristic_path(device_address, char_uuid)?;
        
        let proxy = self.connection.with_proxy(
            BLUEZ_SERVICE,
            char_path,
            Duration::from_secs(10),
        );
        
        proxy.method_call(GATT_CHARACTERISTIC_INTERFACE, "StartNotify", ())
            .map_err(|e| anyhow!("Failed to enable notifications: {}", e))?;
        
        info!(" Notifications enabled for {}", char_uuid);
        Ok(())
    }
    
    /// Disable notifications on a characteristic
    pub fn disable_notifications(&self, device_address: &str, char_uuid: &str) -> Result<()> {
        debug!("🔕 Disabling notifications for characteristic {}", char_uuid);
        
        let char_path = self.get_characteristic_path(device_address, char_uuid)?;
        
        let proxy = self.connection.with_proxy(
            BLUEZ_SERVICE,
            char_path,
            Duration::from_secs(10),
        );
        
        proxy.method_call(GATT_CHARACTERISTIC_INTERFACE, "StopNotify", ())
            .map_err(|e| anyhow!("Failed to disable notifications: {}", e))?;
        
        Ok(())
    }
    
    /// Get device path from MAC address
    fn get_device_path(&self, device_address: &str) -> Result<String> {
        // Convert MAC address to BlueZ device path format
        // Example: "AA:BB:CC:DD:EE:FF" -> "/org/bluez/hci0/dev_AA_BB_CC_DD_EE_FF"
        let normalized = device_address.replace(':', "_");
        Ok(format!("{}/dev_{}", self.adapter_path, normalized))
    }
    
    /// Get characteristic path (simplified - in production, would enumerate services)
    fn get_characteristic_path(&self, device_address: &str, char_uuid: &str) -> Result<String> {
        let device_path = self.get_device_path(device_address)?;
        
        // In production, we'd enumerate GATT services and characteristics
        // For now, construct a typical path
        // Example: "/org/bluez/hci0/dev_XX_XX_XX_XX_XX_XX/service0001/char0003"
        
        // This is a simplified version - real implementation would use GetManagedObjects
        // to find the actual characteristic path
        
        warn!(" Using simplified characteristic path resolution - production code should enumerate services");
        
        // Return a generic path that needs to be resolved
        Ok(format!("{}/service0001/char0001", device_path))
    }
    
    /// Get adapter MAC address
    pub fn get_adapter_address(&self) -> Result<String> {
        let proxy = self.connection.with_proxy(
            BLUEZ_SERVICE,
            &self.adapter_path,
            Duration::from_secs(5),
        );
        
        let address: String = proxy.get(ADAPTER_INTERFACE, "Address")
            .map_err(|e| anyhow!("Failed to get adapter address: {}", e))?;
        
        Ok(address)
    }
    
    /// Check if adapter is powered on
    pub fn is_powered(&self) -> Result<bool> {
        let proxy = self.connection.with_proxy(
            BLUEZ_SERVICE,
            &self.adapter_path,
            Duration::from_secs(5),
        );
        
        let powered: bool = proxy.get(ADAPTER_INTERFACE, "Powered")
            .map_err(|e| anyhow!("Failed to get adapter power state: {}", e))?;
        
        Ok(powered)
    }
    
    /// Power on the adapter
    pub fn power_on(&self) -> Result<()> {
        info!("⚡ Powering on Bluetooth adapter via D-Bus");
        
        let proxy = self.connection.with_proxy(
            BLUEZ_SERVICE,
            &self.adapter_path,
            Duration::from_secs(5),
        );
        
        proxy.set(ADAPTER_INTERFACE, "Powered", true)
            .map_err(|e| anyhow!("Failed to power on adapter: {}", e))?;
        
        info!(" Adapter powered on");
        Ok(())
    }
}

/// Device information from BlueZ
#[derive(Debug, Clone)]
pub struct DeviceInfo {
    pub path: String,
    pub address: String,
    pub name: Option<String>,
    pub rssi: i32,
    pub connected: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_device_path_conversion() {
        let client = BlueZDBusClient {
            connection: Connection::new_system().unwrap(),
            adapter_path: "/org/bluez/hci0".to_string(),
        };
        
        let path = client.get_device_path("AA:BB:CC:DD:EE:FF").unwrap();
        assert_eq!(path, "/org/bluez/hci0/dev_AA_BB_CC_DD_EE_FF");
    }
}
