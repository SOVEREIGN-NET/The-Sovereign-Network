//! Hardware detection utilities
//!
//! Cross-platform hardware detection for mesh networking protocols

use anyhow::Result;
use tracing::{info, debug};
use std::collections::HashMap;
use std::sync::OnceLock;
use super::lorawan_hardware::LoRaWANHardware;

/// Global cache for hardware capabilities (detected once at startup)
static HARDWARE_CACHE: OnceLock<HardwareCapabilities> = OnceLock::new();

/// Hardware capabilities detected on the system
#[derive(Debug, Clone, Default)]
pub struct HardwareCapabilities {
    /// LoRaWAN radio hardware available (supports multiple radios)
    pub lorawan_radios: Vec<LoRaWANHardware>,
    /// Bluetooth LE hardware available
    pub bluetooth_available: bool,
    /// WiFi Direct hardware available
    pub wifi_direct_available: bool,
    /// Detected hardware details
    pub hardware_details: HashMap<String, HardwareDevice>,
}

/// Information about a detected hardware device
#[derive(Debug, Clone)]
pub struct HardwareDevice {
    /// Device name/identifier
    pub name: String,
    /// Device type (USB, SPI, I2C, etc.)
    pub device_type: String,
    /// Vendor/product information
    pub vendor_info: Option<String>,
    /// Device path or address
    pub device_path: Option<String>,
    /// Additional properties
    pub properties: HashMap<String, String>,
}

impl HardwareCapabilities {
    /// Detect all available hardware capabilities (cached after first call)
    ///
    /// Hardware detection is expensive and results don't change at runtime,
    /// so we cache the result after the first detection.
    pub async fn detect() -> Result<Self> {
        // Return cached result if already detected
        if let Some(cached) = HARDWARE_CACHE.get() {
            debug!("Using cached hardware capabilities (no hardware re-detection needed)");
            return Ok(cached.clone());
        }

        info!("Detecting available mesh networking hardware...");

        let mut capabilities = Self::default();

        // Detect LoRaWAN hardware
        capabilities.detect_lorawan().await?;

        // Detect Bluetooth hardware
        capabilities.bluetooth_available = detect_bluetooth_hardware(&mut capabilities.hardware_details).await;

        // Detect WiFi Direct hardware
        capabilities.wifi_direct_available = detect_wifi_direct_hardware(&mut capabilities.hardware_details).await;

        info!("Hardware detection completed:");
        info!("   LoRaWAN: {}", if capabilities.lorawan_available() { "Available" } else { "Not detected" });
        info!("    Bluetooth LE: {}", if capabilities.bluetooth_available { "Available" } else { "Not detected" });
        info!("   WiFi Direct: {}", if capabilities.wifi_direct_available { "Available" } else { "Not detected" });

        // Cache the result for future calls
        let _ = HARDWARE_CACHE.set(capabilities.clone());

        Ok(capabilities)
    }
    
    /// Get enabled protocols based on hardware availability
    pub fn get_enabled_protocols(&self) -> Vec<String> {
        let mut protocols = Vec::new();
        
        if self.bluetooth_available {
            protocols.push("Bluetooth LE".to_string());
        }
        
        if self.wifi_direct_available {
            protocols.push("WiFi Direct".to_string());
        }
        
        if self.lorawan_available() {
            protocols.push("LoRaWAN".to_string());
        }
        
        protocols
    }
    
    /// Check if any mesh protocols are available
    pub fn has_mesh_capabilities(&self) -> bool {
        self.bluetooth_available || self.wifi_direct_available || self.lorawan_available()
    }

    /// Check if any LoRaWAN hardware is available (backward compatibility)
    pub fn lorawan_available(&self) -> bool {
        !self.lorawan_radios.is_empty()
    }
    
    /// Get the primary LoRaWAN radio (first available)
    pub fn primary_lorawan(&self) -> Option<&LoRaWANHardware> {
        self.lorawan_radios.first()
    }
    
    /// Get LoRaWAN radios supporting a specific frequency band
    pub fn lorawan_radios_for_band(&self, band: &super::lorawan_hardware::FrequencyBand) -> Vec<&LoRaWANHardware> {
        self.lorawan_radios
            .iter()
            .filter(|radio| radio.frequency_bands.contains(band))
            .collect()
    }

    async fn detect_lorawan(&mut self) -> Result<()> {
        // Use the dedicated lorawan_hardware detection to get all radios
        match super::lorawan_hardware::detect_lorawan_hardware().await {
            Ok(radios) => {
                self.lorawan_radios = radios;
                
                // Update hardware_details for each radio
                for (index, radio) in self.lorawan_radios.iter().enumerate() {
                    let device_id = format!("lorawan_{}", index);
                    let device = HardwareDevice {
                        name: radio.device_name.clone(),
                        device_type: "LoRaWAN Radio".to_string(),
                        vendor_info: Some(format!("Bands: {:?}, Max Power: {}dBm", 
                            radio.frequency_bands, radio.max_tx_power)),
                        device_path: radio.device_path.clone(),
                        properties: {
                            let mut props = HashMap::new();
                            props.insert("connection_type".to_string(), radio.connection_type.clone());
                            props.insert("max_tx_power".to_string(), radio.max_tx_power.to_string());
                            props.insert("class_a".to_string(), radio.capabilities.class_a.to_string());
                            props.insert("class_b".to_string(), radio.capabilities.class_b.to_string());
                            props.insert("class_c".to_string(), radio.capabilities.class_c.to_string());
                            props.insert("otaa_support".to_string(), radio.capabilities.otaa_support.to_string());
                            props.insert("max_payload_size".to_string(), radio.capabilities.max_payload_size.to_string());
                            props
                        },
                    };
                    self.hardware_details.insert(device_id, device);
                }
                
                if !self.lorawan_radios.is_empty() {
                    info!("Detected {} LoRaWAN radio(s)", self.lorawan_radios.len());
                    for (i, radio) in self.lorawan_radios.iter().enumerate() {
                        debug!("Radio {}: {} on {} (Bands: {:?})", 
                            i, radio.device_name, radio.connection_type, radio.frequency_bands);
                    }
                } else {
                    debug!("No LoRaWAN hardware detected");
                }
            }
            Err(e) => {
                debug!("Failed to detect LoRaWAN hardware: {}", e);
            }
        }
        Ok(())
    }
}

/// Detect Bluetooth LE hardware capabilities
async fn detect_bluetooth_hardware(hardware_details: &mut HashMap<String, HardwareDevice>) -> bool {
    #[cfg(target_os = "linux")]
    {
        use std::process::Command;
        
        // Check if bluetoothctl is available and bluetooth is enabled
        if let Ok(output) = Command::new("bluetoothctl").args(&["show"]).output() {
            let output_str = String::from_utf8_lossy(&output.stdout);
            if output_str.contains("Powered: yes") {
                hardware_details.insert("bluetooth_0".to_string(), HardwareDevice {
                    name: "Bluetooth LE Controller".to_string(),
                    device_type: "Bluetooth".to_string(),
                    vendor_info: None,
                    device_path: Some("/dev/bluetooth".to_string()),
                    properties: HashMap::new(),
                });
                return true;
            }
        }
    }
    
    #[cfg(target_os = "windows")]
    {
        use std::process::Command;
        
        if let Ok(output) = Command::new("powershell")
            .args(&["-Command", "Get-PnpDevice | Where-Object {$_.Class -eq 'Bluetooth'}"])
            .output() {
            let output_str = String::from_utf8_lossy(&output.stdout);
            if !output_str.trim().is_empty() {
                hardware_details.insert("bluetooth_0".to_string(), HardwareDevice {
                    name: "Windows Bluetooth Controller".to_string(),
                    device_type: "Bluetooth".to_string(),
                    vendor_info: None,
                    device_path: None,
                    properties: HashMap::new(),
                });
                return true;
            }
        }
    }
    
    #[cfg(target_os = "macos")]
    {
        use std::process::Command;
        
        if let Ok(output) = Command::new("system_profiler")
            .args(&["SPBluetoothDataType"])
            .output() {
            let output_str = String::from_utf8_lossy(&output.stdout);
            if output_str.contains("Bluetooth") {
                hardware_details.insert("bluetooth_0".to_string(), HardwareDevice {
                    name: "macOS Bluetooth Controller".to_string(),
                    device_type: "Bluetooth".to_string(),
                    vendor_info: None,
                    device_path: None,
                    properties: HashMap::new(),
                });
                return true;
            }
        }
    }
    
    false
}

/// Detect WiFi Direct hardware capabilities
async fn detect_wifi_direct_hardware(hardware_details: &mut HashMap<String, HardwareDevice>) -> bool {
    #[cfg(target_os = "linux")]
    {
        use std::process::Command;
        
        // Check for WiFi Direct support via iw command
        if let Ok(output) = Command::new("iw").args(&["dev"]).output() {
            let output_str = String::from_utf8_lossy(&output.stdout);
            if !output_str.trim().is_empty() {
                // Check if any interface supports P2P
                if let Ok(p2p_output) = Command::new("iw").args(&["list"]).output() {
                    let p2p_str = String::from_utf8_lossy(&p2p_output.stdout);
                    if p2p_str.contains("P2P-client") || p2p_str.contains("P2P-GO") {
                        hardware_details.insert("wifi_direct_0".to_string(), HardwareDevice {
                            name: "WiFi Direct Interface".to_string(),
                            device_type: "WiFi".to_string(),
                            vendor_info: None,
                            device_path: None,
                            properties: HashMap::new(),
                        });
                        return true;
                    }
                }
            }
        }
    }
    
    #[cfg(target_os = "windows")]
    {
        use std::process::Command;
        
        if let Ok(output) = Command::new("netsh")
            .args(&["wlan", "show", "profiles"])
            .output() {
            let output_str = String::from_utf8_lossy(&output.stdout);
            if output_str.contains("DIRECT") {
                hardware_details.insert("wifi_direct_0".to_string(), HardwareDevice {
                    name: "Windows WiFi Direct".to_string(),
                    device_type: "WiFi".to_string(),
                    vendor_info: None,
                    device_path: None,
                    properties: HashMap::new(),
                });
                return true;
            }
        }
    }
    
    #[cfg(target_os = "macos")]
    {
        // macOS has limited WiFi Direct support
        // Check for WiFi interfaces that might support it
        use std::process::Command;
        
        if let Ok(output) = Command::new("ifconfig").output() {
            let output_str = String::from_utf8_lossy(&output.stdout);
            if output_str.contains("en0") && output_str.contains("status: active") {
                hardware_details.insert("wifi_0".to_string(), HardwareDevice {
                    name: "macOS WiFi Interface".to_string(),
                    device_type: "WiFi".to_string(),
                    vendor_info: Some("Limited WiFi Direct support".to_string()),
                    device_path: None,
                    properties: HashMap::new(),
                });
                return true;
            }
        }
    }
    
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_hardware_detection() {
        let capabilities = HardwareCapabilities::detect().await;
        
        match capabilities {
            Ok(caps) => {
                println!("Hardware detection completed:");
                println!("  LoRaWAN radios: {}", caps.lorawan_radios.len());
                println!("  Bluetooth: {}", caps.bluetooth_available);
                println!("  WiFi Direct: {}", caps.wifi_direct_available);
                
                for (id, device) in caps.hardware_details {
                    println!("  Device {}: {} ({})", id, device.name, device.device_type);
                }
            }
            Err(e) => {
                println!("Hardware detection failed: {}", e);
            }
        }
    }

    #[test]
    fn test_lorawan_radio_filtering() {
        use crate::discovery::lorawan_hardware::{FrequencyBand, LoRaWANCapabilities, LoRaWANHardware};

        let mut capabilities = HardwareCapabilities::default();
        
        // Add test radios
        capabilities.lorawan_radios.push(LoRaWANHardware {
            device_name: "Test EU Radio".to_string(),
            connection_type: "SPI".to_string(),
            device_path: Some("/dev/test".to_string()),
            frequency_bands: vec![FrequencyBand::EU868],
            max_tx_power: 14,
            capabilities: LoRaWANCapabilities::default(),
        });

        capabilities.lorawan_radios.push(LoRaWANHardware {
            device_name: "Test US Radio".to_string(),
            connection_type: "USB".to_string(),
            device_path: Some("/dev/test2".to_string()),
            frequency_bands: vec![FrequencyBand::US915],
            max_tx_power: 20,
            capabilities: LoRaWANCapabilities::default(),
        });

        // Test filtering
        let eu_radios = capabilities.lorawan_radios_for_band(&FrequencyBand::EU868);
        assert_eq!(eu_radios.len(), 1);
        assert_eq!(eu_radios[0].device_name, "Test EU Radio");

        let us_radios = capabilities.lorawan_radios_for_band(&FrequencyBand::US915);
        assert_eq!(us_radios.len(), 1);
        assert_eq!(us_radios[0].device_name, "Test US Radio");

        // Test primary radio
        assert_eq!(capabilities.primary_lorawan().unwrap().device_name, "Test EU Radio");

        // Test availability
        assert!(capabilities.lorawan_available());
    }
}
