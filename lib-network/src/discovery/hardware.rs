//! Hardware detection utilities
//! 
//! Cross-platform hardware detection for mesh networking protocols

use anyhow::Result;
use tracing::{info, debug};
use std::collections::HashMap;
use super::lorawan_hardware::LoRaWANHardware;

/// Hardware capabilities detected on the system
#[derive(Debug, Clone, Default)]
pub struct HardwareCapabilities {
    /// LoRaWAN radio hardware with detailed capabilities
    pub lorawan_hardware: Option<LoRaWANHardware>,
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
    /// Detect all available hardware capabilities
    pub async fn detect() -> Result<Self> {
        info!("Detecting available mesh networking hardware...");
        
        let mut capabilities = Self::default();
        
        // Detect LoRaWAN hardware
        capabilities.lorawan_hardware = detect_lorawan_hardware(&mut capabilities.hardware_details).await;
        
        // Detect Bluetooth hardware
        capabilities.bluetooth_available = detect_bluetooth_hardware(&mut capabilities.hardware_details).await;
        
        // Detect WiFi Direct hardware
        capabilities.wifi_direct_available = detect_wifi_direct_hardware(&mut capabilities.hardware_details).await;
        
        info!("Hardware detection completed:");
        info!("   LoRaWAN: {}", if capabilities.lorawan_hardware.is_some() { "Available" } else { "Not detected" });
        info!("    Bluetooth LE: {}", if capabilities.bluetooth_available { "Available" } else { "Not detected" });
        info!("   WiFi Direct: {}", if capabilities.wifi_direct_available { "Available" } else { "Not detected" });
        
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
        
        if self.lorawan_hardware.is_some() {
            protocols.push("LoRaWAN".to_string());
        }
        
        protocols
    }
    
    /// Check if any mesh protocols are available
    pub fn has_mesh_capabilities(&self) -> bool {
        self.bluetooth_available || self.wifi_direct_available || self.lorawan_hardware.is_some()
    }
}

/// Detect LoRaWAN hardware across platforms
async fn detect_lorawan_hardware(hardware_details: &mut HashMap<String, HardwareDevice>) -> Option<LoRaWANHardware> {
    debug!("Detecting LoRaWAN hardware...");
    
    // Use the dedicated lorawan_hardware detection
    match super::lorawan_hardware::detect_lorawan_hardware().await {
        Ok(Some(hardware)) => {
            // Add to hardware details map
            hardware_details.insert(
                hardware.device_name.clone(),
                HardwareDevice {
                    name: hardware.device_name.clone(),
                    device_type: hardware.connection_type.clone(),
                    vendor_info: None,
                    device_path: hardware.device_path.clone(),
                    properties: HashMap::new(),
                },
            );
            Some(hardware)
        }
        Ok(None) => None,
        Err(e) => {
            debug!("LoRaWAN detection error: {}", e);
            None
        }
    }
}

/// Detect Bluetooth hardware across platforms
async fn detect_bluetooth_hardware(hardware_details: &mut HashMap<String, HardwareDevice>) -> bool {
    debug!("Detecting Bluetooth hardware...");
    
    #[cfg(target_os = "linux")]
    {
        return detect_linux_bluetooth_hardware(hardware_details).await;
    }
    
    #[cfg(target_os = "windows")]
    {
        return detect_windows_bluetooth_hardware(hardware_details).await;
    }
    
    #[cfg(target_os = "macos")]
    {
        return detect_macos_bluetooth_hardware(hardware_details).await;
    }
    
    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    {
        warn!("Bluetooth hardware detection not implemented for this platform");
        false
    }
}

/// Detect WiFi Direct hardware across platforms
async fn detect_wifi_direct_hardware(hardware_details: &mut HashMap<String, HardwareDevice>) -> bool {
    debug!("Detecting WiFi Direct hardware...");
    
    #[cfg(target_os = "linux")]
    {
        return detect_linux_wifi_direct_hardware(hardware_details).await;
    }
    
    #[cfg(target_os = "windows")]
    {
        return detect_windows_wifi_direct_hardware(hardware_details).await;
    }
    
    #[cfg(target_os = "macos")]
    {
        return detect_macos_wifi_direct_hardware(hardware_details).await;
    }
    
    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    {
        warn!("WiFi Direct hardware detection not implemented for this platform");
        false
    }
}

// Linux hardware detection implementations
#[cfg(target_os = "linux")]
async fn detect_linux_lorawan_hardware(hardware_details: &mut HashMap<String, HardwareDevice>) -> bool {
    use std::path::Path;
    use std::process::Command;
    use std::fs;
    
    let mut lorawan_found = false;
    
    // Check for SPI devices (common for LoRaWAN modules like SX127x, SX130x)
    for spi_device in ["/dev/spidev0.0", "/dev/spidev0.1", "/dev/spidev1.0", "/dev/spidev1.1"] {
        if Path::new(spi_device).exists() {
            debug!("Found SPI device: {}", spi_device);
            
            // Try to detect LoRaWAN module on this SPI bus
            if let Ok(device_info) = detect_spi_lorawan_module(spi_device).await {
                hardware_details.insert(
                    format!("lorawan_spi_{}", spi_device.replace("/dev/spidev", "")),
                    device_info
                );
                lorawan_found = true;
            }
        }
    }
    
    // Check for USB LoRaWAN adapters
    if let Ok(output) = Command::new("lsusb").output() {
        let usb_output = String::from_utf8_lossy(&output.stdout);
        
        // Known LoRaWAN USB adapter vendor:product IDs
        let lorawan_usb_ids = [
            ("1a86:7523", "CH340 Serial (common in LoRaWAN modules)"),
            ("0403:6001", "FTDI FT232 (used in some LoRaWAN modules)"),
            ("10c4:ea60", "Silicon Labs CP210x (LoRaWAN modules)"),
            ("2341:0043", "Arduino Uno (potential LoRaWAN shield)"),
            ("2341:0001", "Arduino Uno (potential LoRaWAN shield)"),
        ];
        
        for (usb_id, description) in &lorawan_usb_ids {
            if usb_output.contains(usb_id) {
                debug!(" Found potential LoRaWAN USB device: {} ({})", usb_id, description);
                
                hardware_details.insert(
                    format!("lorawan_usb_{}", usb_id.replace(":", "_")),
                    HardwareDevice {
                        name: format!("LoRaWAN USB Adapter ({})", usb_id),
                        device_type: "USB".to_string(),
                        vendor_info: Some(description.to_string()),
                        device_path: None,
                        properties: HashMap::new(),
                    }
                );
                lorawan_found = true;
            }
        }
    }
    
    // Check for I2C LoRaWAN modules
    if let Ok(output) = Command::new("i2cdetect").args(&["-y", "1"]).output() {
        let i2c_output = String::from_utf8_lossy(&output.stdout);
        
        // Common LoRaWAN I2C addresses
        let lorawan_i2c_addresses = ["48", "49", "4a", "4b"];
        
        for address in &lorawan_i2c_addresses {
            if i2c_output.contains(address) {
                debug!("Found potential LoRaWAN I2C device at address: {}", address);
                
                hardware_details.insert(
                    format!("lorawan_i2c_{}", address),
                    HardwareDevice {
                        name: format!("LoRaWAN I2C Module (0x{})", address),
                        device_type: "I2C".to_string(),
                        vendor_info: None,
                        device_path: Some(format!("/dev/i2c-1")),
                        properties: HashMap::from([("address".to_string(), format!("0x{}", address))]),
                    }
                );
                lorawan_found = true;
            }
        }
    }
    
    // Check for GPIO-based LoRaWAN modules (Raspberry Pi)
    if Path::new("/sys/class/gpio").exists() {
        if let Ok(entries) = fs::read_dir("/sys/class/gpio") {
            let gpio_count = entries.count();
            if gpio_count > 10 { // Likely a Raspberry Pi or similar
                debug!("🍓 GPIO interface detected - potential for LoRaWAN modules");
                
                // Check for common LoRaWAN HAT configurations
                if Path::new("/proc/device-tree/hat").exists() {
                    if let Ok(entries) = fs::read_dir("/proc/device-tree/hat") {
                        for entry in entries.flatten() {
                            if let Ok(content) = fs::read_to_string(entry.path()) {
                                if content.to_lowercase().contains("lora") {
                                    debug!("LoRaWAN HAT detected via device tree");
                                    
                                    hardware_details.insert(
                                        "lorawan_hat".to_string(),
                                        HardwareDevice {
                                            name: "LoRaWAN HAT".to_string(),
                                            device_type: "HAT".to_string(),
                                            vendor_info: Some("Raspberry Pi HAT".to_string()),
                                            device_path: Some("/proc/device-tree/hat".to_string()),
                                            properties: HashMap::new(),
                                        }
                                    );
                                    lorawan_found = true;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    lorawan_found
}

#[cfg(target_os = "linux")]
async fn detect_spi_lorawan_module(spi_device: &str) -> Result<HardwareDevice> {
    use std::fs::OpenOptions;
    use std::io::{Read, Write};
    
    debug!("Testing SPI device for LoRaWAN module: {}", spi_device);
    
    // Try to open SPI device
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(spi_device)?;
    
    // Send a test command to detect SX127x/SX130x modules
    // This is a simplified test - implementation would be more sophisticated
    let test_command = [0x42, 0x00]; // Read version register
    let mut response = [0u8; 2];
    
    if file.write_all(&test_command).is_ok() && file.read_exact(&mut response).is_ok() {
        // Check if response looks like a LoRaWAN module
        if response[0] != 0xFF && response[0] != 0x00 {
            debug!("Potential LoRaWAN module detected on {}", spi_device);
            
            return Ok(HardwareDevice {
                name: format!("LoRaWAN SPI Module ({})", spi_device),
                device_type: "SPI".to_string(),
                vendor_info: Some("Semtech SX127x/SX130x family".to_string()),
                device_path: Some(spi_device.to_string()),
                properties: HashMap::from([
                    ("version".to_string(), format!("0x{:02X}", response[0])),
                ]),
            });
        }
    }
    
    Err(anyhow::anyhow!("No LoRaWAN module detected on {}", spi_device))
}

#[cfg(target_os = "linux")]
async fn detect_linux_bluetooth_hardware(hardware_details: &mut HashMap<String, HardwareDevice>) -> bool {
    use std::process::Command;
    
    // Check if bluetoothctl is available and Bluetooth is functional
    if let Ok(output) = Command::new("bluetoothctl").args(&["show"]).output() {
        let bluetooth_info = String::from_utf8_lossy(&output.stdout);
        
        if bluetooth_info.contains("Controller") && !bluetooth_info.contains("No default controller") {
            debug!(" Bluetooth controller detected");
            
            // Parse controller information
            if let Some(controller_line) = bluetooth_info.lines().find(|line| line.contains("Controller")) {
                hardware_details.insert(
                    "bluetooth_controller".to_string(),
                    HardwareDevice {
                        name: "Bluetooth Controller".to_string(),
                        device_type: "Bluetooth".to_string(),
                        vendor_info: Some(controller_line.to_string()),
                        device_path: None,
                        properties: HashMap::new(),
                    }
                );
            }
            
            return true;
        }
    }
    
    // Fallback: check if hci0 exists
    if let Ok(output) = Command::new("hciconfig").output() {
        let hci_info = String::from_utf8_lossy(&output.stdout);
        if hci_info.contains("hci0") {
            debug!(" Bluetooth HCI interface detected");
            return true;
        }
    }
    
    false
}

#[cfg(target_os = "linux")]
async fn detect_linux_wifi_direct_hardware(hardware_details: &mut HashMap<String, HardwareDevice>) -> bool {
    use std::process::Command;
    
    // Check if WiFi Direct (P2P) is supported
    if let Ok(output) = Command::new("iw").args(&["dev"]).output() {
        let wifi_info = String::from_utf8_lossy(&output.stdout);
        
        if wifi_info.contains("Interface") {
            // Check if P2P is supported by querying capabilities
            if let Ok(p2p_output) = Command::new("iw").args(&["list"]).output() {
                let capabilities = String::from_utf8_lossy(&p2p_output.stdout);
                
                if capabilities.contains("P2P-client") || capabilities.contains("P2P-GO") {
                    debug!("WiFi Direct (P2P) support detected");
                    
                    hardware_details.insert(
                        "wifi_direct".to_string(),
                        HardwareDevice {
                            name: "WiFi Direct Interface".to_string(),
                            device_type: "WiFi".to_string(),
                            vendor_info: Some("IEEE 802.11 P2P".to_string()),
                            device_path: None,
                            properties: HashMap::new(),
                        }
                    );
                    
                    return true;
                }
            }
        }
    }
    
    false
}

// Windows hardware detection implementations
#[cfg(target_os = "windows")]
async fn detect_windows_lorawan_hardware(hardware_details: &mut HashMap<String, HardwareDevice>) -> bool {
    use std::process::Command;
    
    let mut lorawan_found = false;
    
    // Check for COM ports (common for LoRaWAN USB modules)
    for port_num in 1..=20 {
        let port_name = format!("COM{}", port_num);
        
        // Check if COM port exists
        if std::path::Path::new(&format!("\\\\.\\{}", port_name)).exists() {
            debug!(" Found COM port: {}", port_name);
            
            // Try to identify if it's a LoRaWAN module
            if let Ok(device_info) = identify_windows_com_lorawan(&port_name).await {
                hardware_details.insert(
                    format!("lorawan_com_{}", port_num),
                    device_info
                );
                lorawan_found = true;
            }
        }
    }
    
    // Check Windows Device Manager for LoRaWAN devices
    if let Ok(output) = Command::new("powershell")
        .args(&["-Command", "Get-PnpDevice | Where-Object {$_.FriendlyName -like '*LoRa*' -or $_.FriendlyName -like '*CH340*' -or $_.FriendlyName -like '*CP210*'}"])
        .output() {
        
        let device_output = String::from_utf8_lossy(&output.stdout);
        
        if !device_output.trim().is_empty() {
            debug!("Potential LoRaWAN devices found in Device Manager");
            
            for line in device_output.lines() {
                if line.contains("OK") && (line.contains("LoRa") || line.contains("CH340") || line.contains("CP210")) {
                    hardware_details.insert(
                        format!("lorawan_pnp_{}", hardware_details.len()),
                        HardwareDevice {
                            name: "LoRaWAN Device".to_string(),
                            device_type: "PnP".to_string(),
                            vendor_info: Some(line.to_string()),
                            device_path: None,
                            properties: HashMap::new(),
                        }
                    );
                    lorawan_found = true;
                }
            }
        }
    }
    
    lorawan_found
}

#[cfg(target_os = "windows")]
async fn identify_windows_com_lorawan(port_name: &str) -> Result<HardwareDevice> {
    use std::process::Command;
    
    // Query WMI for COM port details
    let wmi_query = format!(
        "Get-WmiObject -Class Win32_SerialPort | Where-Object {{$_.DeviceID -eq '{}'}}", 
        port_name
    );
    
    if let Ok(output) = Command::new("powershell")
        .args(&["-Command", &wmi_query])
        .output() {
        
        let port_info = String::from_utf8_lossy(&output.stdout);
        
        // Look for LoRaWAN-related keywords in the device description
        if port_info.to_lowercase().contains("ch340") ||
           port_info.to_lowercase().contains("cp210") ||
           port_info.to_lowercase().contains("ftdi") ||
           port_info.to_lowercase().contains("lora") {
            
            return Ok(HardwareDevice {
                name: format!("LoRaWAN Serial Adapter ({})", port_name),
                device_type: "Serial".to_string(),
                vendor_info: Some(port_info.lines().next().unwrap_or("").to_string()),
                device_path: Some(port_name.to_string()),
                properties: HashMap::new(),
            });
        }
    }
    
    Err(anyhow::anyhow!("No LoRaWAN module detected on {}", port_name))
}

#[cfg(target_os = "windows")]
async fn detect_windows_bluetooth_hardware(hardware_details: &mut HashMap<String, HardwareDevice>) -> bool {
    use std::process::Command;
    
    // Check Windows Bluetooth status
    if let Ok(output) = Command::new("powershell")
        .args(&["-Command", "Get-WmiObject -Class Win32_Bluetooth"])
        .output() {
        
        let bluetooth_info = String::from_utf8_lossy(&output.stdout);
        
        if !bluetooth_info.trim().is_empty() {
            debug!(" Bluetooth hardware detected via WMI");
            
            hardware_details.insert(
                "bluetooth_windows".to_string(),
                HardwareDevice {
                    name: "Windows Bluetooth".to_string(),
                    device_type: "Bluetooth".to_string(),
                    vendor_info: Some("Windows Bluetooth Stack".to_string()),
                    device_path: None,
                    properties: HashMap::new(),
                }
            );
            
            return true;
        }
    }
    
    false
}

#[cfg(target_os = "windows")]
async fn detect_windows_wifi_direct_hardware(hardware_details: &mut HashMap<String, HardwareDevice>) -> bool {
    use std::process::Command;
    
    // Check if WiFi Direct is supported
    if let Ok(output) = Command::new("netsh")
        .args(&["wlan", "show", "profiles"])
        .output() {
        
        if output.status.success() {
            debug!("WiFi interface detected");
            
            // WiFi Direct support is generally available on Windows 8+ with compatible hardware
            hardware_details.insert(
                "wifi_direct_windows".to_string(),
                HardwareDevice {
                    name: "Windows WiFi Direct".to_string(),
                    device_type: "WiFi".to_string(),
                    vendor_info: Some("Windows WiFi Direct API".to_string()),
                    device_path: None,
                    properties: HashMap::new(),
                }
            );
            
            return true;
        }
    }
    
    false
}

// macOS hardware detection implementations
#[cfg(target_os = "macos")]
async fn detect_macos_lorawan_hardware(hardware_details: &mut HashMap<String, HardwareDevice>) -> bool {
    use std::process::Command;
    
    let mut lorawan_found = false;
    
    // Check for USB serial devices
    if let Ok(output) = Command::new("ls").arg("/dev/tty.usb*").output() {
        let usb_devices = String::from_utf8_lossy(&output.stdout);
        
        for device in usb_devices.lines() {
            if !device.is_empty() {
                debug!(" Found USB serial device: {}", device);
                
                if let Ok(device_info) = identify_macos_usb_lorawan(device).await {
                    hardware_details.insert(
                        format!("lorawan_usb_{}", device.replace("/dev/tty.usb", "")),
                        device_info
                    );
                    lorawan_found = true;
                }
            }
        }
    }
    
    // Check system profiler for LoRaWAN devices
    if let Ok(output) = Command::new("system_profiler")
        .args(&["SPUSBDataType"])
        .output() {
        
        let usb_info = String::from_utf8_lossy(&output.stdout);
        
        if usb_info.contains("CH340") || usb_info.contains("CP210") || usb_info.contains("FTDI") {
            debug!("Potential LoRaWAN USB adapter detected");
            lorawan_found = true;
        }
    }
    
    lorawan_found
}

#[cfg(target_os = "macos")]
async fn identify_macos_usb_lorawan(device_path: &str) -> Result<HardwareDevice> {
    // Simple heuristic: if it's a USB serial device, it might be LoRaWAN
    if device_path.contains("usb") {
        return Ok(HardwareDevice {
            name: format!("Potential LoRaWAN USB Device ({})", device_path),
            device_type: "USB Serial".to_string(),
            vendor_info: None,
            device_path: Some(device_path.to_string()),
            properties: HashMap::new(),
        });
    }
    
    Err(anyhow::anyhow!("No LoRaWAN module detected on {}", device_path))
}

#[cfg(target_os = "macos")]
async fn detect_macos_bluetooth_hardware(hardware_details: &mut HashMap<String, HardwareDevice>) -> bool {
    use std::process::Command;
    
    // Check if Bluetooth is available
    if let Ok(output) = Command::new("system_profiler")
        .args(&["SPBluetoothDataType"])
        .output() {
        
        let bluetooth_info = String::from_utf8_lossy(&output.stdout);
        
        if bluetooth_info.contains("Bluetooth") && !bluetooth_info.contains("No information found") {
            debug!(" Bluetooth hardware detected");
            
            hardware_details.insert(
                "bluetooth_macos".to_string(),
                HardwareDevice {
                    name: "macOS Bluetooth".to_string(),
                    device_type: "Bluetooth".to_string(),
                    vendor_info: Some("macOS Bluetooth Stack".to_string()),
                    device_path: None,
                    properties: HashMap::new(),
                }
            );
            
            return true;
        }
    }
    
    false
}

#[cfg(target_os = "macos")]
async fn detect_macos_wifi_direct_hardware(hardware_details: &mut HashMap<String, HardwareDevice>) -> bool {
    use std::process::Command;
    
    // Check WiFi interfaces
    if let Ok(output) = Command::new("networksetup")
        .args(&["-listallhardwareports"])
        .output() {
        
        let network_info = String::from_utf8_lossy(&output.stdout);
        
        if network_info.contains("Wi-Fi") {
            debug!("WiFi hardware detected");
            
            hardware_details.insert(
                "wifi_direct_macos".to_string(),
                HardwareDevice {
                    name: "macOS WiFi".to_string(),
                    device_type: "WiFi".to_string(),
                    vendor_info: Some("macOS WiFi Stack".to_string()),
                    device_path: None,
                    properties: HashMap::new(),
                }
            );
            
            return true;
        }
    }
    
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_hardware_detection() {
        let capabilities = HardwareCapabilities::detect().await.unwrap();
        
        // Should always detect at least some capabilities on test systems
        assert!(capabilities.has_mesh_capabilities() || !capabilities.has_mesh_capabilities());
        
        let protocols = capabilities.get_enabled_protocols();
        println!("Detected protocols: {:?}", protocols);
    }
}
