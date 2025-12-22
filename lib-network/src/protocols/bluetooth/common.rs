//! Common Bluetooth utilities shared across all implementations
//! 
//! This module provides shared functionality to avoid code duplication:
//! - MAC address parsing and retrieval
//! - UUID to GUID conversion
//! - Platform detection helpers
//! - Common error types

use anyhow::{Result, anyhow};
use tracing::{info, warn};

/// Parse MAC address string (AA:BB:CC:DD:EE:FF or AA-BB-CC-DD-EE-FF) to bytes
/// 
/// # Examples
/// ```ignore
/// let mac = parse_mac_address("AA:BB:CC:DD:EE:FF")?;
/// assert_eq!(mac, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
/// ```
pub fn parse_mac_address(mac_str: &str) -> Result<[u8; 6]> {
    let clean = mac_str.replace([':', '-'], "");
    if clean.len() != 12 {
        return Err(anyhow!("Invalid MAC address length: expected 12 hex chars, got {}", clean.len()));
    }
    
    let mut mac = [0u8; 6];
    for i in 0..6 {
        mac[i] = u8::from_str_radix(&clean[i*2..i*2+2], 16)
            .map_err(|e| anyhow!("Failed to parse MAC address byte at position {}: {}", i, e))?;
    }
    Ok(mac)
}

/// Get system Bluetooth MAC address (cross-platform)
/// 
/// Tries multiple methods to retrieve the actual Bluetooth adapter MAC address:
/// - Windows: PowerShell Get-NetAdapter query
/// - Linux: /sys/class/bluetooth adapter address files
/// - macOS: system_profiler SPBluetoothDataType
/// 
/// Falls back to generating a deterministic locally-administered MAC if detection fails.
pub fn get_system_bluetooth_mac() -> Result<[u8; 6]> {
    #[cfg(target_os = "windows")]
    {
        use std::process::Command;
        
        info!(" Windows: Detecting Bluetooth MAC address via PowerShell");
        let output = Command::new("powershell")
            .args(&["-Command", "Get-NetAdapter | Where-Object {$_.Name -like '*Bluetooth*'} | Select-Object -ExpandProperty MacAddress"])
            .output();
        
        if let Ok(result) = output {
            let mac_str = String::from_utf8_lossy(&result.stdout);
            let trimmed = mac_str.trim();
            if !trimmed.is_empty() {
                if let Ok(mac) = parse_mac_address(trimmed) {
                    info!(" Detected Windows Bluetooth MAC: {}", trimmed);
                    return Ok(mac);
                }
            }
        }
        warn!(" Windows: Could not detect Bluetooth MAC via PowerShell");
    }
    
    #[cfg(target_os = "linux")]
    {
        info!("🐧 Linux: Detecting Bluetooth MAC address from /sys/class/bluetooth");
        
        if let Ok(adapters) = std::fs::read_dir("/sys/class/bluetooth") {
            for adapter in adapters.flatten() {
                let address_path = adapter.path().join("address");
                if let Ok(address) = std::fs::read_to_string(address_path) {
                    let trimmed = address.trim();
                    if let Ok(mac) = parse_mac_address(trimmed) {
                        info!(" Detected Linux Bluetooth MAC: {}", trimmed);
                        return Ok(mac);
                    }
                }
            }
        }
        warn!(" Linux: Could not detect Bluetooth MAC from sysfs");
    }
    
    #[cfg(target_os = "macos")]
    {
        use std::process::Command;
        
        info!("🍎 macOS: Detecting Bluetooth MAC address via system_profiler");
        let output = Command::new("system_profiler")
            .args(&["SPBluetoothDataType", "-xml"])
            .output();
        
        if let Ok(result) = output {
            let output_str = String::from_utf8_lossy(&result.stdout);
            
            // Simple parsing - look for MAC address patterns
            for line in output_str.lines() {
                if line.contains("Address") || line.contains("address") {
                    // Look for MAC address pattern (XX:XX:XX:XX:XX:XX)
                    for word in line.split_whitespace() {
                        if word.len() == 17 && word.matches(':').count() == 5 {
                            if let Ok(mac) = parse_mac_address(word) {
                                info!(" Detected macOS Bluetooth MAC: {}", word);
                                return Ok(mac);
                            }
                        }
                    }
                }
            }
        }
        warn!(" macOS: Could not detect Bluetooth MAC via system_profiler");
    }
    
    // Fallback: Generate deterministic locally-administered MAC
    info!(" Generating deterministic fallback Bluetooth MAC address");
    generate_fallback_mac()
}

/// Generate a deterministic locally-administered MAC address
/// Based on system hostname to ensure consistency across restarts
fn generate_fallback_mac() -> Result<[u8; 6]> {
    use sha2::{Sha256, Digest};
    
    // Get system identifier using proper hostname API
    let system_id = hostname::get()
        .map(|h| h.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "UNKNOWN_HOST".to_string());
    
    // Hash to generate deterministic MAC
    let mut hasher = Sha256::new();
    hasher.update(b"BLUETOOTH_FALLBACK_MAC");
    hasher.update(system_id.as_bytes());
    let hash = hasher.finalize();
    
    let mut mac = [0u8; 6];
    mac.copy_from_slice(&hash[0..6]);
    
    // Set locally administered bit (bit 1 of first octet)
    mac[0] |= 0x02;
    // Clear multicast bit (bit 0 of first octet)
    mac[0] &= 0xFE;
    
    info!(" Generated fallback MAC: {:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}", 
          mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    
    Ok(mac)
}

/// Format MAC address as string (XX:XX:XX:XX:XX:XX)
pub fn format_mac_address(mac: &[u8; 6]) -> String {
    format!("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}

/// Format MAC address as D-Bus device path (dev_XX_XX_XX_XX_XX_XX)
pub fn mac_to_dbus_path(mac: &[u8; 6]) -> String {
    format!("dev_{:02X}_{:02X}_{:02X}_{:02X}_{:02X}_{:02X}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}

/// Parse UUID string to Windows GUID
/// 
/// Converts standard UUID format (8-4-4-4-12) to Windows GUID structure
/// Example: "6ba7b810-9dad-11d1-80b4-00c04fd430ca"
#[cfg(all(target_os = "windows", feature = "windows-gatt"))]
pub fn parse_uuid_to_guid(uuid_str: &str) -> Result<windows::core::GUID> {
    use windows::core::GUID;
    
    // Remove hyphens and validate length
    let clean = uuid_str.replace("-", "");
    if clean.len() != 32 {
        return Err(anyhow!("Invalid UUID format: expected 32 hex chars"));
    }
    
    // Parse components
    let data1 = u32::from_str_radix(&clean[0..8], 16)?;
    let data2 = u16::from_str_radix(&clean[8..12], 16)?;
    let data3 = u16::from_str_radix(&clean[12..16], 16)?;
    
    let mut data4 = [0u8; 8];
    for i in 0..8 {
        data4[i] = u8::from_str_radix(&clean[16 + i*2..16 + i*2 + 2], 16)?;
    }
    
    Ok(GUID::from_values(data1, data2, data3, data4))
}

/// Standard ZHTP Service UUIDs
pub mod zhtp_uuids {
    /// ZHTP Mesh Service UUID (v3 - changed last digit from c9 to ca to bypass macOS Core Bluetooth cache)
    pub const ZHTP_MESH_SERVICE: &str = "6ba7b810-9dad-11d1-80b4-00c04fd430ca";
    
    /// ZK Authentication characteristic
    pub const ZK_AUTH_CHAR: &str = "6ba7b811-9dad-11d1-80b4-00c04fd430ca";
    
    /// Quantum-resistant routing characteristic
    pub const QUANTUM_ROUTING_CHAR: &str = "6ba7b812-9dad-11d1-80b4-00c04fd430ca";
    
    /// Mesh data transfer characteristic
    pub const MESH_DATA_CHAR: &str = "6ba7b813-9dad-11d1-80b4-00c04fd430ca";
    
    /// Mesh coordination characteristic
    pub const MESH_COORD_CHAR: &str = "6ba7b814-9dad-11d1-80b4-00c04fd430ca";
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_parse_mac_address_colon() {
        let mac = parse_mac_address("AA:BB:CC:DD:EE:FF").unwrap();
        assert_eq!(mac, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    }
    
    #[test]
    fn test_parse_mac_address_hyphen() {
        let mac = parse_mac_address("AA-BB-CC-DD-EE-FF").unwrap();
        assert_eq!(mac, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    }
    
    #[test]
    fn test_parse_mac_address_lowercase() {
        let mac = parse_mac_address("aa:bb:cc:dd:ee:ff").unwrap();
        assert_eq!(mac, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    }
    
    #[test]
    fn test_parse_mac_address_invalid_length() {
        assert!(parse_mac_address("AA:BB:CC:DD:EE").is_err());
    }
    
    #[test]
    fn test_format_mac_address() {
        let mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        assert_eq!(format_mac_address(&mac), "AA:BB:CC:DD:EE:FF");
    }
    
    #[test]
    fn test_mac_to_dbus_path() {
        let mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        assert_eq!(mac_to_dbus_path(&mac), "dev_AA_BB_CC_DD_EE_FF");
    }
    
    #[test]
    fn test_fallback_mac_generation() {
        // Should generate valid locally-administered MAC
        let mac = generate_fallback_mac().unwrap();
        
        // Check locally administered bit is set
        assert_eq!(mac[0] & 0x02, 0x02);
        // Check multicast bit is clear
        assert_eq!(mac[0] & 0x01, 0x00);
    }
}
