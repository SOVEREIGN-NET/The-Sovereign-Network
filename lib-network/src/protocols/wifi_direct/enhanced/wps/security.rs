//! Imperative shell for WPS security - handles state management and side effects
//!
//! This module provides stateful WPS security management by delegating pure algorithmic
//! operations to the functional core while managing:
//! - PIN cache with expiry tracking
//! - NFC record storage
//! - State mutation (PIN marked as used, expiry checking)
//! - Logging and error reporting

use anyhow::Result;
use std::collections::HashMap;
use tracing::{debug, warn, info};

/// Advanced WPS security with state management
///
/// Implements the "Imperative Shell" pattern - provides stateful PIN and NFC management
/// while delegating pure algorithms to `core` module.
#[derive(Debug)]
pub struct AdvancedWPSSecurity {
    pin_cache: HashMap<String, WPSPinInfo>,
    nfc_cache: HashMap<String, WPSNFCInfo>,
}

impl AdvancedWPSSecurity {
    /// Create a new WPS security manager
    pub fn new() -> Self {
        debug!("Initializing AdvancedWPSSecurity");
        Self {
            pin_cache: HashMap::new(),
            nfc_cache: HashMap::new(),
        }
    }

    /// Generate secure WPS PIN with enhanced validation
    ///
    /// Generates a cryptographically secure 8-digit PIN using the Luhn algorithm
    /// and stores it with expiry tracking.
    pub fn generate_secure_wps_pin(&mut self, device_id: &str) -> Result<String> {
        use rand::{RngCore, Rng};

        debug!(device_id = device_id, "Generating secure WPS PIN");

        // SHELL: Generate random number using OS RNG
        let mut rng = rand::rngs::OsRng;
        let mut pin_bytes = [0u8; 8];
        for byte in &mut pin_bytes {
            *byte = rng.gen_range(b'0'..=b'9');
        }

        // SHELL: Convert to string and parse
        let pin_str = String::from_utf8(pin_bytes.to_vec())?;
        let pin_num: u64 = pin_str.parse()?;

        // CORE: Calculate checksum using pure algorithm
        let checksum = super::super::core::calculate_wps_checksum_alt(pin_num);
        let final_pin = format!("{:08}{}", pin_num, checksum);

        // SHELL: Store PIN info with tracking
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let pin_info = WPSPinInfo {
            pin: final_pin.clone(),
            device_id: device_id.to_string(),
            created_at: now,
            used: false,
            expiry: now + 300, // 5 minute expiry
        };

        self.pin_cache.insert(device_id.to_string(), pin_info);

        info!(device_id = device_id, pin = &final_pin, "Generated secure WPS PIN");
        Ok(final_pin)
    }

    /// Validate WPS PIN with security checks
    ///
    /// Checks:
    /// - PIN format and checksum validity
    /// - Expiry status
    /// - Single-use enforcement
    pub fn validate_wps_pin(&mut self, device_id: &str, pin: &str) -> Result<bool> {
        debug!(device_id = device_id, pin = pin, "Validating WPS PIN");

        if let Some(pin_info) = self.pin_cache.get_mut(device_id) {
            let current_time = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            // SHELL: Check expiry (state-dependent)
            if current_time > pin_info.expiry {
                warn!(device_id = device_id, "WPS PIN expired");
                return Ok(false);
            }

            // SHELL: Check if already used (state-dependent)
            if pin_info.used {
                warn!(device_id = device_id, "WPS PIN already used");
                return Ok(false);
            }

            // CORE: Validate PIN format and checksum using pure algorithm
            if !super::super::core::validate_wps_pin(pin) {
                warn!(device_id = device_id, "WPS PIN validation failed");
                return Ok(false);
            }

            // SHELL: Check if this is the correct PIN for the device
            if pin_info.pin == pin {
                pin_info.used = true;
                info!(device_id = device_id, "WPS PIN validated successfully");
                return Ok(true);
            }
        }

        warn!(device_id = device_id, "PIN not found or validation failed");
        Ok(false)
    }

    /// Generate NFC handover record for WPS
    ///
    /// Creates an NDEF-formatted NFC record containing WPS credentials
    pub fn generate_nfc_handover(&mut self, device_id: &str, ssid: &str, passphrase: &str, pin: &str) -> Result<Vec<u8>> {
        debug!(
            device_id = device_id,
            ssid = ssid,
            "Generating NFC handover record"
        );

        // CORE: Generate pure NDEF record structure
        let record = super::super::core::generate_nfc_ndef_record(ssid, passphrase, pin);

        // SHELL: Store NFC info with metadata
        let nfc_info = WPSNFCInfo {
            record: record.clone(),
            device_id: device_id.to_string(),
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        };

        self.nfc_cache.insert(device_id.to_string(), nfc_info);

        info!(
            device_id = device_id,
            size = record.len(),
            "Generated NFC handover record"
        );
        Ok(record)
    }

    /// Clean up expired PINs
    ///
    /// Removes all PINs that have exceeded their expiry time
    pub fn cleanup_expired_pins(&mut self) {
        debug!("Cleaning up expired WPS PINs");

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let before_count = self.pin_cache.len();
        self.pin_cache.retain(|_, info| now < info.expiry);
        let after_count = self.pin_cache.len();

        if before_count > after_count {
            info!(
                removed = before_count - after_count,
                "Removed expired WPS PINs"
            );
        }
    }

    /// Get PIN info for a device
    pub fn get_pin_info(&self, device_id: &str) -> Option<&WPSPinInfo> {
        self.pin_cache.get(device_id)
    }

    /// Get NFC info for a device
    pub fn get_nfc_info(&self, device_id: &str) -> Option<&WPSNFCInfo> {
        self.nfc_cache.get(device_id)
    }
}

impl Default for AdvancedWPSSecurity {
    fn default() -> Self {
        Self::new()
    }
}

/// WPS PIN information with security tracking
#[derive(Debug, Clone)]
pub struct WPSPinInfo {
    pub pin: String,
    pub device_id: String,
    pub created_at: u64,
    pub used: bool,
    pub expiry: u64,
}

/// WPS NFC handover information
#[derive(Debug, Clone)]
pub struct WPSNFCInfo {
    pub record: Vec<u8>,
    pub device_id: String,
    pub created_at: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wps_security_new() {
        let security = AdvancedWPSSecurity::new();
        assert_eq!(security.pin_cache.len(), 0);
        assert_eq!(security.nfc_cache.len(), 0);
    }

    #[test]
    fn test_wps_security_generate_pin() {
        let mut security = AdvancedWPSSecurity::new();
        let pin = security.generate_secure_wps_pin("device1").unwrap();
        assert_eq!(pin.len(), 9); // 8 digits + checksum
        assert!(security.get_pin_info("device1").is_some());
    }

    #[test]
    fn test_wps_security_cleanup_expired() {
        let mut security = AdvancedWPSSecurity::new();
        security.pin_cache.insert(
            "expired_device".to_string(),
            WPSPinInfo {
                pin: "12345670".to_string(),
                device_id: "expired_device".to_string(),
                created_at: 1000,
                used: false,
                expiry: 2000, // Far in the past
            },
        );

        security.cleanup_expired_pins();
        assert_eq!(security.pin_cache.len(), 0);
    }
}
