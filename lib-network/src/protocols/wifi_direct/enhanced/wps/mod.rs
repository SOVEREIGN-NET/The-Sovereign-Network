//! WiFi Protected Setup (WPS) security implementation
//!
//! Handles PIN generation, validation, and NFC handover for P2P authentication

use anyhow::Result;
use std::collections::HashMap;
use tracing::{info, warn};
use rand::{Rng, RngCore};
use super::core;

/// Advanced WPS security manager
pub struct AdvancedWPSSecurity {
    pin_cache: HashMap<String, WPSPinInfo>,
    nfc_cache: HashMap<String, WPSNFCInfo>,
}

impl AdvancedWPSSecurity {
    pub fn new() -> Self {
        Self {
            pin_cache: HashMap::new(),
            nfc_cache: HashMap::new(),
        }
    }

    /// Generate secure WPS PIN with validation
    pub fn generate_secure_wps_pin(&mut self, device_id: &str) -> Result<String> {
        let mut rng = rand::rngs::OsRng;
        let base = rng.next_u32();

        // Use pure core function for PIN generation
        let pin = core::generate_wps_pin_deterministic(base);

        // Store PIN info with expiry (5 minutes)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let pin_info = WPSPinInfo {
            pin: pin.clone(),
            device_id: device_id.to_string(),
            created_at: now,
            used: false,
            expiry: now + 300,
        };

        self.pin_cache.insert(device_id.to_string(), pin_info);
        info!(" Generated secure WPS PIN for device {}", device_id);

        Ok(pin)
    }

    /// Validate WPS PIN with security checks
    pub fn validate_wps_pin(&mut self, device_id: &str, pin: &str) -> Result<bool> {
        if let Some(pin_info) = self.pin_cache.get_mut(device_id) {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            // Check expiry
            if now > pin_info.expiry {
                warn!(" WPS PIN expired for device {}", device_id);
                return Ok(false);
            }

            // Check if already used
            if pin_info.used {
                warn!(" WPS PIN already used for device {}", device_id);
                return Ok(false);
            }

            // Use pure core validation
            let format_valid = core::validate_wps_pin_format(pin);

            if format_valid && pin_info.pin == pin {
                pin_info.used = true;
                info!(" WPS PIN validated for device {}", device_id);
                return Ok(true);
            }
        }

        warn!(" Invalid WPS PIN for device {}", device_id);
        Ok(false)
    }

    /// Generate NFC handover record
    pub fn generate_nfc_handover(&mut self, device_id: &str) -> Result<Vec<u8>> {
        let mut rng = rand::rngs::OsRng;

        // Generate NDEF handover record
        let mut handover_record = Vec::new();

        // NDEF record header
        handover_record.push(0xD1);
        handover_record.push(0x02);
        handover_record.push(0x20);

        // Record type: Handover Select
        handover_record.extend_from_slice(b"Hs");

        // Payload with WPS config
        let mut payload = Vec::new();
        payload.push(0x10); // Version
        payload.push(0x4A); // Device Password ID
        payload.extend_from_slice(&[0x00, 0x10]);

        // Random config data
        let mut config_data = [0u8; 16];
        rng.fill(&mut config_data);
        payload.extend_from_slice(&config_data);

        handover_record.extend_from_slice(&payload);

        // Store NFC info
        let nfc_info = WPSNFCInfo {
            record: handover_record.clone(),
            device_id: device_id.to_string(),
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        };

        self.nfc_cache.insert(device_id.to_string(), nfc_info);
        info!(" Generated NFC handover record for device {}", device_id);

        Ok(handover_record)
    }

    /// Get cached PIN info
    pub fn get_pin_info(&self, device_id: &str) -> Option<WPSPinInfo> {
        self.pin_cache.get(device_id).cloned()
    }

    /// Get cached NFC info
    pub fn get_nfc_info(&self, device_id: &str) -> Option<WPSNFCInfo> {
        self.nfc_cache.get(device_id).cloned()
    }

    /// Cleanup expired PINs
    pub fn cleanup_expired_pins(&mut self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let before_count = self.pin_cache.len();
        self.pin_cache.retain(|_, info| now <= info.expiry);
        let after_count = self.pin_cache.len();

        if before_count > after_count {
            info!(" Cleaned up {} expired WPS PINs", before_count - after_count);
        }
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
    fn test_generate_and_validate_pin() {
        let mut wps = AdvancedWPSSecurity::new();
        let pin = wps.generate_secure_wps_pin("device-1").unwrap();

        assert_eq!(pin.len(), 8);
        assert!(wps.validate_wps_pin("device-1", &pin).unwrap());
    }

    #[test]
    fn test_pin_expiry() {
        let mut wps = AdvancedWPSSecurity::new();
        let pin = wps.generate_secure_wps_pin("device-2").unwrap();

        // Manually set expiry to past
        if let Some(pin_info) = wps.pin_cache.get_mut("device-2") {
            pin_info.expiry = 0;
        }

        assert!(!wps.validate_wps_pin("device-2", &pin).unwrap());
    }

    #[test]
    fn test_pin_single_use() {
        let mut wps = AdvancedWPSSecurity::new();
        let pin = wps.generate_secure_wps_pin("device-3").unwrap();

        // First use succeeds
        assert!(wps.validate_wps_pin("device-3", &pin).unwrap());

        // Second use fails
        assert!(!wps.validate_wps_pin("device-3", &pin).unwrap());
    }

    #[test]
    fn test_nfc_handover_generation() {
        let mut wps = AdvancedWPSSecurity::new();
        let handover = wps.generate_nfc_handover("device-4").unwrap();

        assert!(!handover.is_empty());
        assert_eq!(handover[0], 0xD1); // NDEF header
        assert!(wps.get_nfc_info("device-4").is_some());
    }
}
