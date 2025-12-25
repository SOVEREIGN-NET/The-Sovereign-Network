//! Enhanced WiFi Direct implementations following FCIS (Functional Core / Imperative Shell)
//!
//! This module provides production-grade WiFi Direct support with:
//! - macOS Core WLAN integration
//! - Enhanced WPS security protocols
//! - Advanced P2P authentication
//!
//! # Architecture
//!
//! - `core.rs` - Pure, deterministic algorithms (WPS PIN, NFC NDEF, etc.)
//! - `wps/` - WPS security management with state tracking
//! - `macos/` - Platform-specific macOS implementation

pub mod core;
pub mod wps;

#[cfg(target_os = "macos")]
pub mod macos;

// Re-exports for convenience
pub use core::{
    calculate_wps_checksum_digit, validate_wps_pin, generate_nfc_ndef_record,
    derive_p2p_interface_name, generate_group_id, calculate_capability_score,
    resolve_go_tie, derive_p2p_bssid,
};
pub use wps::{AdvancedWPSSecurity, WPSPinInfo, WPSNFCInfo};

#[cfg(target_os = "macos")]
pub use macos::{MacOSWiFiDirectManager, MacOSWiFiInterface, MacOSP2PGroup};
