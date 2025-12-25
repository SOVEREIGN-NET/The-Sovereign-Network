//! macOS Core WLAN integration for WiFi Direct
//!
//! Provides platform-specific WiFi Direct functionality using macOS system frameworks.

pub mod manager;

pub use manager::MacOSWiFiDirectManager;

/// macOS WiFi Interface information
#[derive(Debug, Clone)]
pub struct MacOSWiFiInterface {
    pub name: String,
    pub device: String,
    pub bsd_name: String,
    pub p2p_capable: bool,
    pub current_network: Option<String>,
    pub signal_strength: i16,
}

/// macOS P2P Group information
#[derive(Debug, Clone)]
pub struct MacOSP2PGroup {
    pub name: String,
    pub interface: String,
    pub ssid: String,
    pub password: String,
    pub frequency: u16,
    pub group_owner: bool,
    pub connected_devices: Vec<String>,
    pub created_at: u64,
}
