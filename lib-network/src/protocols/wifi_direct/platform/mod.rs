//! Platform abstraction layer for WiFi Direct
//!
//! This module provides a trait-based abstraction for platform-specific WiFi Direct operations.
//! All platform-specific code (Linux, Windows, macOS) must implement this trait.

use anyhow::Result;
use crate::protocols::wifi_direct::wifi_direct::{
    P2PGoNegotiation, P2PInvitationRequest, P2PInvitationResponse, WiFiDirectConnection, WpsMethod,
    DeviceCapability, GroupCapability,
};

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "windows")]
pub mod windows;
#[cfg(target_os = "macos")]
pub mod macos;

/// Platform trait for WiFi Direct operations
///
/// All WiFi Direct implementations must provide a platform-specific implementation
/// of this trait. This ensures consistent behavior across different operating systems
/// while allowing platform-specific optimizations and workarounds.
#[async_trait::async_trait]
pub trait WiFiDirectPlatform: Send + Sync {
    /// Initialize the WiFi Direct platform
    async fn initialize(&self) -> Result<()>;

    /// Scan for P2P devices
    async fn scan_p2p_devices(&self) -> Result<Vec<WiFiDirectConnection>>;

    /// Scan for existing P2P groups
    async fn scan_groups(&self) -> Result<Vec<String>>;

    /// Create a P2P group (as Group Owner)
    async fn create_p2p_group(&self, ssid: &str, passphrase: &str) -> Result<()>;

    /// Join an existing P2P group
    async fn join_p2p_group(&self, ssid: &str, passphrase: &str) -> Result<()>;

    /// Get the current WiFi interface IP address
    async fn get_interface_ip(&self) -> Result<String>;

    /// Get the device's MAC address
    async fn get_mac_address(&self) -> Result<String>;

    /// Send a P2P invitation to a device
    async fn send_invitation(&self, request: &P2PInvitationRequest) -> Result<P2PInvitationResponse>;

    /// Perform WPS Push Button Configuration with a peer
    async fn perform_wps_pbc(&self, peer: &str) -> Result<String>;

    /// Perform WPS PIN Display method (we display the PIN)
    async fn perform_wps_pin_display(&self, peer: &str, pin: &str) -> Result<String>;

    /// Perform WPS PIN Keypad method (peer enters our PIN)
    async fn perform_wps_pin_keypad(&self, peer: &str, pin: &str) -> Result<String>;

    /// Transmit data over P2P link to a device
    async fn transmit_data(&self, ip: &str, port: u16, data: &[u8]) -> Result<()>;

    /// Get P2P negotiation parameters for our device
    fn get_go_negotiation(&self) -> P2PGoNegotiation;

    /// Set WPS method
    fn set_wps_method(&mut self, method: WpsMethod);
}

#[cfg(target_os = "linux")]
pub use linux::LinuxWiFiDirect;

#[cfg(target_os = "windows")]
pub use windows::WindowsWiFiDirect;

#[cfg(target_os = "macos")]
pub use macos::MacOSWiFiDirect;
