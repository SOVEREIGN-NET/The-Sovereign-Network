//! Hardware detection utilities

use anyhow::Result;

/// Detect available hardware capabilities
pub async fn detect_hardware_capabilities() -> Result<HardwareCapabilities> {
    Ok(HardwareCapabilities {
        has_bluetooth: false,
        has_wifi: false,
        has_ethernet: false,
        has_cellular: false,
        cpu_cores: 1,
        memory_gb: 1,
    })
}

/// Hardware capabilities structure
#[derive(Debug, Clone)]
pub struct HardwareCapabilities {
    pub has_bluetooth: bool,
    pub has_wifi: bool,
    pub has_ethernet: bool,
    pub has_cellular: bool,
    pub cpu_cores: u32,
    pub memory_gb: u32,
}
