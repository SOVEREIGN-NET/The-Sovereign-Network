//! WiFi Direct Connection Manager
//!
//! Handles:
//! - Connection quality monitoring
//! - Connectivity testing (ping)
//! - Automatic peer cleanup
//! - Mesh status reporting

use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};
use crate::protocols::wifi_direct::wifi_direct::{WiFiDirectConnection, WiFiDirectMeshStatus};

pub struct ConnectionManager {
    connected_devices: Arc<RwLock<HashMap<String, WiFiDirectConnection>>>,
}

impl ConnectionManager {
    pub fn new(
        connected_devices: Arc<RwLock<HashMap<String, WiFiDirectConnection>>>,
    ) -> Result<Self> {
        debug!("Initializing Connection Manager");
        Ok(Self { connected_devices })
    }

    /// Start connection quality monitoring
    pub async fn start_monitoring(&self) -> Result<()> {
        debug!("Starting connection quality monitoring");

        let connected_devices = self.connected_devices.clone();

        tokio::spawn(async move {
            let mut monitoring_interval = tokio::time::interval(tokio::time::Duration::from_secs(30));

            loop {
                monitoring_interval.tick().await;

                let devices = connected_devices.read().await;
                debug!(count = devices.len(), "Checking connection quality");

                for (_mac, device) in devices.iter() {
                    // Test connectivity via ping
                    if let Ok(reachable) = Self::test_connection(&device.ip_address).await {
                        if !reachable {
                            warn!(
                                device = &device.device_name,
                                ip = &device.ip_address,
                                "Device connection lost"
                            );
                        }
                    }
                }
            }
        });

        info!("Connection quality monitoring started");
        Ok(())
    }

    /// Test connection to a device via ping
    async fn test_connection(ip_address: &str) -> Result<bool> {
        use std::process::Command;
        use std::time::Duration;

        debug!(ip = ip_address, "Testing connection via ping");

        #[cfg(target_os = "linux")]
        {
            let output = Command::new("ping")
                .args(&["-c", "1", "-W", "2", ip_address])
                .output();

            Ok(output.is_ok() && output.unwrap().status.success())
        }

        #[cfg(target_os = "windows")]
        {
            let output = Command::new("ping")
                .args(&["-n", "1", "-w", "2000", ip_address])
                .output();

            Ok(output.is_ok() && output.unwrap().status.success())
        }

        #[cfg(target_os = "macos")]
        {
            let output = Command::new("ping")
                .args(&["-c", "1", "-W", "2", ip_address])
                .output();

            Ok(output.is_ok() && output.unwrap().status.success())
        }

        #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
        {
            Ok(true)
        }
    }

    /// Get mesh status
    pub async fn get_mesh_status(&self, group_owner: bool, discovery_active: bool) -> WiFiDirectMeshStatus {
        let devices = self.connected_devices.read().await;

        let device_count = devices.len() as u32;
        let total_data_rate: u64 = devices.iter().map(|(_, d)| d.data_rate).sum();
        let avg_signal_strength: i32 = if device_count > 0 {
            (devices.iter().map(|(_, d)| d.signal_strength as i64).sum::<i64>()
                / device_count as i64) as i32
        } else {
            0
        };

        let throughput_mbps = (total_data_rate / device_count.max(1) as u64) as u32;

        // Calculate mesh quality (0.0 to 1.0)
        let mesh_quality = if device_count == 0 {
            0.0
        } else {
            let signal_quality = ((avg_signal_strength + 100) as f64 / 100.0).max(0.0).min(1.0);
            signal_quality * 0.7 + (device_count as f64 / 10.0).min(1.0) * 0.3
        };

        WiFiDirectMeshStatus {
            discovery_active,
            group_owner,
            connected_peers: device_count,
            group_members: device_count,
            signal_strength: avg_signal_strength,
            throughput_mbps,
            mesh_quality,
        }
    }

    /// Clean up inactive peers
    pub async fn cleanup_inactive_peers(&self) -> Result<()> {
        debug!("Cleaning up inactive peers");

        let mut devices = self.connected_devices.write().await;
        let before_count = devices.len();

        // Remove peers with no activity in last 5 minutes
        let cutoff_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() - 300;

        devices.retain(|_mac, device| device.connection_time > cutoff_time);

        let after_count = devices.len();
        if before_count > after_count {
            info!(
                removed = before_count - after_count,
                "Cleaned up inactive peers"
            );
        }

        Ok(())
    }

    /// Get list of connected devices
    pub async fn get_connected_devices(&self) -> Vec<WiFiDirectConnection> {
        self.connected_devices
            .read()
            .await
            .values()
            .cloned()
            .collect()
    }
}

impl Default for ConnectionManager {
    fn default() -> Self {
        Self {
            connected_devices: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}
