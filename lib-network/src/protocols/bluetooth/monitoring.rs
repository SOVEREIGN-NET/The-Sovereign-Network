//! Monitoring helpers for Bluetooth mesh protocol.

use anyhow::Result;
use tracing::{info, warn};

use super::BluetoothMeshProtocol;

/// Bluetooth LE mesh status information
#[derive(Debug, Clone)]
pub struct BluetoothMeshStatus {
    pub discovery_active: bool,
    pub connected_peers: u32,
    pub signal_strength: i32, // dBm
    pub mesh_quality: f64, // 0.0 to 1.0
}

impl BluetoothMeshProtocol {
    /// Get Bluetooth LE mesh status
    pub async fn get_mesh_status(&self) -> BluetoothMeshStatus {
        let connections = self.current_connections.read().await;
        let connected_peers = connections.len() as u32;

        let avg_rssi = if !connections.is_empty() {
            connections.values().map(|c| c.rssi as i32).sum::<i32>() / connections.len() as i32
        } else {
            -45
        };

        let mesh_quality = if connected_peers > 0 {
            let connection_factor = (connected_peers as f64 / 8.0).min(1.0);
            let signal_factor = ((avg_rssi + 100) as f64 / 100.0).max(0.0).min(1.0);
            (connection_factor * 0.7 + signal_factor * 0.3).min(1.0)
        } else {
            0.0
        };

        BluetoothMeshStatus {
            discovery_active: self.discovery_active,
            connected_peers,
            signal_strength: avg_rssi,
            mesh_quality,
        }
    }

    /// Monitor ZHTP Bluetooth status (checks only)
    pub async fn start_zhtp_transmission_monitoring(&self) -> Result<()> {
        if self
            .zhtp_monitor_active
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            info!("Bluetooth monitoring already active");
            return Ok(());
        }

        info!("Starting Bluetooth status monitoring...");
        self.zhtp_monitor_active
            .store(true, std::sync::atomic::Ordering::Relaxed);

        let monitor_active = self.zhtp_monitor_active.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));

            while monitor_active.load(std::sync::atomic::Ordering::Relaxed) {
                interval.tick().await;

                use std::process::Command;
                let output = Command::new("powershell")
                    .args(&["-Command", "(Get-Service -Name bthserv).Status"])
                    .output();

                if let Ok(result) = output {
                    let status = String::from_utf8_lossy(&result.stdout).trim().to_string();
                    if status == "Running" {
                        info!("Bluetooth service: Running");
                    } else {
                        warn!("Bluetooth service status: {}", status);
                    }
                }
            }

            info!("Bluetooth monitoring stopped");
        });

        Ok(())
    }

    /// Stop ZHTP transmission monitoring
    pub fn stop_zhtp_transmission_monitoring(&self) {
        self.zhtp_monitor_active
            .store(false, std::sync::atomic::Ordering::Relaxed);
    }

    #[cfg(test)]
    pub(crate) fn mesh_quality(connected_peers: u32, avg_rssi: i32) -> f64 {
        if connected_peers > 0 {
            let connection_factor = (connected_peers as f64 / 8.0).min(1.0);
            let signal_factor = ((avg_rssi + 100) as f64 / 100.0).max(0.0).min(1.0);
            (connection_factor * 0.7 + signal_factor * 0.3).min(1.0)
        } else {
            0.0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::BluetoothMeshProtocol;
    use super::BluetoothMeshStatus;
    use lib_crypto::KeyPair;

    #[test]
    fn test_mesh_quality_no_peers() {
        let quality = BluetoothMeshProtocol::mesh_quality(0, -45);
        assert_eq!(quality, 0.0);
    }

    #[test]
    fn test_mesh_quality_bounds() {
        let quality = BluetoothMeshProtocol::mesh_quality(8, -10);
        assert!(quality <= 1.0);
        assert!(quality >= 0.0);
    }

    #[tokio::test]
    async fn test_mesh_status_empty() {
        let node_id = [2u8; 32];
        let keypair = KeyPair::generate().unwrap();
        let protocol = BluetoothMeshProtocol::new(node_id, keypair.public_key).unwrap();

        let status: BluetoothMeshStatus = protocol.get_mesh_status().await;
        assert_eq!(status.connected_peers, 0);
        assert!(status.mesh_quality >= 0.0);
    }
}
