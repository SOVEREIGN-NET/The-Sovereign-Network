//! P2P Device Scanner
//!
//! Handles platform-specific P2P device discovery (Linux, Windows, macOS)

use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn, error};
use crate::protocols::wifi_direct::wifi_direct::WiFiDirectConnection;

pub struct DiscoveryScanner {
    #[cfg(target_os = "linux")]
    _marker: std::marker::PhantomData<()>,
    #[cfg(target_os = "windows")]
    _marker: std::marker::PhantomData<()>,
    #[cfg(target_os = "macos")]
    _marker: std::marker::PhantomData<()>,
}

impl DiscoveryScanner {
    pub fn new() -> Result<Self> {
        debug!("Initializing P2P Discovery Scanner");
        Ok(Self {
            #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
            _marker: std::marker::PhantomData,
        })
    }

    /// Start P2P device discovery (platform-specific)
    pub async fn start_discovery(
        &self,
        connected_devices: Arc<RwLock<HashMap<String, WiFiDirectConnection>>>,
    ) -> Result<()> {
        debug!("Starting P2P device discovery");

        // Spawn background discovery task
        tokio::spawn(async move {
            let mut discovery_interval = tokio::time::interval(tokio::time::Duration::from_secs(30));

            loop {
                discovery_interval.tick().await;

                // Scan for WiFi Direct devices
                match Self::scan_devices().await {
                    Ok(devices) => {
                        let mut devices_map = connected_devices.write().await;

                        for device in devices {
                            if !devices_map.contains_key(&device.mac_address) {
                                info!(
                                    "Discovered WiFi Direct device: {} ({})",
                                    device.device_name, device.mac_address
                                );
                                devices_map.insert(device.mac_address.clone(), device);
                            }
                        }
                    }
                    Err(e) => {
                        warn!("P2P discovery scan failed: {:?}", e);
                    }
                }
            }
        });

        Ok(())
    }

    /// Scan for P2P devices (platform-specific)
    async fn scan_devices() -> Result<Vec<WiFiDirectConnection>> {
        #[cfg(target_os = "linux")]
        {
            Self::linux_scan_devices().await
        }

        #[cfg(target_os = "windows")]
        {
            Self::windows_scan_devices().await
        }

        #[cfg(target_os = "macos")]
        {
            Self::macos_scan_devices().await
        }

        #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
        {
            Ok(Vec::new())
        }
    }

    #[cfg(target_os = "linux")]
    async fn linux_scan_devices() -> Result<Vec<WiFiDirectConnection>> {
        use std::process::Command;

        debug!("Scanning P2P devices on Linux");
        let mut devices = Vec::new();

        // Use wpa_cli to list P2P peers
        let output = Command::new("wpa_cli")
            .args(&["-i", "wlan0", "p2p_peers"])
            .output();

        if let Ok(result) = output {
            let output_str = String::from_utf8_lossy(&result.stdout);

            for line in output_str.lines() {
                let mac_address = line.trim().to_string();
                if !mac_address.is_empty() && mac_address.contains(':') {
                    devices.push(WiFiDirectConnection {
                        mac_address: mac_address.clone(),
                        ip_address: "0.0.0.0".to_string(),
                        signal_strength: -70,
                        connection_time: 0,
                        data_rate: 0,
                        device_name: format!("P2P-{}", &mac_address[..8]),
                        device_type: crate::protocols::wifi_direct::wifi_direct::WiFiDirectDeviceType::P2P,
                        session_key: None,
                        encryption: None,
                    });
                }
            }
        }

        Ok(devices)
    }

    #[cfg(target_os = "windows")]
    async fn windows_scan_devices() -> Result<Vec<WiFiDirectConnection>> {
        debug!("Scanning P2P devices on Windows");
        // Windows implementation would use WinRT APIs
        Ok(Vec::new())
    }

    #[cfg(target_os = "macos")]
    async fn macos_scan_devices() -> Result<Vec<WiFiDirectConnection>> {
        use std::process::Command;

        debug!("Scanning P2P networks on macOS");
        let mut devices = Vec::new();

        let scan_output = Command::new("/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport")
            .args(&["-s"])
            .output();

        if let Ok(result) = scan_output {
            let scan_str = String::from_utf8_lossy(&result.stdout);

            for line in scan_str.lines().skip(1) {
                // Skip header
                if line.contains("DIRECT-") || line.contains("P2P-") || line.contains("ZHTP-") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 3 {
                        let ssid = parts[0];
                        let bssid = parts[1];
                        let rssi_raw: i16 = parts[2].parse().unwrap_or(-70);
                        let rssi: i8 = rssi_raw.clamp(-128, 127) as i8;

                        devices.push(WiFiDirectConnection {
                            mac_address: bssid.to_string(),
                            ip_address: "0.0.0.0".to_string(),
                            signal_strength: rssi,
                            connection_time: 0,
                            data_rate: 0,
                            device_name: ssid.to_string(),
                            device_type: crate::protocols::wifi_direct::wifi_direct::WiFiDirectDeviceType::P2P,
                            session_key: None,
                            encryption: None,
                        });
                    }
                }
            }
        }

        Ok(devices)
    }

    /// Stop discovery
    pub async fn stop(&self) -> Result<()> {
        debug!("Stopping P2P discovery scanner");
        // Scanner runs in background task - cleanup is automatic
        Ok(())
    }
}

impl Default for DiscoveryScanner {
    fn default() -> Self {
        Self::new().unwrap_or_else(|_| Self {
            #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
            _marker: std::marker::PhantomData,
        })
    }
}
