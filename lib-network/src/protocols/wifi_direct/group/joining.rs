//! P2P Group Joining
//!
//! Handles joining existing P2P groups and scanning for available groups (platform-specific)

use anyhow::Result;
use tracing::{debug, info, warn};

pub struct GroupJoiner {
    // Platform-specific state can be added here
}

impl GroupJoiner {
    pub fn new() -> Result<Self> {
        debug!("Initializing Group Joiner");
        Ok(Self {})
    }

    /// Scan for available P2P groups
    pub async fn scan_for_groups(&self) -> Result<Vec<String>> {
        debug!("Scanning for available P2P groups");

        #[cfg(target_os = "linux")]
        {
            self.linux_scan_groups().await
        }

        #[cfg(target_os = "windows")]
        {
            self.windows_scan_groups().await
        }

        #[cfg(target_os = "macos")]
        {
            self.macos_scan_groups().await
        }

        #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
        {
            Ok(Vec::new())
        }
    }

    /// Join an existing P2P group
    pub async fn join_group(&self, ssid: &str, passphrase: &str) -> Result<()> {
        debug!(ssid = ssid, "Joining P2P group");

        #[cfg(target_os = "linux")]
        {
            self.linux_join_group(ssid, passphrase).await?;
        }

        #[cfg(target_os = "windows")]
        {
            self.windows_join_group(ssid, passphrase).await?;
        }

        #[cfg(target_os = "macos")]
        {
            self.macos_join_group(ssid, passphrase).await?;
        }

        info!(ssid = ssid, "Joined P2P group");
        Ok(())
    }

    /// Join existing P2P groups
    pub async fn join_existing_groups(&self) -> Result<()> {
        debug!("Joining existing P2P groups");

        // Scan for available groups
        let groups = self.scan_for_groups().await?;

        if groups.is_empty() {
            debug!("No P2P groups available to join");
            return Ok(());
        }

        // Attempt to join first available group
        if let Some(ssid) = groups.first() {
            debug!(ssid = ssid, "Joining first available group");
            // In real implementation, would use known passphrase from persistent groups
            self.join_group(ssid, "").await.ok(); // Ignore errors for now
        }

        Ok(())
    }

    #[cfg(target_os = "linux")]
    async fn linux_scan_groups(&self) -> Result<Vec<String>> {
        use std::process::Command;

        debug!("Scanning P2P groups on Linux");
        let mut groups = Vec::new();

        // Use wpa_cli to list networks
        let output = Command::new("wpa_cli")
            .args(&["-i", "wlan0", "list_networks"])
            .output()?;

        let output_str = String::from_utf8_lossy(&output.stdout);

        for line in output_str.lines().skip(1) {
            // Skip header
            let parts: Vec<&str> = line.split('\t').collect();
            if parts.len() >= 2 {
                let ssid = parts[1].to_string();
                if ssid.contains("DIRECT-") || ssid.contains("P2P-") {
                    groups.push(ssid);
                }
            }
        }

        Ok(groups)
    }

    #[cfg(target_os = "linux")]
    async fn linux_join_group(&self, ssid: &str, passphrase: &str) -> Result<()> {
        use std::process::Command;

        debug!(ssid = ssid, "Joining P2P group on Linux");

        // Use wpa_cli to add and connect to network
        let add_output = Command::new("wpa_cli")
            .args(&["-i", "wlan0", "add_network"])
            .output()?;

        let output_str = String::from_utf8_lossy(&add_output.stdout);
        let network_id = output_str.trim();

        // Set SSID
        Command::new("wpa_cli")
            .args(&["-i", "wlan0", "set_network", network_id, "ssid", &format!("\"{}\"", ssid)])
            .output()?;

        // Set passphrase if provided
        if !passphrase.is_empty() {
            Command::new("wpa_cli")
                .args(&[
                    "-i",
                    "wlan0",
                    "set_network",
                    network_id,
                    "psk",
                    &format!("\"{}\"", passphrase),
                ])
                .output()?;
        }

        // Enable network
        Command::new("wpa_cli")
            .args(&["-i", "wlan0", "enable_network", network_id])
            .output()?;

        info!(ssid = ssid, "Joined P2P group on Linux");
        Ok(())
    }

    #[cfg(target_os = "windows")]
    async fn windows_scan_groups(&self) -> Result<Vec<String>> {
        debug!("Scanning P2P groups on Windows");
        // Windows implementation would use WinRT APIs
        Ok(Vec::new())
    }

    #[cfg(target_os = "windows")]
    async fn windows_join_group(&self, ssid: &str, _passphrase: &str) -> Result<()> {
        debug!(ssid = ssid, "Joining P2P group on Windows");
        // Windows implementation would use WinRT APIs
        Ok(())
    }

    #[cfg(target_os = "macos")]
    async fn macos_scan_groups(&self) -> Result<Vec<String>> {
        use std::process::Command;

        debug!("Scanning P2P groups on macOS");
        let mut groups = Vec::new();

        let scan_output = Command::new("/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport")
            .args(&["-s"])
            .output();

        if let Ok(result) = scan_output {
            let scan_str = String::from_utf8_lossy(&result.stdout);

            for line in scan_str.lines().skip(1) {
                if line.contains("DIRECT-") || line.contains("P2P-") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if !parts.is_empty() {
                        groups.push(parts[0].to_string());
                    }
                }
            }
        }

        Ok(groups)
    }

    #[cfg(target_os = "macos")]
    async fn macos_join_group(&self, ssid: &str, _passphrase: &str) -> Result<()> {
        use std::process::Command;

        debug!(ssid = ssid, "Joining P2P group on macOS");

        // Use networksetup to join network
        Command::new("networksetup")
            .args(&["-setairportnetwork", "en0", ssid])
            .output()?;

        info!(ssid = ssid, "Joined P2P group on macOS");
        Ok(())
    }
}

impl Default for GroupJoiner {
    fn default() -> Self {
        Self::new().unwrap_or_else(|_| Self {})
    }
}
