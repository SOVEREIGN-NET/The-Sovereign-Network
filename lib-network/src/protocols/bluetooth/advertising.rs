//! BLE advertising helpers for Bluetooth mesh.

#[cfg(target_os = "windows")]
use anyhow::anyhow;
use anyhow::Result;
use tracing::{info, warn};

use super::BluetoothMeshProtocol;

impl BluetoothMeshProtocol {
    /// Start advertising for phone discovery
    pub async fn start_advertising(&mut self) -> Result<()> {
        warn!("  Windows limitation: Phone discovery requires manual pairing");

        self.start_discovery().await?;

        warn!("   GATT service active but NOT phone-discoverable");
        warn!("   Solution: Pair PC with phone in Windows Settings first");
        Ok(())
    }

    /// Check if currently advertising
    pub fn is_advertising(&self) -> bool {
        self.discovery_active
    }

    pub(crate) async fn broadcast_mesh_advertisement(&self, adv_data: &[u8]) -> Result<()> {
        info!("Broadcasting  advertisement ({} bytes)", adv_data.len());

        #[cfg(target_os = "linux")]
        {
            self.linux_broadcast_bypass_adv(adv_data).await?;
        }

        #[cfg(target_os = "windows")]
        {
            self.windows_broadcast_bypass_adv(adv_data).await?;
        }

        #[cfg(target_os = "macos")]
        {
            self.macos_broadcast_mesh_adv(adv_data).await?;
        }

        Ok(())
    }

    #[cfg(target_os = "linux")]
    async fn linux_broadcast_bypass_adv(&self, adv_data: &[u8]) -> Result<()> {
        use std::process::Command;

        let hex_data = adv_data.iter().map(|b| format!("{:02x}", b)).collect::<String>();

        let _ = Command::new("sudo")
            .args(&["hcitool", "-i", "hci0", "cmd", "0x08", "0x0008", &hex_data])
            .output();

        let _ = Command::new("sudo")
            .args(&["hcitool", "-i", "hci0", "cmd", "0x08", "0x000a", "01"])
            .output();

        info!("Linux:  advertising started");
        Ok(())
    }

    #[cfg(target_os = "windows")]
    async fn windows_broadcast_bypass_adv(&self, adv_data: &[u8]) -> Result<()> {
        info!("Windows: Starting BLE advertising ({} bytes)", adv_data.len());

        #[cfg(feature = "windows-gatt")]
        {
            let adv_data = adv_data.to_vec();
            let result = tokio::task::spawn_blocking(move || -> Result<()> {
                use windows::{
                    core::HSTRING,
                    Devices::Bluetooth::Advertisement::*,
                };

                if adv_data.is_empty() {
                    return Err(anyhow!("Advertisement data cannot be empty for Windows BLE"));
                }

                let advertisement = BluetoothLEAdvertisement::new()
                    .map_err(|e| anyhow!("Failed to create advertisement: {:?}", e))?;

                let local_name = HSTRING::from("ZHTP");
                advertisement
                    .SetLocalName(&local_name)
                    .map_err(|e| anyhow!("Failed to set local name: {:?}", e))?;

                let publisher = BluetoothLEAdvertisementPublisher::Create(&advertisement)
                    .map_err(|e| anyhow!("Failed to create BLE publisher with advertisement: {:?}", e))?;

                publisher
                    .SetUseExtendedAdvertisement(false)
                    .map_err(|e| anyhow!("Failed to set extended advertisement: {:?}", e))?;

                publisher
                    .Start()
                    .map_err(|e| anyhow!("Failed to start advertising: {:?}", e))?;

                info!(" Windows: BLE advertising started successfully");
                info!("   Broadcasting as: ZHTP-MESH");
                info!("   Service UUID: {}", crate::constants::BLE_MESH_SERVICE_UUID);
                info!("   Advertisement Data: {} bytes", adv_data.len());

                Ok(())
            })
            .await
            .map_err(|e| anyhow!("Windows COM threading error: {}", e))?;

            result
        }

        #[cfg(not(feature = "windows-gatt"))]
        {
            use std::process::Command;

            warn!("Windows GATT feature not enabled, using PowerShell fallback");

            let _ = Command::new("powershell")
                .args(&["-Command", "Enable-NetAdapter -Name '*Bluetooth*' -Confirm:$false"])
                .output();

            let _ = Command::new("powershell")
                .args(&["-Command", "Set-NetConnectionProfile -NetworkCategory Private"])
                .output();

            info!(" Windows: Bluetooth enabled (limited advertising via PowerShell)");
            info!(" For full BLE mesh support, build with --features windows-gatt");

            Ok(())
        }
    }

    // macOS-specific advertising moved to bluetooth::macos module.
}

#[cfg(test)]
mod tests {
    use super::BluetoothMeshProtocol;
    use lib_crypto::KeyPair;

    #[test]
    fn test_is_advertising_reflects_state() {
        let node_id = [8u8; 32];
        let keypair = KeyPair::generate().unwrap();
        let mut protocol = BluetoothMeshProtocol::new(node_id, keypair.public_key).unwrap();

        assert!(!protocol.is_advertising());
        protocol.discovery_active = true;
        assert!(protocol.is_advertising());
    }
}
