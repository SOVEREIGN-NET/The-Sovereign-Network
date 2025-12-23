//! Platform device discovery helpers for Bluetooth mesh protocol.

#[cfg(any(target_os = "linux", target_os = "windows"))]
use anyhow::Result;
#[cfg(any(target_os = "linux", target_os = "windows"))]
use tracing::{info, warn};

use super::BluetoothMeshProtocol;

impl BluetoothMeshProtocol {
    /// Linux device discovery
    #[cfg(target_os = "linux")]
    pub(crate) async fn linux_discover_device(&self, address: &str) -> Result<()> {
        use std::process::Command;

        let _ = Command::new("bluetoothctl")
            .args(&["scan", "on"])
            .output();

        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        let info_output = Command::new("bluetoothctl")
            .args(&["info", address])
            .output();

        if let Ok(result) = info_output {
            let output_str = String::from_utf8_lossy(&result.stdout);

            if output_str.contains("Device") {
                let raw_mac = super::common::parse_mac_address(address)?;

                let mut device =
                    self.create_secure_tracked_device(&raw_mac, Self::extract_device_name(&output_str));
                device.services = Self::extract_services(&output_str);

                self.track_device(&raw_mac, device).await?;
                info!(" Linux: Securely discovered device with ephemeral ID");
            }
        }

        Ok(())
    }

    /// Windows device discovery
    #[cfg(target_os = "windows")]
    pub(crate) async fn windows_discover_device(&self, address: &str) -> Result<()> {
        info!("Windows: Device discovery for {}", address);

        #[cfg(feature = "windows-gatt")]
        {
            use windows::Devices::Bluetooth::BluetoothLEDevice;

            let bluetooth_address = self.parse_windows_bluetooth_address(address)?;

            let device_async = BluetoothLEDevice::FromBluetoothAddressAsync(bluetooth_address)
                .map_err(|e| anyhow::anyhow!("Failed to get BLE device: {:?}", e))?;
            let device = device_async
                .get()
                .map_err(|e| anyhow::anyhow!("Failed to await BLE device: {:?}", e))?;

            let device_name = device
                .Name()
                .map(|name| name.to_string())
                .unwrap_or_else(|_| "Unknown".to_string());

            let connection_status = device
                .ConnectionStatus()
                .map_err(|e| anyhow::anyhow!("Failed to get connection status: {:?}", e))?;

            info!(
                "Windows: Discovered device - Name: {}, Status: {:?}",
                device_name, connection_status
            );

            let raw_mac = {
                let parts: Vec<&str> = address.split(':').collect();
                let mut mac = [0u8; 6];
                for (i, part) in parts.iter().enumerate() {
                    if i < 6 {
                        mac[i] = u8::from_str_radix(part, 16).unwrap_or(0);
                    }
                }
                mac
            };

            let tracked_device = self.create_secure_tracked_device(&raw_mac, Some(device_name));

            self.track_device(&raw_mac, tracked_device).await?;

            info!(" Windows: Device securely tracked with ephemeral ID");
        }

        #[cfg(not(feature = "windows-gatt"))]
        {
            use std::process::Command;

            let ps_script = format!(
                "$device = Get-PnpDevice | Where-Object {{$_.InstanceId -like '*{}*'}}; \
                if ($device) {{ \
                    Write-Host 'Device found:' $device.Name; \
                    Write-Host 'Status:' $device.Status; \
                }} else {{ \
                    Write-Host 'Device not found'; \
                }}",
                address.replace(":", "")
            );

            let output = Command::new("powershell")
                .args(&["-Command", &ps_script])
                .output();

            if let Ok(result) = output {
                let output_str = String::from_utf8_lossy(&result.stdout);
                if output_str.contains("Device found") {
                    info!("Windows: Device discovery completed via PowerShell");
                } else {
                    warn!("Windows: Device {} not found via PowerShell", address);
                }
            }
        }

        Ok(())
    }

    // macOS-specific discovery moved to bluetooth::macos module.
}
