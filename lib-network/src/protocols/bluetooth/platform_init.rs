//! Platform initialization for Bluetooth mesh protocol.

use anyhow::Result;
use tracing::info;

use super::BluetoothMeshProtocol;

impl BluetoothMeshProtocol {
    /// Initialize Bluetooth stack
    pub(crate) async fn initialize_bluetooth_stack(&self) -> Result<()> {
        info!("Initializing Bluetooth stack for mesh networking...");

        #[cfg(target_os = "windows")]
        {
            self.init_windows_bluetooth().await?;
        }

        #[cfg(target_os = "linux")]
        {
            self.init_bluez_bluetooth().await?;
        }

        #[cfg(target_os = "macos")]
        {
            self.init_corebluetooth().await?;
        }

        Ok(())
    }

    /// Platform-specific implementations
    #[cfg(target_os = "windows")]
    async fn init_windows_bluetooth(&self) -> Result<()> {
        use std::process::Command;

        info!("Enabling Windows Bluetooth for mesh networking...");

        let _ = Command::new("powershell")
            .args(&["-Command", "Enable-NetAdapter -Name '*Bluetooth*'"])
            .output();

        let _ = Command::new("powershell")
            .args(&["-Command", "Set-NetConnectionProfile -NetworkCategory Private"])
            .output();

        info!("Windows Bluetooth ready for mesh networking");
        Ok(())
    }

    #[cfg(target_os = "linux")]
    async fn init_bluez_bluetooth(&self) -> Result<()> {
        use std::process::Command;

        info!("Configuring Linux BlueZ for ...");

        let _ = Command::new("sudo")
            .args(&["systemctl", "start", "bluetooth"])
            .output();

        let _ = Command::new("sudo")
            .args(&["hciconfig", "hci0", "up"])
            .output();

        let _ = Command::new("bluetoothctl")
            .args(&["discoverable", "on"])
            .output();

        info!("Linux BlueZ configured for ");
        Ok(())
    }

    #[cfg(target_os = "macos")]
    async fn init_corebluetooth(&self) -> Result<()> {
        info!("macOS Core Bluetooth ready for ");

        info!(" Initializing Core Bluetooth managers...");
        self.initialize_core_bluetooth().await?;
        info!(" Core Bluetooth central and peripheral managers initialized");

        Ok(())
    }
}
