//! Core Bluetooth initialization helpers for macOS.

use anyhow::Result;
use tracing::info;

use std::sync::Arc;

use super::BluetoothMeshProtocol;

#[cfg(target_os = "macos")]
use super::macos_core::CoreBluetoothManager;

impl BluetoothMeshProtocol {
    /// Initialize Core Bluetooth on macOS
    #[cfg(target_os = "macos")]
    pub async fn initialize_core_bluetooth(&self) -> Result<()> {
        info!(" Initializing Core Bluetooth for macOS");

        let core_bt_manager = Arc::new(CoreBluetoothManager::new()?);

        core_bt_manager.initialize_central_manager().await?;
        core_bt_manager.initialize_peripheral_manager().await?;

        if let Some(tx) = self.gatt_message_tx.read().await.as_ref() {
            core_bt_manager.set_gatt_message_channel(tx.clone()).await;
        }

        info!(" Starting Core Bluetooth event loop...");
        core_bt_manager.start_event_loop().await?;
        info!(" Event loop started - delegate callbacks will now be processed");

        *self.core_bluetooth.write().await = Some(Arc::clone(&core_bt_manager));

        info!(" Core Bluetooth initialized successfully");
        Ok(())
    }
}
