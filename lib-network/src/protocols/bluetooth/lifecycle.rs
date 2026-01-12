//! Lifecycle helpers for Bluetooth mesh protocol.

use anyhow::Result;
use tracing::info;

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use super::{config, gatt};
use super::BluetoothMeshProtocol;
use super::common::get_system_bluetooth_mac;
use super::gatt::GattMessage;

impl BluetoothMeshProtocol {
    /// Create new Bluetooth LE mesh protocol
    pub fn new(node_id: [u8; 32], public_key: lib_crypto::PublicKey) -> Result<Self> {
        let device_id = get_system_bluetooth_mac()?;

        Ok(BluetoothMeshProtocol {
            node_id,
            public_key,
            device_id,
            advertising_interval: config::DEFAULT_ADVERTISING_INTERVAL_MS,
            connection_interval: config::DEFAULT_CONNECTION_INTERVAL_UNITS,
            max_connections: config::DEFAULT_MAX_CONNECTIONS,
            current_connections: Arc::new(RwLock::new(HashMap::new())),
            discovery_active: false,
            enabled: true,  // Default to enabled; mesh server will set to false if config disables it
            tracked_devices: Arc::new(RwLock::new(HashMap::new())),
            address_mapping: Arc::new(RwLock::new(HashMap::new())),
            zhtp_monitor_active: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            auth_manager: Arc::new(RwLock::new(None)),
            authenticated_peers: Arc::new(RwLock::new(HashMap::new())),
            #[cfg(target_os = "windows")]
            gatt_service_provider: Arc::new(RwLock::new(None)),
            #[cfg(any(test, feature = "ble-mock"))]
            gatt_backend: Arc::new(RwLock::new(None)),
            #[cfg(target_os = "windows")]
            ble_advertiser: Arc::new(RwLock::new(None)),
            gatt_message_tx: Arc::new(RwLock::new(None)),
            #[cfg(target_os = "macos")]
            core_bluetooth: Arc::new(RwLock::new(None)),
            blockchain_provider: Arc::new(RwLock::new(None)),
            fragment_reassembler: Arc::new(RwLock::new(gatt::FragmentReassembler::new())),
        })
    }

    /// Set blockchain provider for serving edge node sync requests
    pub async fn set_blockchain_provider(
        &self,
        provider: Arc<dyn crate::blockchain_sync::BlockchainProvider>,
    ) {
        *self.blockchain_provider.write().await = Some(provider);
        info!(" Blockchain provider configured for BLE edge sync");
    }

    /// Set the GATT message channel for forwarding to unified server
    pub async fn set_gatt_message_channel(
        &self,
        tx: tokio::sync::mpsc::UnboundedSender<GattMessage>,
    ) {
        *self.gatt_message_tx.write().await = Some(tx);
        info!(" GATT message channel configured");
    }

    /// Set whether Bluetooth is enabled (SAFETY: defensive configuration)
    /// Called by mesh server after filtering based on config.toml
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
        if !enabled {
            info!("⊘ Bluetooth LE disabled by configuration - discovery will be refused if attempted");
        }
    }
}
