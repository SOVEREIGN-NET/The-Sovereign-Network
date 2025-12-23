//! GATT backend abstraction for testing without platform BLE stacks.

use anyhow::Result;
use async_trait::async_trait;

#[cfg(any(test, feature = "ble-mock"))]
use std::sync::Arc;

#[cfg(any(test, feature = "ble-mock"))]
use super::BluetoothMeshProtocol;

#[async_trait]
pub trait GattBackend: Send + Sync {
    async fn read_characteristic(&self, device_address: &str, char_uuid: &str) -> Result<Vec<u8>>;
    async fn write_characteristic(
        &self,
        device_address: &str,
        char_uuid: &str,
        data: &[u8],
    ) -> Result<()>;
    async fn discover_services(&self, device_address: &str) -> Result<Vec<String>>;
    async fn enable_notifications(&self, device_address: &str, char_uuid: &str) -> Result<()>;
    async fn disable_notifications(&self, device_address: &str, char_uuid: &str) -> Result<()>;
    async fn wait_for_notification(
        &self,
        device_address: &str,
        char_uuid: &str,
    ) -> Result<Vec<u8>>;
}

#[cfg(any(test, feature = "ble-mock"))]
impl BluetoothMeshProtocol {
    pub async fn set_gatt_backend(&self, backend: Arc<dyn GattBackend>) {
        *self.gatt_backend.write().await = Some(backend);
    }

    pub(crate) async fn gatt_backend(&self) -> Option<Arc<dyn GattBackend>> {
        self.gatt_backend.read().await.clone()
    }
}
