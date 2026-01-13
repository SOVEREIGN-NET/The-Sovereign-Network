//! Global storage provider for shared access across components
//!
//! This allows components to share a single PersistentStorageSystem instance,
//! avoiding sled database lock conflicts.

use std::sync::OnceLock;
use std::sync::Arc;
use tokio::sync::RwLock;
use lib_storage::PersistentStorageSystem;
use anyhow::Result;
use tracing::info;

/// Global storage provider instance
static GLOBAL_STORAGE: OnceLock<Arc<RwLock<Option<Arc<RwLock<PersistentStorageSystem>>>>>> = OnceLock::new();

fn get_storage_holder() -> &'static Arc<RwLock<Option<Arc<RwLock<PersistentStorageSystem>>>>> {
    GLOBAL_STORAGE.get_or_init(|| Arc::new(RwLock::new(None)))
}

/// Set the global storage instance (called by StorageComponent after initialization)
pub async fn set_global_storage(storage: Arc<RwLock<PersistentStorageSystem>>) -> Result<()> {
    let holder = get_storage_holder();
    *holder.write().await = Some(storage);
    info!("Global storage instance set");
    Ok(())
}

/// Get the global storage instance
pub async fn get_global_storage() -> Result<Arc<RwLock<PersistentStorageSystem>>> {
    let holder = get_storage_holder();
    holder.read().await
        .as_ref()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("Global storage not initialized"))
}

/// Check if global storage is available
pub async fn is_global_storage_available() -> bool {
    let holder = get_storage_holder();
    holder.read().await.is_some()
}
