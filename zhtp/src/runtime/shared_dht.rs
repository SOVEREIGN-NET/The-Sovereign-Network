//! Shared DHT Instance Manager
//!
//! Provides a singleton DHT client that can be shared across all components
//! to prevent multiple initialization and port conflicts.

use crate::integration::dht_adapter::DhtIntegrationAdapter;
use anyhow::Result;
use lib_identity::ZhtpIdentity;
use std::sync::Arc;
use tokio::sync::{OnceCell, RwLock};
use tracing::{debug, info};

/// Global DHT instance manager - wrapped in RwLock for mutable access
static GLOBAL_DHT: OnceCell<Arc<RwLock<Option<Arc<RwLock<DhtIntegrationAdapter>>>>>> =
    OnceCell::const_new();

/// Initialize the global DHT instance (singleton with proper guards)
/// This should be called once at application startup
pub async fn initialize_global_dht(identity: ZhtpIdentity) -> Result<()> {
    let dht_container = GLOBAL_DHT
        .get_or_init(|| async { Arc::new(RwLock::new(None)) })
        .await;

    let mut dht_guard = dht_container.write().await;

    // Check if DHT is already initialized
    if dht_guard.is_some() {
        debug!("DHT already initialized, skipping duplicate initialization");
        return Ok(());
    }

    info!("Initializing global DHT client instance (singleton)");

    // Create the DHT client (uses lib-storage backend)
    let mut dht_client = DhtIntegrationAdapter::new();
    dht_client.initialize(identity).await?;

    // Store in global container wrapped in Arc<RwLock<_>> for mutable access
    *dht_guard = Some(Arc::new(RwLock::new(dht_client)));

    info!("Global DHT instance initialized successfully");
    Ok(())
}

/// Initialize DHT if not already initialized (safe wrapper)
pub async fn initialize_global_dht_safe(identity: ZhtpIdentity) -> Result<()> {
    if is_dht_initialized().await {
        debug!("DHT already initialized, skipping");
        return Ok(());
    }

    initialize_global_dht(identity).await
}

/// Get a reference to the global DHT instance
/// Returns None if not yet initialized
pub async fn get_global_dht() -> Option<Arc<RwLock<Option<Arc<RwLock<DhtIntegrationAdapter>>>>>> {
    GLOBAL_DHT.get().cloned()
}

/// Get a clone of the DHT client for use in operations
/// Returns Arc<RwLock<DhtIntegrationAdapter>> to allow mutable access when needed
pub async fn get_dht_client() -> Result<Arc<RwLock<DhtIntegrationAdapter>>> {
    let dht_container = get_global_dht().await.ok_or_else(|| {
        anyhow::anyhow!("DHT not initialized - call initialize_global_dht() first")
    })?;

    let dht_guard = dht_container.read().await;

    match dht_guard.as_ref() {
        Some(dht_client) => {
            debug!("Retrieved shared DHT client instance");
            Ok(dht_client.clone())
        }
        None => Err(anyhow::anyhow!("DHT container exists but client is None")),
    }
}

/// Check if the global DHT is initialized
pub async fn is_dht_initialized() -> bool {
    if let Some(dht_container) = get_global_dht().await {
        let dht_guard = dht_container.read().await;
        dht_guard.is_some()
    } else {
        false
    }
}

/// Shutdown the global DHT instance
pub async fn shutdown_global_dht() -> Result<()> {
    if let Some(dht_container) = get_global_dht().await {
        let mut dht_guard = dht_container.write().await;
        if let Some(dht_client) = dht_guard.take() {
            info!(" Shutting down global DHT instance");
            // DHT client will be dropped and cleaned up automatically
            drop(dht_client);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use lib_identity::ZhtpIdentity;

    #[tokio::test]
    async fn test_dht_singleton_pattern() {
        // Create test identity using P1-7 architecture
        let identity = ZhtpIdentity::new_unified(
            lib_identity::IdentityType::Device,
            None, // No age for device
            None, // No jurisdiction for device
            "test-dht-device",
            None, // Random seed
        )
        .ok();

        // Test initialization
        assert!(!is_dht_initialized().await);

        initialize_global_dht(identity.clone()).await.ok();

        assert!(is_dht_initialized().await);

        // Test duplicate initialization (should be ignored)
        initialize_global_dht(identity.clone()).await.ok();

        // Test getting client
        let _dht_client = get_dht_client().await.ok();

        // Test shutdown
        shutdown_global_dht().await.ok();

        // Note: We can't easily test if it's uninitialized due to OnceCell behavior
    }
}
