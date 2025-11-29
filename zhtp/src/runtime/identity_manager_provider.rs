use std::sync::{Arc, OnceLock};
use tokio::sync::RwLock;
use lib_identity::IdentityManager;
use anyhow::Result;
use tracing::info;

/// Global identity manager provider for shared access across components
/// This allows the protocols component to access the shared IdentityManager instance
/// that was initialized in IdentityComponent with genesis identities
#[derive(Debug, Clone)]
pub struct IdentityManagerProvider {
    identity_manager: Arc<RwLock<Option<Arc<RwLock<IdentityManager>>>>>,
}

impl IdentityManagerProvider {
    /// Create a new empty identity manager provider
    pub fn new() -> Self {
        Self {
            identity_manager: Arc::new(RwLock::new(None)),
        }
    }

    /// Set the identity manager instance
    pub async fn set_identity_manager(&self, identity_manager: Arc<RwLock<IdentityManager>>) -> Result<()> {
        *self.identity_manager.write().await = Some(identity_manager);
        info!("Global identity manager instance set");
        Ok(())
    }

    /// Get the identity manager instance
    pub async fn get_identity_manager(&self) -> Result<Arc<RwLock<IdentityManager>>> {
        self.identity_manager.read().await
            .as_ref()
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Identity manager not available"))
    }

    /// Check if identity manager is available
    pub async fn is_available(&self) -> bool {
        self.identity_manager.read().await.is_some()
    }
}

/// Global identity manager provider instance
static GLOBAL_IDENTITY_MANAGER_PROVIDER: OnceLock<IdentityManagerProvider> = OnceLock::new();

/// Initialize the global identity manager provider
pub fn initialize_global_identity_manager_provider() -> &'static IdentityManagerProvider {
    GLOBAL_IDENTITY_MANAGER_PROVIDER.get_or_init(|| {
        info!("Initializing global identity manager provider");
        IdentityManagerProvider::new()
    })
}

/// Get the global identity manager provider
pub fn get_global_identity_manager_provider() -> &'static IdentityManagerProvider {
    GLOBAL_IDENTITY_MANAGER_PROVIDER.get().unwrap_or_else(|| {
        initialize_global_identity_manager_provider()
    })
}

/// Set the global identity manager instance (called by IdentityComponent)
pub async fn set_global_identity_manager(identity_manager: Arc<RwLock<IdentityManager>>) -> Result<()> {
    let provider = get_global_identity_manager_provider();
    provider.set_identity_manager(identity_manager).await
}

/// Get the global identity manager instance (called by ProtocolsComponent and others)
pub async fn get_global_identity_manager() -> Result<Arc<RwLock<IdentityManager>>> {
    let provider = get_global_identity_manager_provider();
    provider.get_identity_manager().await
}
