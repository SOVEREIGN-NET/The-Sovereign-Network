use crate::Blockchain;
use std::sync::Arc;
use tokio::sync::RwLock;
use once_cell::sync::OnceCell;
use anyhow::{Result, Context};

/// Global shared blockchain provider
static GLOBAL_BLOCKCHAIN: OnceCell<Arc<RwLock<Blockchain>>> = OnceCell::new();

/// Initialize the global blockchain provider with a blockchain instance
pub async fn initialize_global_blockchain_provider(blockchain: Blockchain) -> Result<()> {
    let shared_blockchain = Arc::new(RwLock::new(blockchain));
    
    GLOBAL_BLOCKCHAIN.set(shared_blockchain.clone())
        .map_err(|_| anyhow::anyhow!("Global blockchain provider already initialized"))?;
    
    tracing::info!("Global blockchain provider initialized successfully");
    Ok(())
}

/// Set or update the global blockchain instance
pub async fn set_global_blockchain(blockchain: Blockchain) -> Result<()> {
    match GLOBAL_BLOCKCHAIN.get() {
        Some(shared_blockchain) => {
            let mut guard = shared_blockchain.write().await;
            *guard = blockchain;
            tracing::info!(" Global blockchain instance updated");
            Ok(())
        }
        None => {
            // Initialize if not already done
            initialize_global_blockchain_provider(blockchain).await
        }
    }
}

/// Get access to the global blockchain instance
pub async fn get_global_blockchain() -> Result<Arc<RwLock<Blockchain>>> {
    GLOBAL_BLOCKCHAIN.get()
        .ok_or_else(|| anyhow::anyhow!("Global blockchain provider not initialized"))
        .map(|blockchain| blockchain.clone())
}

/// Check if global blockchain provider is initialized
pub fn is_global_blockchain_initialized() -> bool {
    GLOBAL_BLOCKCHAIN.get().is_some()
}

/// Reset the global blockchain provider (useful for testing)
pub fn reset_global_blockchain_provider() {
    // Note: OnceCell doesn't support reset, so this is primarily for documentation
    // In practice, you'd need to restart the application to truly reset
    tracing::warn!("Global blockchain provider reset requested - requires application restart");
}
