use std::sync::Arc;
use tokio::sync::RwLock;
use lib_blockchain::Blockchain;
use anyhow::Result;

/// Blockchain factory that provides either shared or isolated blockchain instances
/// This allows us to patch the protocols component to use shared blockchain
/// without modifying the lib-protocols source code
pub struct BlockchainFactory;

impl BlockchainFactory {
    /// Create a blockchain instance - will try to use shared instance first
    pub async fn create_blockchain() -> Result<Blockchain> {
        // Try to get the global blockchain first
        if let Ok(shared_blockchain) = crate::runtime::blockchain_provider::get_global_blockchain() {
            // Clone the blockchain state for isolated operations
            // This is a temporary approach - ideally we'd want to share the actual instance
            let blockchain_guard = shared_blockchain.read().await;
            if let Some(shared_state) = blockchain_guard.get_blockchain_state() {
                // Create a new blockchain with the same state
                let mut new_blockchain = Blockchain::new()?;
                new_blockchain.restore_state(shared_state)?;
                
                log::info!("Created blockchain instance from shared state");
                return Ok(new_blockchain);
            }
        }
        
        // Fall back to creating a new blockchain instance
        log::warn!("Falling back to isolated blockchain instance - shared blockchain not available");
        Blockchain::new()
    }
    
    /// Create a blockchain instance that shares the global state
    pub async fn create_shared_blockchain() -> Result<Arc<RwLock<Blockchain>>> {
        // Return the global blockchain if available
        if let Ok(shared_blockchain) = crate::runtime::blockchain_provider::get_global_blockchain() {
            log::info!("Using shared blockchain instance");
            return Ok(shared_blockchain);
        }
        
        // Create a new blockchain and register it globally
        let blockchain = Blockchain::new()?;
        let blockchain_arc = Arc::new(RwLock::new(blockchain));
        
        if let Err(e) = crate::runtime::blockchain_provider::set_global_blockchain(blockchain_arc.clone()) {
            log::warn!("Failed to register new blockchain as global: {}", e);
        } else {
            log::info!("Created and registered new shared blockchain");
        }
        
        Ok(blockchain_arc)
    }
}

/// Patch function to replace Blockchain::new() calls in protocols
/// This can be used as a drop-in replacement
pub async fn create_patched_blockchain() -> Result<Blockchain> {
    BlockchainFactory::create_blockchain().await
}

/// Get the shared blockchain instance for direct access
pub async fn get_shared_blockchain_instance() -> Result<Arc<RwLock<Blockchain>>> {
    BlockchainFactory::create_shared_blockchain().await
}
