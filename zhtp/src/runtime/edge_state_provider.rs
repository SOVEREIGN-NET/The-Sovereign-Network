use std::sync::{Arc, OnceLock};
use tokio::sync::RwLock;
use lib_blockchain::edge_node_state::EdgeNodeState;
use lib_blockchain::{BlockHeader, TransactionOutput, Hash};  // Need TransactionOutput and Hash for UTXO tracking
use anyhow::Result;
use tracing::info;

/// Global edge state provider for shared access across components
/// This allows the unified server to access the edge node state
/// without directly coupling to the BlockchainComponent
#[derive(Debug, Clone)]
pub struct EdgeStateProvider {
    edge_state: Arc<RwLock<Option<Arc<RwLock<EdgeNodeState>>>>>,
}

impl EdgeStateProvider {
    /// Create a new empty edge state provider
    pub fn new() -> Self {
        Self {
            edge_state: Arc::new(RwLock::new(None)),
        }
    }

    /// Set the edge state instance
    pub async fn set_edge_state(&self, edge_state: Arc<RwLock<EdgeNodeState>>) -> Result<()> {
        *self.edge_state.write().await = Some(edge_state);
        info!("Global edge state instance set");
        Ok(())
    }

    /// Get the edge state instance
    pub async fn get_edge_state(&self) -> Result<Arc<RwLock<EdgeNodeState>>> {
        self.edge_state.read().await
            .as_ref()
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Edge state not available (not an edge node)"))
    }

    /// Check if edge state is available
    pub async fn is_available(&self) -> bool {
        self.edge_state.read().await.is_some()
    }
}

/// Global edge state provider instance
static GLOBAL_EDGE_STATE_PROVIDER: OnceLock<EdgeStateProvider> = OnceLock::new();

/// Initialize the global edge state provider
pub fn initialize_global_edge_state_provider() -> &'static EdgeStateProvider {
    GLOBAL_EDGE_STATE_PROVIDER.get_or_init(|| {
        info!("Initializing global edge state provider");
        EdgeStateProvider::new()
    })
}

/// Get the global edge state provider
pub fn get_global_edge_state_provider() -> Option<&'static EdgeStateProvider> {
    GLOBAL_EDGE_STATE_PROVIDER.get()
}

/// Set the global edge state instance
pub async fn set_global_edge_state(edge_state: Arc<RwLock<EdgeNodeState>>) -> Result<()> {
    let provider = initialize_global_edge_state_provider();
    provider.set_edge_state(edge_state).await
}

/// Get the global edge state instance
pub async fn get_global_edge_state() -> Result<Arc<RwLock<EdgeNodeState>>> {
    let provider = get_global_edge_state_provider()
        .ok_or_else(|| anyhow::anyhow!("Global edge state provider not initialized"))?;
    provider.get_edge_state().await
}

/// Check if global edge state is available
pub async fn is_global_edge_state_available() -> bool {
    if let Some(provider) = get_global_edge_state_provider() {
        provider.is_available().await
    } else {
        false
    }
}

/// Add a block header to the global edge state
pub async fn add_header(header: BlockHeader) -> Result<()> {
    let edge_state = get_global_edge_state().await?;
    let mut edge_state_lock = edge_state.write().await;
    edge_state_lock.add_header(header)?;  // Propagate validation error
    Ok(())
}

/// Get the current height from the global edge state
pub async fn get_height() -> Result<u64> {
    let edge_state = get_global_edge_state().await?;
    let edge_state_lock = edge_state.read().await;
    Ok(edge_state_lock.current_height)
}

/// Get a header by height from the global edge state
pub async fn get_header(height: u64) -> Result<Option<BlockHeader>> {
    let edge_state = get_global_edge_state().await?;
    let edge_state_lock = edge_state.read().await;
    Ok(edge_state_lock.get_header_by_height(height).cloned())
}

/// Add a UTXO to the global edge state
pub async fn add_utxo(tx_hash: Hash, output_index: u32, output: TransactionOutput) -> Result<()> {
    let edge_state = get_global_edge_state().await?;
    let mut edge_state_lock = edge_state.write().await;
    edge_state_lock.add_utxo(tx_hash, output_index, &output);
    Ok(())
}

/// Remove a UTXO from the global edge state
pub async fn remove_utxo(tx_hash: &Hash, output_index: u32) -> Result<bool> {
    let edge_state = get_global_edge_state().await?;
    let mut edge_state_lock = edge_state.write().await;
    Ok(edge_state_lock.remove_utxo(tx_hash, output_index))
}

/// Add an address to track in the global edge state
pub async fn add_address(address: Vec<u8>) -> Result<()> {
    let edge_state = get_global_edge_state().await?;
    let mut edge_state_lock = edge_state.write().await;
    edge_state_lock.add_address(address);
    Ok(())
}

/// Get UTXO count from the global edge state
pub async fn get_utxo_count() -> Result<usize> {
    let edge_state = get_global_edge_state().await?;
    let edge_state_lock = edge_state.read().await;
    Ok(edge_state_lock.utxo_count())
}
