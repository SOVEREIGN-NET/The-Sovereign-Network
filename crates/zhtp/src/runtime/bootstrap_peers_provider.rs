//! Bootstrap Peers Provider - Global access to discovered bootstrap peers
//! 
//! This module provides a singleton access pattern for bootstrap peers discovered
//! during network join. The UnifiedServer can access these peers to initiate
//! outgoing connections for blockchain sync.

use tokio::sync::RwLock;
use anyhow::Result;
use once_cell::sync::Lazy;

/// Global bootstrap peers storage
static BOOTSTRAP_PEERS: Lazy<RwLock<Option<Vec<String>>>> = Lazy::new(|| RwLock::new(None));

/// Set the global bootstrap peers (called after discovery)
pub async fn set_bootstrap_peers(peers: Vec<String>) -> Result<()> {
    *BOOTSTRAP_PEERS.write().await = Some(peers);
    Ok(())
}

/// Get the global bootstrap peers (called by UnifiedServer)
pub async fn get_bootstrap_peers() -> Option<Vec<String>> {
    let guard = BOOTSTRAP_PEERS.read().await;
    guard.as_ref().cloned()
}

/// Clear the bootstrap peers (after successful connection)
pub async fn clear_bootstrap_peers() {
    *BOOTSTRAP_PEERS.write().await = None;
}
