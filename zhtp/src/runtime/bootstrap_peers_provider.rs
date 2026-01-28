//! Bootstrap Peers Provider - Global access to discovered bootstrap peers
//!
//! This module provides a singleton access pattern for bootstrap peers discovered
//! during network join. The UnifiedServer can access these peers to initiate
//! outgoing connections for blockchain sync.

use std::collections::HashMap;
use tokio::sync::RwLock;
use anyhow::Result;
use once_cell::sync::Lazy;

/// Global bootstrap peers storage
static BOOTSTRAP_PEERS: Lazy<RwLock<Option<Vec<String>>>> = Lazy::new(|| RwLock::new(None));

/// Global bootstrap peer SPKI pins storage (hex-encoded SHA-256)
/// Key = "host:port", Value = hex-encoded 64-char SHA-256 hash
static BOOTSTRAP_PEER_PINS: Lazy<RwLock<Option<HashMap<String, String>>>> = Lazy::new(|| RwLock::new(None));

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

/// Set the global bootstrap peer SPKI pins (called from runtime after config load)
pub async fn set_bootstrap_peer_pins(pins: HashMap<String, String>) {
    *BOOTSTRAP_PEER_PINS.write().await = Some(pins);
}

/// Get the global bootstrap peer SPKI pins (called by UnifiedServer)
pub async fn get_bootstrap_peer_pins() -> Option<HashMap<String, String>> {
    let guard = BOOTSTRAP_PEER_PINS.read().await;
    guard.as_ref().cloned()
}
