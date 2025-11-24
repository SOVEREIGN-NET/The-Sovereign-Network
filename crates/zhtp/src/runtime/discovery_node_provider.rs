//! Global Discovery Node ID Provider
//!
//! Provides global access to the discovery node UUID used in Phase 1.
//! This prevents the unified server from discovering itself in Phase 4.

use anyhow::{Result, anyhow};
use std::sync::OnceLock;
use uuid::Uuid;
use tracing::info;

/// Global discovery node ID (set once during Phase 1)
static DISCOVERY_NODE_ID: OnceLock<Uuid> = OnceLock::new();

/// Set the global discovery node ID (called during Phase 1 discovery)
pub fn set_discovery_node_id(node_id: Uuid) -> Result<()> {
    DISCOVERY_NODE_ID.set(node_id)
        .map_err(|_| anyhow!("Discovery node ID already set"))?;
    info!(" Discovery node ID stored globally: {}", node_id);
    Ok(())
}

/// Get the global discovery node ID
pub fn get_discovery_node_id() -> Option<Uuid> {
    DISCOVERY_NODE_ID.get().copied()
}
