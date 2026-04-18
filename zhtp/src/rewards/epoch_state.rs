//! Epoch state persistence — save/load dynamic pool and per-node accumulators.

use anyhow::Result;
use tracing::{debug, info};

use super::nai::EpochState;

/// Save epoch state to disk.
pub fn save_epoch_state(state: &EpochState, path: &std::path::Path) -> Result<()> {
    use std::io::Write;
    let encoded = bincode::serialize(state)
        .map_err(|e| anyhow::anyhow!("Failed to serialize epoch state: {}", e))?;
    let mut file = std::fs::File::create(path)?;
    file.write_all(&encoded)?;
    debug!(epoch = state.epoch, "Epoch state saved to {}", path.display());
    Ok(())
}

/// Load epoch state from disk.
pub fn load_epoch_state(path: &std::path::Path) -> Result<Option<EpochState>> {
    if !path.exists() {
        info!("No epoch state file at {} — starting fresh", path.display());
        return Ok(None);
    }
    let bytes = std::fs::read(path)?;
    let loaded: EpochState = bincode::deserialize(&bytes)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize epoch state: {}", e))?;
    info!(
        epoch = loaded.epoch,
        pool = loaded.epoch_pool,
        cap = loaded.per_node_cap,
        nodes = loaded.per_node_paid.len(),
        "Epoch state loaded from disk"
    );
    Ok(Some(loaded))
}

/// Derive the epoch state file path from a blockchain data path.
pub fn epoch_state_path(blockchain_dat: &std::path::Path) -> std::path::PathBuf {
    blockchain_dat
        .parent()
        .unwrap_or(std::path::Path::new("."))
        .join("epoch_state.dat")
}
