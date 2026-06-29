//! Versioned replay block fixtures for GENESIS-2 manual gates (#2730).

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::block::Block;

/// Fixture format version — bump when `ReplayBlocksFixture` layout changes.
pub const REPLAY_BLOCKS_FIXTURE_VERSION: u32 = 1;

/// g4 wipe-and-replay first wedged here (Insufficient SOV @ payroll). Floor for manual gates.
pub const G4_CHECKPOINT_HEIGHT_FLOOR: u64 = 74_010;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayBlocksFixture {
    pub version: u32,
    pub exported_to_height: u64,
    pub blocks: Vec<Block>,
}

impl ReplayBlocksFixture {
    pub fn encode(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(self)
    }

    pub fn decode(data: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(data)
    }

    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let data = std::fs::read(path)?;
        Self::decode(&data).map_err(|e| {
            anyhow::anyhow!(
                "replay fixture decode failed (version mismatch or corrupt file): {e}"
            )
        })
    }

    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        std::fs::write(path, self.encode()?)?;
        Ok(())
    }
}