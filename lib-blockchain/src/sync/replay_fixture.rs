//! Versioned replay block fixtures for GENESIS-2 manual gates (#2730).

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::block::Block;

/// Fixture format version — bump when `ReplayBlocksFixture` layout changes.
pub const REPLAY_BLOCKS_FIXTURE_VERSION: u32 = 1;

/// Maximum fixture file size (512 MiB) — guards against OOM on malformed/truncated input.
pub const MAX_REPLAY_FIXTURE_BYTES: usize = 512 * 1024 * 1024;

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

    /// Decode and validate version + size bound. Prefer this over raw `bincode::deserialize`.
    pub fn decode_validated(data: &[u8]) -> anyhow::Result<Self> {
        anyhow::ensure!(
            data.len() <= MAX_REPLAY_FIXTURE_BYTES,
            "fixture too large ({} bytes, max {})",
            data.len(),
            MAX_REPLAY_FIXTURE_BYTES
        );
        let fixture: Self = bincode::deserialize(data)
            .map_err(|e| anyhow::anyhow!("replay fixture decode failed: {e}"))?;
        anyhow::ensure!(
            fixture.version == REPLAY_BLOCKS_FIXTURE_VERSION,
            "unsupported fixture version {} (expected {})",
            fixture.version,
            REPLAY_BLOCKS_FIXTURE_VERSION
        );
        Ok(fixture)
    }

    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let meta = std::fs::metadata(path)?;
        anyhow::ensure!(
            meta.len() as usize <= MAX_REPLAY_FIXTURE_BYTES,
            "fixture file too large ({} bytes, max {})",
            meta.len(),
            MAX_REPLAY_FIXTURE_BYTES
        );
        let data = std::fs::read(path)?;
        Self::decode_validated(&data)
    }

    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        std::fs::write(path, self.encode()?)?;
        Ok(())
    }
}