//! Fork detection compatibility types.
//!
//! Reorg handling was removed for BFT-only operation, but these lightweight
//! types are retained so integration code can compile while migration completes.

use crate::types::Hash;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ForkResolution {
    SwitchedToFork,
    KeptCanonical,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ForkDetection {
    pub height: u64,
    pub existing_hash: Hash,
    pub new_hash: Hash,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ForkPoint {
    pub height: u64,
    pub timestamp: u64,
    pub original_hash: Hash,
    pub forked_hash: Hash,
    pub resolution: ForkResolution,
}

impl ForkPoint {
    pub fn new(
        height: u64,
        timestamp: u64,
        original_hash: Hash,
        forked_hash: Hash,
        resolution: ForkResolution,
    ) -> Self {
        Self {
            height,
            timestamp,
            original_hash,
            forked_hash,
            resolution,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForkRecoveryConfig {
    pub max_reorg_depth: u64,
}

impl Default for ForkRecoveryConfig {
    fn default() -> Self {
        Self { max_reorg_depth: 100 }
    }
}
