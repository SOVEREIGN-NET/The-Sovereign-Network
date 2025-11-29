//! Self-healing mechanisms

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use crate::integrity::ErasureParams;
use crate::erasure::ErasureCoding;

/// Self-healing system
pub struct SelfHealing {
    /// Maximum repair attempts
    max_repair_attempts: usize,
}

impl SelfHealing {
    pub fn new() -> Self {
        Self {
            max_repair_attempts: 3,
        }
    }

    /// Heal corrupted blocks using erasure codes
    pub fn heal_blocks(
        &self,
        blocks: &mut [Vec<u8>],
        parity_blocks: &[Vec<u8>],
        corrupted_indices: &[usize],
        erasure_params: &ErasureParams,
    ) -> Result<HealingResult> {
        if corrupted_indices.is_empty() {
            return Ok(HealingResult::NoHealingNeeded);
        }

        // Check if we can recover
        if corrupted_indices.len() > erasure_params.parity_shards {
            return Ok(HealingResult::Unrecoverable(
                format!(
                    "Too many corrupted blocks: {} corrupted, {} parity shards",
                    corrupted_indices.len(),
                    erasure_params.parity_shards
                )
            ));
        }

        // Attempt recovery using erasure codes
        let erasure_coder = ErasureCoding::new(
            erasure_params.data_shards,
            erasure_params.parity_shards,
        )?;

        // Combine data and parity blocks for repair
        let shard_size = blocks.first().map(|b| b.len()).unwrap_or(0);
        let mut all_shards = crate::erasure::EncodedShards {
            data_shards: blocks.to_vec(),
            parity_shards: parity_blocks.to_vec(),
            shard_size,
            original_size: shard_size * erasure_params.data_shards,
        };

        // Attempt repair
        match erasure_coder.repair_shards(&mut all_shards, corrupted_indices) {
            Ok(_) => {
                // Copy repaired blocks back
                for &idx in corrupted_indices {
                    if idx < blocks.len() {
                        blocks[idx] = all_shards.data_shards[idx].clone();
                    }
                }
                
                Ok(HealingResult::Healed {
                    repaired_blocks: corrupted_indices.len(),
                    attempts: 1,
                })
            }
            Err(e) => Ok(HealingResult::Failed(format!("Repair failed: {}", e))),
        }
    }

    /// Heal a single block using erasure coding
    pub fn heal_single_block(
        &self,
        block_index: usize,
        all_blocks: &[Vec<u8>],
        parity_blocks: &[Vec<u8>],
        erasure_params: &ErasureParams,
    ) -> Result<Vec<u8>> {
        // Validate inputs
        if block_index >= all_blocks.len() {
            return Err(anyhow!("Block index {} out of range (total: {})", block_index, all_blocks.len()));
        }

        // Create erasure coder from params
        let erasure_coder = ErasureCoding::new(
            erasure_params.data_shards,
            erasure_params.parity_shards,
        )?;

        // Prepare shards structure (same as heal_blocks)
        let shard_size = all_blocks.first().map(|b| b.len()).unwrap_or(0);
        let mut all_shards = crate::erasure::EncodedShards {
            data_shards: all_blocks.to_vec(),
            parity_shards: parity_blocks.to_vec(),
            shard_size,
            original_size: shard_size * erasure_params.data_shards,
        };

        // Mark the corrupted block for repair
        let corrupted_indices = vec![block_index];

        // Repair using erasure coding
        erasure_coder.repair_shards(&mut all_shards, &corrupted_indices)?;

        // Extract and return the repaired block
        if block_index < all_shards.data_shards.len() {
            Ok(all_shards.data_shards[block_index].clone())
        } else {
            Err(anyhow!("Failed to extract repaired block at index {}", block_index))
        }
    }
}

impl Default for SelfHealing {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of healing attempt
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HealingResult {
    /// No healing was needed
    NoHealingNeeded,
    /// Successfully healed
    Healed {
        repaired_blocks: usize,
        attempts: usize,
    },
    /// Healing failed
    Failed(String),
    /// Unrecoverable corruption
    Unrecoverable(String),
}

impl HealingResult {
    pub fn is_success(&self) -> bool {
        matches!(self, HealingResult::NoHealingNeeded | HealingResult::Healed { .. })
    }

    pub fn is_failure(&self) -> bool {
        !self.is_success()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_self_healing_creation() {
        let healer = SelfHealing::new();
        assert_eq!(healer.max_repair_attempts, 3);
    }

    #[test]
    fn test_healing_result() {
        let result = HealingResult::NoHealingNeeded;
        assert!(result.is_success());

        let result = HealingResult::Failed("test".to_string());
        assert!(result.is_failure());
    }
}
