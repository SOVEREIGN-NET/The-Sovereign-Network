//! Data Integrity Layer
//!
//! Provides checksum management, corruption detection, and self-healing mechanisms
//! for stored data using lib-crypto hashing and erasure codes.

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use lib_crypto::hashing::{hash_blake3, hash_blake3_multiple};

pub mod checksum;
pub mod corruption;
pub mod healing;
pub mod verification;

// Re-export key types
pub use checksum::{ChecksumAlgorithm, ChecksumManager, Checksum};
pub use corruption::{CorruptionDetector, CorruptionReport};
pub use healing::{SelfHealing, HealingResult};
pub use verification::{IntegrityVerifier, VerificationReport};

/// Integrity check result for a piece of data
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IntegrityStatus {
    /// Data is intact and valid
    Valid,
    /// Data is corrupted with specific issues
    Corrupted(Vec<CorruptionIssue>),
    /// Data is missing or unavailable
    Missing,
    /// Checksum mismatch
    ChecksumMismatch,
}

impl IntegrityStatus {
    pub fn is_valid(&self) -> bool {
        matches!(self, IntegrityStatus::Valid)
    }

    pub fn is_corrupted(&self) -> bool {
        matches!(self, IntegrityStatus::Corrupted(_))
    }
}

/// Specific corruption issue detected
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorruptionIssue {
    /// Type of corruption
    pub issue_type: CorruptionType,
    /// Block index where corruption was found
    pub block_index: usize,
    /// Expected checksum
    pub expected_checksum: Option<[u8; 32]>,
    /// Actual checksum
    pub actual_checksum: Option<[u8; 32]>,
    /// Additional details
    pub details: String,
}

/// Type of corruption detected
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CorruptionType {
    /// Checksum mismatch
    ChecksumMismatch,
    /// Block is missing
    MissingBlock,
    /// Block size mismatch
    SizeMismatch,
    /// Invalid block format
    InvalidFormat,
    /// Bit flip or partial corruption
    BitCorruption,
}

/// Integrity metadata for stored content
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityMetadata {
    /// Content identifier
    pub content_id: String,
    /// Overall checksum of entire content
    pub content_checksum: [u8; 32],
    /// Checksums for individual blocks
    pub block_checksums: Vec<[u8; 32]>,
    /// Block size in bytes
    pub block_size: usize,
    /// Total blocks
    pub total_blocks: usize,
    /// Last integrity check timestamp
    pub last_check: u64,
    /// Checksum algorithm used
    pub algorithm: ChecksumAlgorithm,
    /// Erasure coding parameters
    pub erasure_params: Option<ErasureParams>,
}

/// Erasure coding parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErasureParams {
    /// Data shards
    pub data_shards: usize,
    /// Parity shards
    pub parity_shards: usize,
    /// Total shards
    pub total_shards: usize,
}

impl IntegrityMetadata {
    /// Create new integrity metadata
    pub fn new(
        content_id: String,
        blocks: &[Vec<u8>],
        algorithm: ChecksumAlgorithm,
    ) -> Self {
        let block_checksums: Vec<[u8; 32]> = blocks
            .iter()
            .map(|block| hash_blake3(block))
            .collect();

        // Compute overall content checksum from all block checksums
        let all_checksums: Vec<&[u8]> = block_checksums
            .iter()
            .map(|c| c.as_slice())
            .collect();
        let content_checksum = hash_blake3_multiple(&all_checksums);

        let block_size = if blocks.is_empty() { 0 } else { blocks[0].len() };

        Self {
            content_id,
            content_checksum,
            block_checksums,
            block_size,
            total_blocks: blocks.len(),
            last_check: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            algorithm,
            erasure_params: None,
        }
    }

    /// Add erasure coding parameters
    pub fn with_erasure_params(mut self, data_shards: usize, parity_shards: usize) -> Self {
        self.erasure_params = Some(ErasureParams {
            data_shards,
            parity_shards,
            total_shards: data_shards + parity_shards,
        });
        self
    }

    /// Update last check timestamp
    pub fn update_check_time(&mut self) {
        self.last_check = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }

    /// Check if metadata indicates erasure coding is enabled
    pub fn has_erasure_coding(&self) -> bool {
        self.erasure_params.is_some()
    }

    /// Get time since last integrity check in seconds
    pub fn time_since_last_check(&self) -> u64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now.saturating_sub(self.last_check)
    }
}

/// Integrity manager for coordinating integrity operations
pub struct IntegrityManager {
    /// Checksum manager
    checksum_manager: ChecksumManager,
    /// Corruption detector
    corruption_detector: CorruptionDetector,
    /// Self-healing system
    self_healing: SelfHealing,
    /// Integrity metadata for all content
    metadata: HashMap<String, IntegrityMetadata>,
    /// Background check interval in seconds
    check_interval: u64,
}

impl IntegrityManager {
    /// Create a new integrity manager
    pub fn new(check_interval: u64) -> Self {
        Self {
            checksum_manager: ChecksumManager::new(),
            corruption_detector: CorruptionDetector::new(),
            self_healing: SelfHealing::new(),
            metadata: HashMap::new(),
            check_interval,
        }
    }

    /// Register content with integrity tracking
    pub fn register_content(
        &mut self,
        content_id: String,
        blocks: &[Vec<u8>],
        algorithm: ChecksumAlgorithm,
    ) -> IntegrityMetadata {
        let metadata = IntegrityMetadata::new(content_id.clone(), blocks, algorithm);
        self.metadata.insert(content_id, metadata.clone());
        metadata
    }

    /// Register content with erasure coding
    pub fn register_content_with_erasure(
        &mut self,
        content_id: String,
        blocks: &[Vec<u8>],
        algorithm: ChecksumAlgorithm,
        data_shards: usize,
        parity_shards: usize,
    ) -> IntegrityMetadata {
        let metadata = IntegrityMetadata::new(content_id.clone(), blocks, algorithm)
            .with_erasure_params(data_shards, parity_shards);
        self.metadata.insert(content_id, metadata.clone());
        metadata
    }

    /// Verify integrity of content
    pub fn verify_content(
        &mut self,
        content_id: &str,
        blocks: &[Vec<u8>],
    ) -> Result<IntegrityStatus> {
        let metadata = self.metadata
            .get(content_id)
            .ok_or_else(|| anyhow!("Content not registered"))?;

        // Check block count matches
        if blocks.len() != metadata.total_blocks {
            return Ok(IntegrityStatus::Corrupted(vec![CorruptionIssue {
                issue_type: CorruptionType::MissingBlock,
                block_index: 0,
                expected_checksum: None,
                actual_checksum: None,
                details: format!(
                    "Expected {} blocks, found {}",
                    metadata.total_blocks,
                    blocks.len()
                ),
            }]));
        }

        // Verify each block
        let mut issues = Vec::new();
        for (i, block) in blocks.iter().enumerate() {
            let expected_checksum = metadata.block_checksums[i];
            let actual_checksum = hash_blake3(block);

            if actual_checksum != expected_checksum {
                issues.push(CorruptionIssue {
                    issue_type: CorruptionType::ChecksumMismatch,
                    block_index: i,
                    expected_checksum: Some(expected_checksum),
                    actual_checksum: Some(actual_checksum),
                    details: format!("Block {} checksum mismatch", i),
                });
            }
        }

        // Update last check time
        if let Some(meta) = self.metadata.get_mut(content_id) {
            meta.update_check_time();
        }

        if issues.is_empty() {
            Ok(IntegrityStatus::Valid)
        } else {
            Ok(IntegrityStatus::Corrupted(issues))
        }
    }

    /// Attempt to heal corrupted content
    pub fn heal_content(
        &mut self,
        content_id: &str,
        blocks: &mut [Vec<u8>],
        parity_blocks: &[Vec<u8>],
    ) -> Result<HealingResult> {
        // Get metadata and check erasure coding in separate scope
        let has_erasure = self.metadata
            .get(content_id)
            .ok_or_else(|| anyhow!("Content not registered"))?
            .has_erasure_coding();

        if !has_erasure {
            return Err(anyhow!("Content does not have erasure coding enabled"));
        }

        // Detect corrupted blocks
        let status = self.verify_content(content_id, blocks)?;
        
        match status {
            IntegrityStatus::Valid => Ok(HealingResult::NoHealingNeeded),
            IntegrityStatus::Corrupted(issues) => {
                // Extract corrupted block indices
                let corrupted_indices: Vec<usize> = issues
                    .iter()
                    .map(|issue| issue.block_index)
                    .collect();

                // Get erasure params (need to clone to avoid borrow issues)
                let erasure_params = self.metadata
                    .get(content_id)
                    .unwrap()
                    .erasure_params
                    .as_ref()
                    .unwrap()
                    .clone();

                // Attempt healing using erasure codes
                self.self_healing.heal_blocks(
                    blocks,
                    parity_blocks,
                    &corrupted_indices,
                    &erasure_params,
                )
            }
            _ => Err(anyhow!("Cannot heal missing content")),
        }
    }

    /// Get integrity metadata for content
    pub fn get_metadata(&self, content_id: &str) -> Option<&IntegrityMetadata> {
        self.metadata.get(content_id)
    }

    /// List content that needs integrity check
    pub fn list_content_needing_check(&self) -> Vec<String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        self.metadata
            .iter()
            .filter(|(_, meta)| now > meta.last_check + self.check_interval)
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Get integrity statistics
    pub fn get_stats(&self) -> IntegrityStats {
        let total_content = self.metadata.len();
        let with_erasure = self.metadata
            .values()
            .filter(|m| m.has_erasure_coding())
            .count();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let needs_check = self.metadata
            .values()
            .filter(|m| now > m.last_check + self.check_interval)
            .count();

        IntegrityStats {
            total_content,
            with_erasure_coding: with_erasure,
            needs_integrity_check: needs_check,
            total_blocks: self.metadata.values().map(|m| m.total_blocks).sum(),
        }
    }

    /// Remove content from tracking
    pub fn unregister_content(&mut self, content_id: &str) -> Option<IntegrityMetadata> {
        self.metadata.remove(content_id)
    }
}

impl Default for IntegrityManager {
    fn default() -> Self {
        Self::new(3600) // Check every hour
    }
}

/// Integrity statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityStats {
    pub total_content: usize,
    pub with_erasure_coding: usize,
    pub needs_integrity_check: usize,
    pub total_blocks: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_integrity_metadata_creation() {
        let blocks = vec![
            b"block0".to_vec(),
            b"block1".to_vec(),
            b"block2".to_vec(),
        ];

        let metadata = IntegrityMetadata::new(
            "test_content".to_string(),
            &blocks,
            ChecksumAlgorithm::Blake3,
        );

        assert_eq!(metadata.total_blocks, 3);
        assert_eq!(metadata.block_checksums.len(), 3);
        assert_eq!(metadata.block_size, 6);
    }

    #[test]
    fn test_integrity_metadata_with_erasure() {
        let blocks = vec![b"block0".to_vec()];
        let metadata = IntegrityMetadata::new(
            "test".to_string(),
            &blocks,
            ChecksumAlgorithm::Blake3,
        )
        .with_erasure_params(4, 2);

        assert!(metadata.has_erasure_coding());
        assert_eq!(metadata.erasure_params.as_ref().unwrap().data_shards, 4);
        assert_eq!(metadata.erasure_params.as_ref().unwrap().parity_shards, 2);
    }

    #[test]
    fn test_integrity_manager_registration() {
        let mut manager = IntegrityManager::default();
        let blocks = vec![b"block0".to_vec(), b"block1".to_vec()];

        let metadata = manager.register_content(
            "test_content".to_string(),
            &blocks,
            ChecksumAlgorithm::Blake3,
        );

        assert_eq!(metadata.total_blocks, 2);
        assert!(manager.get_metadata("test_content").is_some());
    }

    #[test]
    fn test_integrity_verification() {
        let mut manager = IntegrityManager::default();
        let blocks = vec![b"block0".to_vec(), b"block1".to_vec()];

        manager.register_content(
            "test_content".to_string(),
            &blocks,
            ChecksumAlgorithm::Blake3,
        );

        let status = manager.verify_content("test_content", &blocks);
        assert!(status.is_ok());
        assert!(status.unwrap().is_valid());
    }

    #[test]
    fn test_corruption_detection() {
        let mut manager = IntegrityManager::default();
        let blocks = vec![b"block0".to_vec(), b"block1".to_vec()];

        manager.register_content(
            "test_content".to_string(),
            &blocks,
            ChecksumAlgorithm::Blake3,
        );

        // Corrupt the second block
        let mut corrupted_blocks = blocks.clone();
        corrupted_blocks[1] = b"corrupted".to_vec();

        let status = manager.verify_content("test_content", &corrupted_blocks);
        assert!(status.is_ok());
        
        let status = status.unwrap();
        assert!(status.is_corrupted());
        
        if let IntegrityStatus::Corrupted(issues) = status {
            assert_eq!(issues.len(), 1);
            assert_eq!(issues[0].block_index, 1);
        }
    }

    #[test]
    fn test_integrity_stats() {
        let mut manager = IntegrityManager::default();
        
        manager.register_content(
            "content1".to_string(),
            &vec![b"block".to_vec()],
            ChecksumAlgorithm::Blake3,
        );

        manager.register_content_with_erasure(
            "content2".to_string(),
            &vec![b"block".to_vec()],
            ChecksumAlgorithm::Blake3,
            4,
            2,
        );

        let stats = manager.get_stats();
        assert_eq!(stats.total_content, 2);
        assert_eq!(stats.with_erasure_coding, 1);
    }
}
