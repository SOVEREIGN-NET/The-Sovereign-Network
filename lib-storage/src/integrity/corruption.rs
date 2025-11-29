//! Corruption detection

use serde::{Deserialize, Serialize};
use crate::integrity::{CorruptionIssue, CorruptionType};
use lib_crypto::hashing::hash_blake3;

/// Corruption detector
pub struct CorruptionDetector {
    /// Detection sensitivity (0.0 to 1.0)
    sensitivity: f64,
}

impl CorruptionDetector {
    pub fn new() -> Self {
        Self { sensitivity: 0.95 }
    }

    /// Detect corruption in blocks
    pub fn detect_corruption(
        &self,
        blocks: &[Vec<u8>],
        expected_checksums: &[[u8; 32]],
    ) -> Vec<CorruptionIssue> {
        let mut issues = Vec::new();

        for (i, (block, &expected)) in blocks.iter().zip(expected_checksums.iter()).enumerate() {
            let actual = hash_blake3(block);
            
            if actual != expected {
                issues.push(CorruptionIssue {
                    issue_type: CorruptionType::ChecksumMismatch,
                    block_index: i,
                    expected_checksum: Some(expected),
                    actual_checksum: Some(actual),
                    details: format!("Block {} checksum mismatch", i),
                });
            }
        }

        issues
    }

    /// Detect bit-level corruption
    pub fn detect_bit_corruption(&self, original: &[u8], current: &[u8]) -> Option<CorruptionIssue> {
        if original.len() != current.len() {
            return Some(CorruptionIssue {
                issue_type: CorruptionType::SizeMismatch,
                block_index: 0,
                expected_checksum: None,
                actual_checksum: None,
                details: format!("Size mismatch: expected {}, got {}", original.len(), current.len()),
            });
        }

        let mut diff_count = 0;
        for (a, b) in original.iter().zip(current.iter()) {
            if a != b {
                diff_count += 1;
            }
        }

        if diff_count > 0 {
            Some(CorruptionIssue {
                issue_type: CorruptionType::BitCorruption,
                block_index: 0,
                expected_checksum: None,
                actual_checksum: None,
                details: format!("{} bytes differ", diff_count),
            })
        } else {
            None
        }
    }
}

impl Default for CorruptionDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Corruption report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorruptionReport {
    pub total_blocks: usize,
    pub corrupted_blocks: usize,
    pub issues: Vec<CorruptionIssue>,
    pub severity: CorruptionSeverity,
}

/// Corruption severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CorruptionSeverity {
    None,
    Low,     // < 10% corrupted
    Medium,  // 10-30% corrupted
    High,    // 30-50% corrupted
    Critical, // > 50% corrupted
}

impl CorruptionReport {
    pub fn new(total_blocks: usize, issues: Vec<CorruptionIssue>) -> Self {
        let corrupted_blocks = issues.len();
        let corruption_ratio = corrupted_blocks as f64 / total_blocks as f64;

        let severity = if corrupted_blocks == 0 {
            CorruptionSeverity::None
        } else if corruption_ratio < 0.1 {
            CorruptionSeverity::Low
        } else if corruption_ratio < 0.3 {
            CorruptionSeverity::Medium
        } else if corruption_ratio < 0.5 {
            CorruptionSeverity::High
        } else {
            CorruptionSeverity::Critical
        };

        Self {
            total_blocks,
            corrupted_blocks,
            issues,
            severity,
        }
    }

    pub fn is_recoverable(&self) -> bool {
        // Can recover if less than 50% corrupted with erasure codes
        self.corrupted_blocks < self.total_blocks / 2
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_corruption_detector() {
        let detector = CorruptionDetector::new();
        let blocks = vec![b"block1".to_vec(), b"block2".to_vec()];
        let checksums: Vec<[u8; 32]> = blocks.iter().map(|b| hash_blake3(b)).collect();

        let issues = detector.detect_corruption(&blocks, &checksums);
        assert_eq!(issues.len(), 0);
    }

    #[test]
    fn test_corruption_report() {
        let report = CorruptionReport::new(10, vec![]);
        assert_eq!(report.severity, CorruptionSeverity::None);
        assert!(report.is_recoverable());
    }
}
