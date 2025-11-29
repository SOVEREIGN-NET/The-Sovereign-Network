//! Integrity verification

use serde::{Deserialize, Serialize};
use lib_crypto::hashing::hash_blake3;

/// Integrity verifier
pub struct IntegrityVerifier {
    /// Strict mode (fails on any mismatch)
    strict_mode: bool,
}

impl IntegrityVerifier {
    pub fn new(strict_mode: bool) -> Self {
        Self { strict_mode }
    }

    /// Verify block integrity
    pub fn verify_block(&self, block: &[u8], expected_checksum: &[u8; 32]) -> bool {
        let actual = hash_blake3(block);
        actual == *expected_checksum
    }

    /// Verify multiple blocks
    pub fn verify_blocks(&self, blocks: &[Vec<u8>], expected_checksums: &[[u8; 32]]) -> VerificationReport {
        let mut verified = 0;
        let mut failed = 0;
        let mut failed_indices = Vec::new();

        for (i, (block, expected)) in blocks.iter().zip(expected_checksums.iter()).enumerate() {
            if self.verify_block(block, expected) {
                verified += 1;
            } else {
                failed += 1;
                failed_indices.push(i);
            }
        }

        VerificationReport {
            total_blocks: blocks.len(),
            verified_blocks: verified,
            failed_blocks: failed,
            failed_indices,
            passed: if self.strict_mode { failed == 0 } else { verified > failed },
        }
    }
}

impl Default for IntegrityVerifier {
    fn default() -> Self {
        Self::new(true) // Strict mode by default
    }
}

/// Verification report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationReport {
    pub total_blocks: usize,
    pub verified_blocks: usize,
    pub failed_blocks: usize,
    pub failed_indices: Vec<usize>,
    pub passed: bool,
}

impl VerificationReport {
    pub fn success_rate(&self) -> f64 {
        if self.total_blocks == 0 {
            0.0
        } else {
            (self.verified_blocks as f64 / self.total_blocks as f64) * 100.0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_integrity_verifier() {
        let verifier = IntegrityVerifier::default();
        let block = b"test block";
        let checksum = hash_blake3(block);

        assert!(verifier.verify_block(block, &checksum));
        assert!(!verifier.verify_block(b"wrong", &checksum));
    }

    #[test]
    fn test_verification_report() {
        let verifier = IntegrityVerifier::default();
        let blocks = vec![b"block1".to_vec(), b"block2".to_vec()];
        let checksums: Vec<[u8; 32]> = blocks.iter().map(|b| hash_blake3(b)).collect();

        let report = verifier.verify_blocks(&blocks, &checksums);
        assert_eq!(report.total_blocks, 2);
        assert_eq!(report.verified_blocks, 2);
        assert_eq!(report.failed_blocks, 0);
        assert!(report.passed);
        assert_eq!(report.success_rate(), 100.0);
    }
}
