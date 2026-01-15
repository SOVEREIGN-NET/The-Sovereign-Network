//! Byzantine Evidence Recording and Validator Slashing
//!
//! This module implements the evidence recording system for Byzantine validators,
//! tracking misbehavior and executing slashing penalties.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use anyhow::{Result, anyhow};
use crate::integration::crypto_integration::PublicKey;

// ============================================================================
// EVIDENCE TYPES
// ============================================================================

/// Type of Byzantine misbehavior
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ByzantineEvidenceType {
    /// Validator proposed conflicting blocks at same height
    DoubleProposal,

    /// Validator signed conflicting blocks at same height
    EquivocationOnBlock,

    /// Validator signed blocks from different forks
    ForkEquivocation,

    /// Validator proposed invalid block (failed validation)
    InvalidProposal,

    /// Validator missed required number of blocks
    MissedBlocks,

    /// Validator violated consensus rules
    ConsensusViolation,
}

impl std::fmt::Display for ByzantineEvidenceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ByzantineEvidenceType::DoubleProposal => write!(f, "DoubleProposal"),
            ByzantineEvidenceType::EquivocationOnBlock => write!(f, "EquivocationOnBlock"),
            ByzantineEvidenceType::ForkEquivocation => write!(f, "ForkEquivocation"),
            ByzantineEvidenceType::InvalidProposal => write!(f, "InvalidProposal"),
            ByzantineEvidenceType::MissedBlocks => write!(f, "MissedBlocks"),
            ByzantineEvidenceType::ConsensusViolation => write!(f, "ConsensusViolation"),
        }
    }
}

/// Single piece of Byzantine evidence against a validator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ByzantineEvidence {
    /// Type of misbehavior
    pub evidence_type: ByzantineEvidenceType,

    /// The malicious validator's public key
    pub validator: PublicKey,

    /// Block height where misbehavior occurred
    pub block_height: u64,

    /// Timestamp when evidence was recorded
    pub recorded_at: u64,

    /// First block hash involved (if applicable)
    pub first_block_hash: Option<[u8; 32]>,

    /// Second block hash involved (if applicable, for conflicts)
    pub second_block_hash: Option<[u8; 32]>,

    /// Description of the misbehavior
    pub description: String,

    /// Whether slashing has been executed
    pub slashing_executed: bool,
}

impl ByzantineEvidence {
    /// Create new Byzantine evidence
    pub fn new(
        evidence_type: ByzantineEvidenceType,
        validator: PublicKey,
        block_height: u64,
        recorded_at: u64,
        description: String,
    ) -> Self {
        Self {
            evidence_type,
            validator,
            block_height,
            recorded_at,
            first_block_hash: None,
            second_block_hash: None,
            description,
            slashing_executed: false,
        }
    }

    /// Mark slashing as executed for this evidence
    pub fn mark_slashed(&mut self) {
        self.slashing_executed = true;
    }
}

// ============================================================================
// EVIDENCE RECORDER
// ============================================================================

/// Records and manages Byzantine evidence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ByzantineEvidenceRecorder {
    /// All recorded evidence (evidence_id -> evidence)
    evidence: HashMap<[u8; 32], ByzantineEvidence>,

    /// Per-validator misbehavior count
    validator_strikes: HashMap<[u8; 32], u64>,

    /// Validators marked for slashing
    marked_for_slashing: std::collections::HashSet<[u8; 32]>,

    /// Total slashing amount per validator (in SOV)
    slashing_amounts: HashMap<[u8; 32], u64>,
}

impl ByzantineEvidenceRecorder {
    /// Create a new evidence recorder
    pub fn new() -> Self {
        Self {
            evidence: HashMap::new(),
            validator_strikes: HashMap::new(),
            marked_for_slashing: std::collections::HashSet::new(),
            slashing_amounts: HashMap::new(),
        }
    }

    /// Record a piece of Byzantine evidence
    pub fn record_evidence(&mut self, evidence: ByzantineEvidence) -> Result<[u8; 32]> {
        // Generate unique evidence ID using Blake3 cryptographic hash over all components
        // This ensures collision resistance even when same validator has multiple evidence
        // types at the same block height
        let evidence_id = {
            let mut hasher = blake3::Hasher::new();
            
            // Hash validator key
            hasher.update(&evidence.validator.key_id);
            
            // Hash block height
            hasher.update(&evidence.block_height.to_le_bytes());
            
            // Hash evidence type discriminant
            let type_discriminant = match evidence.evidence_type {
                ByzantineEvidenceType::DoubleProposal => 1u8,
                ByzantineEvidenceType::EquivocationOnBlock => 2u8,
                ByzantineEvidenceType::ForkEquivocation => 3u8,
                ByzantineEvidenceType::InvalidProposal => 4u8,
                ByzantineEvidenceType::MissedBlocks => 5u8,
                ByzantineEvidenceType::ConsensusViolation => 6u8,
            };
            hasher.update(&[type_discriminant]);
            
            // Hash timestamp to ensure uniqueness even for duplicate evidence submissions
            hasher.update(&evidence.recorded_at.to_le_bytes());
            
            // Finalize hash to 32-byte array
            let hash = hasher.finalize();
            let mut id = [0u8; 32];
            id.copy_from_slice(hash.as_bytes());
            id
        };

        // Check if we already have evidence for this validator at this height
        if self.evidence.contains_key(&evidence_id) {
            return Err(anyhow!("Evidence already recorded for this validator at height {}", evidence.block_height));
        }

        // Record the evidence
        self.evidence.insert(evidence_id, evidence.clone());

        // Update strike count and slashing amount
        let validator_key = evidence.validator.key_id;
        let strikes = self.validator_strikes.entry(validator_key).or_insert(0);
        *strikes += 1;

        // Add to slashing amount: 10 SOV per strike
        let slashing_amount = self.slashing_amounts.entry(validator_key).or_insert(0);
        *slashing_amount += 10;

        // Mark for slashing if too many strikes (3 strikes = slashing)
        if *strikes >= 3 {
            self.marked_for_slashing.insert(validator_key);
        }

        Ok(evidence_id)
    }

    /// Get evidence by ID
    pub fn get_evidence(&self, evidence_id: &[u8; 32]) -> Option<&ByzantineEvidence> {
        self.evidence.get(evidence_id)
    }

    /// Get all evidence for a validator
    pub fn get_validator_evidence(&self, validator_key: &[u8; 32]) -> Vec<ByzantineEvidence> {
        self.evidence
            .values()
            .filter(|e| &e.validator.key_id == validator_key)
            .cloned()
            .collect()
    }

    /// Get strike count for a validator
    pub fn get_validator_strikes(&self, validator_key: &[u8; 32]) -> u64 {
        self.validator_strikes.get(validator_key).copied().unwrap_or(0)
    }

    /// Check if validator should be slashed
    pub fn should_be_slashed(&self, validator_key: &[u8; 32]) -> bool {
        self.marked_for_slashing.contains(validator_key)
    }

    /// Get slashing amount for validator
    pub fn get_slashing_amount(&self, validator_key: &[u8; 32]) -> u64 {
        self.slashing_amounts.get(validator_key).copied().unwrap_or(0)
    }

    /// Execute slashing for a validator
    pub fn execute_slashing(&mut self, validator_key: &[u8; 32]) -> Result<u64> {
        if !self.should_be_slashed(validator_key) {
            return Err(anyhow!("Validator not marked for slashing"));
        }

        let amount = self.get_slashing_amount(validator_key);

        // Mark all evidence for this validator as slashed
        for evidence in self.evidence.values_mut() {
            if &evidence.validator.key_id == validator_key {
                evidence.mark_slashed();
            }
        }

        // Remove from marked_for_slashing (already executed)
        self.marked_for_slashing.remove(validator_key);

        Ok(amount)
    }

    /// Get all validators marked for slashing
    pub fn get_marked_validators(&self) -> Vec<([u8; 32], u64)> {
        self.marked_for_slashing
            .iter()
            .map(|v| (*v, self.get_slashing_amount(v)))
            .collect()
    }

    /// Get evidence count
    pub fn evidence_count(&self) -> usize {
        self.evidence.len()
    }
}

impl Default for ByzantineEvidenceRecorder {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// UNIT TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_public_key(id: u8) -> PublicKey {
        PublicKey {
            dilithium_pk: vec![id; 32],
            kyber_pk: vec![id; 32],
            key_id: [id; 32],
        }
    }

    #[test]
    fn test_record_byzantine_evidence() {
        let mut recorder = ByzantineEvidenceRecorder::new();
        let validator = test_public_key(1);

        let evidence = ByzantineEvidence::new(
            ByzantineEvidenceType::DoubleProposal,
            validator.clone(),
            100,
            1000,
            "Validator proposed two different blocks at height 100".to_string(),
        );

        let evidence_id = recorder.record_evidence(evidence).unwrap();
        assert_eq!(recorder.evidence_count(), 1);
        assert!(recorder.get_evidence(&evidence_id).is_some());
    }

    #[test]
    fn test_strike_counting_and_slashing_threshold() {
        let mut recorder = ByzantineEvidenceRecorder::new();
        let validator = test_public_key(2);
        let validator_key = [2u8; 32];

        // First strike
        let evidence1 = ByzantineEvidence::new(
            ByzantineEvidenceType::InvalidProposal,
            validator.clone(),
            50,
            1000,
            "Invalid proposal 1".to_string(),
        );
        recorder.record_evidence(evidence1).unwrap();
        assert_eq!(recorder.get_validator_strikes(&validator_key), 1);
        assert!(!recorder.should_be_slashed(&validator_key));

        // Second strike
        let evidence2 = ByzantineEvidence::new(
            ByzantineEvidenceType::EquivocationOnBlock,
            validator.clone(),
            60,
            2000,
            "Equivocation on block".to_string(),
        );
        recorder.record_evidence(evidence2).unwrap();
        assert_eq!(recorder.get_validator_strikes(&validator_key), 2);
        assert!(!recorder.should_be_slashed(&validator_key));

        // Third strike - should trigger slashing
        let evidence3 = ByzantineEvidence::new(
            ByzantineEvidenceType::ConsensusViolation,
            validator.clone(),
            70,
            3000,
            "Consensus violation".to_string(),
        );
        recorder.record_evidence(evidence3).unwrap();
        assert_eq!(recorder.get_validator_strikes(&validator_key), 3);
        assert!(recorder.should_be_slashed(&validator_key));
        assert_eq!(recorder.get_slashing_amount(&validator_key), 30); // 3 * 10
    }

    #[test]
    fn test_execute_slashing() {
        let mut recorder = ByzantineEvidenceRecorder::new();
        let validator = test_public_key(3);
        let validator_key = [3u8; 32];

        // Record 3 pieces of evidence
        for i in 0..3 {
            let evidence = ByzantineEvidence::new(
                ByzantineEvidenceType::MissedBlocks,
                validator.clone(),
                100 + i as u64,
                1000 + (i as u64 * 100),
                format!("Missed blocks violation {}", i + 1),
            );
            recorder.record_evidence(evidence).unwrap();
        }

        assert!(recorder.should_be_slashed(&validator_key));

        // Execute slashing
        let slashed_amount = recorder.execute_slashing(&validator_key).unwrap();
        assert_eq!(slashed_amount, 30);

        // Verify validator is no longer marked for slashing
        assert!(!recorder.should_be_slashed(&validator_key));

        // Verify all evidence is marked as slashed
        let evidence = recorder.get_validator_evidence(&validator_key);
        for ev in evidence {
            assert!(ev.slashing_executed);
        }
    }

    #[test]
    fn test_multiple_validators_tracked() {
        let mut recorder = ByzantineEvidenceRecorder::new();
        let validator1 = test_public_key(4);
        let validator2 = test_public_key(5);

        let evidence1 = ByzantineEvidence::new(
            ByzantineEvidenceType::DoubleProposal,
            validator1.clone(),
            100,
            1000,
            "Validator 1 double proposal".to_string(),
        );

        let evidence2 = ByzantineEvidence::new(
            ByzantineEvidenceType::InvalidProposal,
            validator2.clone(),
            100,
            1000,
            "Validator 2 invalid proposal".to_string(),
        );

        recorder.record_evidence(evidence1).unwrap();
        recorder.record_evidence(evidence2).unwrap();

        assert_eq!(recorder.evidence_count(), 2);
        assert_eq!(recorder.get_validator_strikes(&[4u8; 32]), 1);
        assert_eq!(recorder.get_validator_strikes(&[5u8; 32]), 1);
    }

    #[test]
    fn test_evidence_id_uniqueness_different_types_same_height() {
        // Test that different evidence types at the same height generate unique IDs
        // This verifies the Blake3 hash approach prevents collisions
        let mut recorder = ByzantineEvidenceRecorder::new();
        let validator = test_public_key(6);

        // Create two different evidence types at the same height but different timestamps
        let evidence1 = ByzantineEvidence::new(
            ByzantineEvidenceType::DoubleProposal,
            validator.clone(),
            100, // same height
            1000, // timestamp 1
            "Double proposal".to_string(),
        );

        let evidence2 = ByzantineEvidence::new(
            ByzantineEvidenceType::InvalidProposal,
            validator.clone(),
            100, // same height
            1001, // timestamp 2 - slightly different
            "Invalid proposal".to_string(),
        );

        // Both should be recorded successfully with different IDs
        let id1 = recorder.record_evidence(evidence1).unwrap();
        let id2 = recorder.record_evidence(evidence2).unwrap();

        // Evidence IDs must be different
        assert_ne!(id1, id2, "Evidence IDs should be unique even for same validator at same height");
        
        // Both pieces of evidence should be stored
        assert_eq!(recorder.evidence_count(), 2);
        assert!(recorder.get_evidence(&id1).is_some());
        assert!(recorder.get_evidence(&id2).is_some());
    }
}
