//! Byzantine Evidence (Consensus-Critical)
//!
//! This module defines the canonical evidence types for Byzantine behavior
//! that are stored in chain state and trigger deterministic slashing.
//!
//! # Design Principles
//!
//! 1. **Persistence required**: All evidence is stored in chain state
//! 2. **Slashing deterministic**: Same evidence → same slash amount
//! 3. **Peer isolation triggered**: Evidence submission triggers network isolation
//!
//! # Evidence Types
//!
//! - `DoubleSign`: Validator signed two different blocks at same height
//! - `Replay`: Transaction replayed (same tx_hash submitted twice)

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use lib_types::{BlockHeight, TxHash, Amount};
use lib_identity::IdentityId;

// =============================================================================
// EVIDENCE TYPES
// =============================================================================

/// Byzantine evidence that triggers slashing and peer isolation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Evidence {
    /// Validator signed two different blocks at same height
    DoubleSign {
        /// Validator identity
        validator: IdentityId,
        /// Block height where double-sign occurred
        height: BlockHeight,
        /// Hash of first block signed
        block_hash_a: [u8; 32],
        /// Hash of second block signed
        block_hash_b: [u8; 32],
        /// Signature on first block (proof)
        signature_a: Vec<u8>,
        /// Signature on second block (proof)
        signature_b: Vec<u8>,
    },

    /// Transaction replay (same tx submitted multiple times)
    Replay {
        /// Transaction hash that was replayed
        tx: TxHash,
        /// Height where original tx was included
        original_height: BlockHeight,
        /// Height where replay was attempted
        replay_height: BlockHeight,
    },
}

impl Evidence {
    /// Get the validator involved (if applicable)
    pub fn validator(&self) -> Option<&IdentityId> {
        match self {
            Evidence::DoubleSign { validator, .. } => Some(validator),
            Evidence::Replay { .. } => None,
        }
    }

    /// Get the block height where evidence was observed
    pub fn height(&self) -> BlockHeight {
        match self {
            Evidence::DoubleSign { height, .. } => *height,
            Evidence::Replay { replay_height, .. } => *replay_height,
        }
    }

    /// Get evidence type as string
    pub fn evidence_type(&self) -> &'static str {
        match self {
            Evidence::DoubleSign { .. } => "DoubleSign",
            Evidence::Replay { .. } => "Replay",
        }
    }

    /// Compute deterministic evidence ID for deduplication
    pub fn evidence_id(&self) -> [u8; 32] {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();

        match self {
            Evidence::DoubleSign { validator, height, .. } => {
                "DoubleSign".hash(&mut hasher);
                validator.as_bytes().hash(&mut hasher);
                height.hash(&mut hasher);
            }
            Evidence::Replay { tx, original_height, .. } => {
                "Replay".hash(&mut hasher);
                tx.as_bytes().hash(&mut hasher);
                original_height.hash(&mut hasher);
            }
        }

        let hash = hasher.finish();
        let mut id = [0u8; 32];
        id[..8].copy_from_slice(&hash.to_le_bytes());
        id
    }
}

// =============================================================================
// SLASHING CONFIGURATION
// =============================================================================

/// Slashing parameters (deterministic)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashingParams {
    /// Slash percentage for double-sign (basis points, e.g., 500 = 5%)
    pub double_sign_slash_bps: u16,
    /// Slash percentage for other evidence (basis points)
    pub default_slash_bps: u16,
    /// Minimum slash amount
    pub min_slash_amount: Amount,
    /// Jail duration in blocks after slashing
    pub jail_duration_blocks: BlockHeight,
}

impl Default for SlashingParams {
    fn default() -> Self {
        Self {
            double_sign_slash_bps: 500,      // 5% slash for double-sign
            default_slash_bps: 100,          // 1% for other evidence
            min_slash_amount: 1_000_000,     // Minimum 1M units
            jail_duration_blocks: 10_000,    // ~16 hours at 6s blocks
        }
    }
}

impl SlashingParams {
    /// Calculate slash amount for evidence
    ///
    /// # Determinism
    ///
    /// Same evidence + same stake → same slash amount
    pub fn calculate_slash(&self, evidence: &Evidence, validator_stake: Amount) -> Amount {
        let slash_bps = match evidence {
            Evidence::DoubleSign { .. } => self.double_sign_slash_bps,
            Evidence::Replay { .. } => self.default_slash_bps,
        };

        let slash = validator_stake
            .saturating_mul(slash_bps as Amount)
            / 10_000;

        slash.max(self.min_slash_amount)
    }
}

// =============================================================================
// EVIDENCE STORE
// =============================================================================

/// Stored evidence record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceRecord {
    /// The evidence itself
    pub evidence: Evidence,
    /// Block height when evidence was submitted
    pub submitted_at: BlockHeight,
    /// Block height when evidence was processed
    pub processed_at: Option<BlockHeight>,
    /// Slash amount applied (if processed)
    pub slash_amount: Option<Amount>,
    /// Whether validator was jailed
    pub jailed: bool,
}

/// Evidence storage for chain state
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EvidenceStore {
    /// Evidence indexed by evidence_id
    evidence: BTreeMap<[u8; 32], EvidenceRecord>,
    /// Evidence IDs by validator (for lookup)
    by_validator: BTreeMap<IdentityId, Vec<[u8; 32]>>,
    /// Pending evidence (not yet processed)
    pending: Vec<[u8; 32]>,
}

impl EvidenceStore {
    /// Create empty evidence store
    pub fn new() -> Self {
        Self::default()
    }

    /// Submit new evidence
    ///
    /// Returns evidence_id if accepted, None if duplicate
    pub fn submit(
        &mut self,
        evidence: Evidence,
        current_height: BlockHeight,
    ) -> Option<[u8; 32]> {
        let evidence_id = evidence.evidence_id();

        // Reject duplicates
        if self.evidence.contains_key(&evidence_id) {
            return None;
        }

        // Record validator association
        if let Some(validator) = evidence.validator() {
            self.by_validator
                .entry(validator.clone())
                .or_default()
                .push(evidence_id);
        }

        // Create record
        let record = EvidenceRecord {
            evidence,
            submitted_at: current_height,
            processed_at: None,
            slash_amount: None,
            jailed: false,
        };

        self.evidence.insert(evidence_id, record);
        self.pending.push(evidence_id);

        Some(evidence_id)
    }

    /// Get evidence by ID
    pub fn get(&self, evidence_id: &[u8; 32]) -> Option<&EvidenceRecord> {
        self.evidence.get(evidence_id)
    }

    /// Get all evidence for a validator
    pub fn get_by_validator(&self, validator: &IdentityId) -> Vec<&EvidenceRecord> {
        self.by_validator
            .get(validator)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| self.evidence.get(id))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get pending evidence to process
    pub fn get_pending(&self) -> Vec<&EvidenceRecord> {
        self.pending
            .iter()
            .filter_map(|id| self.evidence.get(id))
            .collect()
    }

    /// Mark evidence as processed
    pub fn mark_processed(
        &mut self,
        evidence_id: &[u8; 32],
        processed_at: BlockHeight,
        slash_amount: Amount,
        jailed: bool,
    ) -> bool {
        if let Some(record) = self.evidence.get_mut(evidence_id) {
            record.processed_at = Some(processed_at);
            record.slash_amount = Some(slash_amount);
            record.jailed = jailed;

            // Remove from pending
            self.pending.retain(|id| id != evidence_id);
            true
        } else {
            false
        }
    }

    /// Get total evidence count
    pub fn len(&self) -> usize {
        self.evidence.len()
    }

    /// Check if store is empty
    pub fn is_empty(&self) -> bool {
        self.evidence.is_empty()
    }

    /// Get count of pending evidence
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }
}

// =============================================================================
// PEER ISOLATION
// =============================================================================

/// Action to take after evidence is confirmed
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IsolationAction {
    /// Disconnect and ban the peer
    BanPeer { peer_id: IdentityId, duration_secs: u64 },
    /// Reduce peer score (soft isolation)
    ReduceScore { peer_id: IdentityId, penalty: i32 },
    /// No network action needed
    None,
}

/// Determine isolation action for evidence
pub fn isolation_action(evidence: &Evidence) -> IsolationAction {
    match evidence {
        Evidence::DoubleSign { validator, .. } => {
            // Double-sign: immediate ban
            IsolationAction::BanPeer {
                peer_id: validator.clone(),
                duration_secs: 86400 * 7, // 7 days
            }
        }
        Evidence::Replay { .. } => {
            // Replay: no peer action (could be network issue)
            IsolationAction::None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_validator() -> IdentityId {
        IdentityId::from_bytes(&[1u8; 32])
    }

    fn create_double_sign_evidence(height: BlockHeight) -> Evidence {
        Evidence::DoubleSign {
            validator: create_test_validator(),
            height,
            block_hash_a: [1u8; 32],
            block_hash_b: [2u8; 32],
            signature_a: vec![1, 2, 3],
            signature_b: vec![4, 5, 6],
        }
    }

    fn create_replay_evidence() -> Evidence {
        Evidence::Replay {
            tx: TxHash::new([1u8; 32]),
            original_height: 100,
            replay_height: 200,
        }
    }

    #[test]
    fn test_evidence_id_deterministic() {
        let ev1 = create_double_sign_evidence(100);
        let ev2 = create_double_sign_evidence(100);

        assert_eq!(ev1.evidence_id(), ev2.evidence_id());
    }

    #[test]
    fn test_evidence_id_different_heights() {
        let ev1 = create_double_sign_evidence(100);
        let ev2 = create_double_sign_evidence(200);

        assert_ne!(ev1.evidence_id(), ev2.evidence_id());
    }

    #[test]
    fn test_slashing_calculation() {
        let params = SlashingParams::default();
        let evidence = create_double_sign_evidence(100);

        // 5% of 100M = 5M
        let slash = params.calculate_slash(&evidence, 100_000_000);
        assert_eq!(slash, 5_000_000);

        // Minimum slash enforced
        let small_slash = params.calculate_slash(&evidence, 1_000);
        assert_eq!(small_slash, params.min_slash_amount);
    }

    #[test]
    fn test_evidence_store_submit() {
        let mut store = EvidenceStore::new();
        let evidence = create_double_sign_evidence(100);

        let id = store.submit(evidence.clone(), 100);
        assert!(id.is_some());
        assert_eq!(store.len(), 1);
        assert_eq!(store.pending_count(), 1);

        // Duplicate rejected
        let id2 = store.submit(evidence, 100);
        assert!(id2.is_none());
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn test_evidence_store_process() {
        let mut store = EvidenceStore::new();
        let evidence = create_double_sign_evidence(100);

        let id = store.submit(evidence, 100).unwrap();
        assert_eq!(store.pending_count(), 1);

        store.mark_processed(&id, 101, 5_000_000, true);

        let record = store.get(&id).unwrap();
        assert_eq!(record.processed_at, Some(101));
        assert_eq!(record.slash_amount, Some(5_000_000));
        assert!(record.jailed);
        assert_eq!(store.pending_count(), 0);
    }

    #[test]
    fn test_evidence_by_validator() {
        let mut store = EvidenceStore::new();

        store.submit(create_double_sign_evidence(100), 100);
        store.submit(create_double_sign_evidence(200), 200);

        let validator = create_test_validator();
        let evidence = store.get_by_validator(&validator);
        assert_eq!(evidence.len(), 2);
    }

    #[test]
    fn test_isolation_action() {
        let double_sign = create_double_sign_evidence(100);
        let replay = create_replay_evidence();

        assert!(matches!(
            isolation_action(&double_sign),
            IsolationAction::BanPeer { .. }
        ));

        assert!(matches!(
            isolation_action(&replay),
            IsolationAction::None
        ));
    }
}
